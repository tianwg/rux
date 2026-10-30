//! Login-server PAM session.
//!
//! Official Rex opens a PAM login session, the same as a console or SSH
//! login, every time it starts a server for an account. The policy never
//! asks for a password: the caller was already identified. This module
//! dlopens `libpam.so.0` so the personal-server binary still starts on a
//! machine where the link-time sysroot has no libpam.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::OnceLock;

use anyhow::{Context, bail};

const PAM_SUCCESS: c_int = 0;
const PAM_BUF_ERR: c_int = 5;
const PAM_CONV_ERR: c_int = 19;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;
const PAM_ESTABLISH_CRED: c_int = 0x0002;
const PAM_DELETE_CRED: c_int = 0x0004;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: unsafe extern "C" fn(
        num_msg: c_int,
        msg: *const *const PamMessage,
        resp: *mut *mut PamResponse,
        appdata: *mut c_void,
    ) -> c_int,
    appdata: *mut c_void,
}

type PamStart =
    unsafe extern "C" fn(*const c_char, *const c_char, *const PamConv, *mut *mut c_void) -> c_int;
type PamCall = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type PamGetenvlist = unsafe extern "C" fn(*mut c_void) -> *mut *mut c_char;
type PamStrerror = unsafe extern "C" fn(*mut c_void, c_int) -> *const c_char;

struct PamLib {
    start: PamStart,
    authenticate: PamCall,
    acct_mgmt: PamCall,
    setcred: PamCall,
    open_session: PamCall,
    close_session: PamCall,
    getenvlist: PamGetenvlist,
    end: PamCall,
    strerror: PamStrerror,
}

unsafe impl Send for PamLib {}
unsafe impl Sync for PamLib {}

fn lib() -> anyhow::Result<&'static PamLib> {
    static LIB: OnceLock<PamLib> = OnceLock::new();
    if let Some(ready) = LIB.get() {
        return Ok(ready);
    }
    let loaded = load_lib().context("loading libpam.so.0")?;
    let _ = LIB.set(loaded);
    Ok(LIB.get().expect("pam library"))
}

fn load_lib() -> anyhow::Result<PamLib> {
    unsafe {
        let name = CString::new("libpam.so.0").unwrap();
        let handle = libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        if handle.is_null() {
            let err = CStr::from_ptr(libc::dlerror());
            bail!(
                "libpam.so.0 is not available ({}); the login server cannot open a PAM session",
                err.to_string_lossy()
            );
        }
        Ok(PamLib {
            start: sym(handle, "pam_start")?,
            authenticate: sym(handle, "pam_authenticate")?,
            acct_mgmt: sym(handle, "pam_acct_mgmt")?,
            setcred: sym(handle, "pam_setcred")?,
            open_session: sym(handle, "pam_open_session")?,
            close_session: sym(handle, "pam_close_session")?,
            getenvlist: sym(handle, "pam_getenvlist")?,
            end: sym(handle, "pam_end")?,
            strerror: sym(handle, "pam_strerror")?,
        })
    }
}

unsafe fn sym<T>(handle: *mut c_void, name: &str) -> anyhow::Result<T> {
    let c_name = CString::new(name).unwrap();
    let ptr = unsafe { libc::dlsym(handle, c_name.as_ptr()) };
    if ptr.is_null() {
        bail!("libpam.so.0 is missing {name}");
    }
    Ok(unsafe { std::mem::transmute_copy(&ptr) })
}

/// Refuse every prompt. Rex identified the caller already, so the policy
/// never asks for a password. Informational messages are acknowledged.
unsafe extern "C" fn pam_converse(
    num_msg: c_int,
    msg: *const *const PamMessage,
    resp: *mut *mut PamResponse,
    _appdata: *mut c_void,
) -> c_int {
    unsafe {
        if resp.is_null() || num_msg < 0 {
            return PAM_CONV_ERR;
        }
        *resp = std::ptr::null_mut();
        if num_msg == 0 {
            return PAM_SUCCESS;
        }
        if msg.is_null() {
            return PAM_CONV_ERR;
        }
        let responses = libc::calloc(num_msg as usize, std::mem::size_of::<PamResponse>());
        if responses.is_null() {
            return PAM_BUF_ERR;
        }
        for index in 0..num_msg {
            let message = *msg.add(index as usize);
            if message.is_null() {
                libc::free(responses);
                return PAM_CONV_ERR;
            }
            let style = (*message).msg_style;
            if style != PAM_ERROR_MSG && style != PAM_TEXT_INFO {
                libc::free(responses);
                return PAM_CONV_ERR;
            }
        }
        *resp = responses.cast();
        PAM_SUCCESS
    }
}

pub struct LoginSession {
    handle: *mut c_void,
    opened: bool,
    creds: bool,
    env: Vec<(String, String)>,
}

unsafe impl Send for LoginSession {}

impl Drop for LoginSession {
    fn drop(&mut self) {
        self.close();
    }
}

impl LoginSession {
    pub fn env(&self) -> &[(String, String)] {
        &self.env
    }

    pub fn close(&mut self) {
        if self.handle.is_null() {
            return;
        }
        let Ok(pam) = lib() else {
            self.handle = std::ptr::null_mut();
            return;
        };
        unsafe {
            if self.opened {
                (pam.close_session)(self.handle, 0);
                self.opened = false;
            }
            if self.creds {
                (pam.setcred)(self.handle, PAM_DELETE_CRED);
                self.creds = false;
            }
            (pam.end)(self.handle, PAM_SUCCESS);
        }
        self.handle = std::ptr::null_mut();
    }
}

/// `pam_start`, `pam_authenticate`, `pam_acct_mgmt`, `pam_setcred`, and
/// `pam_open_session` for `service` as `user`. The conversation refuses a
/// password prompt.
pub fn open_login_session(service: &str, user: &str) -> anyhow::Result<LoginSession> {
    let pam = lib()?;
    let service = CString::new(service).context("PAM service name")?;
    let user = CString::new(user).context("PAM account name")?;
    let conv = PamConv {
        conv: pam_converse,
        appdata: std::ptr::null_mut(),
    };
    let mut handle = std::ptr::null_mut();
    let rc = unsafe { (pam.start)(service.as_ptr(), user.as_ptr(), &conv, &mut handle) };
    if rc != PAM_SUCCESS || handle.is_null() {
        bail!("pam_start failed: {}", strerror(pam, handle, rc));
    }
    let mut session = LoginSession {
        handle,
        opened: false,
        creds: false,
        env: Vec::new(),
    };
    if let Err(error) = open_rest(pam, &mut session) {
        session.close();
        return Err(error);
    }
    Ok(session)
}

fn open_rest(pam: &PamLib, session: &mut LoginSession) -> anyhow::Result<()> {
    let rc = unsafe { (pam.authenticate)(session.handle, 0) };
    if rc != PAM_SUCCESS {
        bail!(
            "pam_authenticate failed: {}",
            strerror(pam, session.handle, rc)
        );
    }
    let rc = unsafe { (pam.acct_mgmt)(session.handle, 0) };
    if rc != PAM_SUCCESS {
        bail!(
            "pam_acct_mgmt failed: {}",
            strerror(pam, session.handle, rc)
        );
    }
    let rc = unsafe { (pam.setcred)(session.handle, PAM_ESTABLISH_CRED) };
    if rc != PAM_SUCCESS {
        bail!("pam_setcred failed: {}", strerror(pam, session.handle, rc));
    }
    session.creds = true;
    let rc = unsafe { (pam.open_session)(session.handle, 0) };
    if rc != PAM_SUCCESS {
        bail!(
            "pam_open_session failed: {}",
            strerror(pam, session.handle, rc)
        );
    }
    session.opened = true;
    session.env = read_env(pam, session.handle);
    Ok(())
}

fn read_env(pam: &PamLib, handle: *mut c_void) -> Vec<(String, String)> {
    let mut out = Vec::new();
    unsafe {
        let list = (pam.getenvlist)(handle);
        if list.is_null() {
            return out;
        }
        let mut index = 0;
        loop {
            let item = *list.add(index);
            if item.is_null() {
                break;
            }
            if let Ok(text) = CStr::from_ptr(item).to_str() {
                if let Some((key, value)) = text.split_once('=') {
                    if !key.is_empty() {
                        out.push((key.to_string(), value.to_string()));
                    }
                }
            }
            libc::free(item.cast());
            index += 1;
        }
        libc::free(list.cast());
    }
    out
}

fn strerror(pam: &PamLib, handle: *mut c_void, rc: c_int) -> String {
    unsafe {
        let text = (pam.strerror)(handle, rc);
        if text.is_null() {
            return format!("PAM error {rc}");
        }
        CStr::from_ptr(text).to_string_lossy().into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversation_refuses_a_password_prompt() {
        let prompt = CString::new("Password:").unwrap();
        let message = PamMessage {
            msg_style: 1,
            msg: prompt.as_ptr(),
        };
        let messages = [&message as *const PamMessage];
        let mut resp = std::ptr::null_mut();
        let rc = unsafe { pam_converse(1, messages.as_ptr(), &mut resp, std::ptr::null_mut()) };
        assert_eq!(rc, PAM_CONV_ERR);
        assert!(resp.is_null());
    }

    #[test]
    fn conversation_accepts_an_informational_message() {
        let note = CString::new("session opened").unwrap();
        let message = PamMessage {
            msg_style: PAM_TEXT_INFO,
            msg: note.as_ptr(),
        };
        let messages = [&message as *const PamMessage];
        let mut resp = std::ptr::null_mut();
        let rc = unsafe { pam_converse(1, messages.as_ptr(), &mut resp, std::ptr::null_mut()) };
        assert_eq!(rc, PAM_SUCCESS);
        assert!(!resp.is_null());
        unsafe { libc::free(resp.cast()) };
    }
}

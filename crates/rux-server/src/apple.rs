//! macOS integration behind the `server.apple.*` methods.
//!
//! The protocol surface is identical on every platform. The privacy
//! list is empty when the server cannot read privacy decisions — the
//! documented contract names a non-macOS server as that example — and
//! sandbox extension tokens exist only on macOS, so the native pieces
//! live in the cfg-gated `platform` module. The macOS code is FFI over
//! the system frameworks (no Objective-C runtime dependencies beyond
//! libobjc's message send for AVFoundation).

use serde_json::Value;

/// `server.apple.privacy_status`: privacy services with their status,
/// plus the responsible executable path when the platform reports it.
pub fn privacy_status() -> Value {
    platform::privacy_status()
}

/// Consume a sandbox extension token so this process (and everything
/// it spawns) can read `path`. Only meaningful on macOS; anywhere else
/// there are no tokens to consume and this returns false.
pub fn consume_sandbox_token(path: &str, token: &str) -> bool {
    let _ = path;
    platform::consume_sandbox_token(token)
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use serde_json::{json, Value};

    pub fn privacy_status() -> Value {
        json!({ "services": [] })
    }

    pub fn consume_sandbox_token(_token: &str) -> bool {
        false
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::{c_char, c_void, CString};
    use std::os::raw::c_int;

    use serde_json::{json, Value};

    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        fn AXIsProcessTrusted() -> bool;
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGPreflightScreenCaptureAccess() -> bool;
    }

    unsafe extern "C" {
        // In libSystem's sandbox library; every macOS binary links it.
        fn sandbox_extension_consume(token: *const c_char) -> c_int;
    }

    pub fn consume_sandbox_token(token: &str) -> bool {
        let Ok(token) = CString::new(token) else {
            return false;
        };
        // The returned handle stays consumed for the life of the
        // process; the API has no per-call release for class tokens
        // the server intends to keep using.
        unsafe { sandbox_extension_consume(token.as_ptr()) >= 0 }
    }

    /// AVFoundation authorization status for the video or audio media
    /// type: 0 notDetermined, 1 restricted, 2 denied, 3 authorized.
    fn media_status(video: bool) -> Option<i64> {
        type Id = *mut c_void;
        type Sel = *mut c_void;
        unsafe extern "C" {
            fn objc_getClass(name: *const c_char) -> Id;
            fn sel_registerName(name: *const c_char) -> Sel;
            fn objc_msgSend(receiver: Id, selector: Sel, arg: Id) -> i64;
        }
        #[link(name = "AVFoundation", kind = "framework")]
        unsafe extern "C" {
            static AVMediaTypeVideo: *const c_void;
            static AVMediaTypeAudio: *const c_void;
        }
        let class_name = CString::new("AVCaptureDevice").ok()?;
        let selector_name = CString::new("authorizationStatusForMediaType:").ok()?;
        unsafe {
            let class = objc_getClass(class_name.as_ptr());
            if class.is_null() {
                return None;
            }
            let selector = sel_registerName(selector_name.as_ptr());
            let media_type = if video {
                AVMediaTypeVideo
            } else {
                AVMediaTypeAudio
            };
            if media_type.is_null() {
                return None;
            }
            // `authorizationStatusForMediaType:` is a class method
            // returning an NSInteger; objc_msgSend is declared above
            // with exactly that signature.
            Some(objc_msgSend(class, selector, media_type as Id))
        }
    }

    fn av_status(video: bool) -> &'static str {
        match media_status(video) {
            Some(3) => "granted",
            Some(0) => "not_determined",
            Some(1) | Some(2) => "denied",
            _ => "unknown",
        }
    }

    pub fn privacy_status() -> Value {
        let mut services: Vec<Value> = Vec::new();
        let mut report = |service: &str, status: &str| {
            services.push(json!({ "service": service, "status": status }));
        };

        // Full Disk Access has no query API; the probe is opening the
        // user TCC database, which TCC itself gates on the grant.
        let fda = match std::env::var_os("HOME") {
            Some(home) => {
                let path = std::path::Path::new(&home)
                    .join("Library/Application Support/com.apple.TCC/TCC.db");
                match std::fs::File::open(&path) {
                    Ok(_) => "granted",
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => "unknown",
                    Err(_) => "denied",
                }
            }
            None => "unknown",
        };
        report("full_disk_access", fda);

        let accessibility = unsafe { AXIsProcessTrusted() };
        report(
            "accessibility",
            if accessibility { "granted" } else { "denied" },
        );

        let screen = unsafe { CGPreflightScreenCaptureAccess() };
        report(
            "screen_recording",
            if screen { "granted" } else { "denied" },
        );

        report("camera", av_status(true));
        report("microphone", av_status(false));

        let mut result = json!({ "services": services });
        if let Ok(exe) = std::env::current_exe() {
            result["responsible_path"] = json!(exe.to_string_lossy());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn privacy_status_always_has_a_services_list() {
        let status = super::privacy_status();
        assert!(status["services"].is_array(), "{status}");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_reports_no_services_and_consumes_nothing() {
        assert_eq!(super::privacy_status(), json!({ "services": [] }));
        assert!(!super::consume_sandbox_token("/tmp", "bogus-token"));
    }
}

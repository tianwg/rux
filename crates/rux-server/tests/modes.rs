//! Process-level checks for flags and the login server. The account server is
//! a second `rux-server` the login server starts for this uid.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_rux-server")
}

fn uid() -> u32 {
    for line in std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
    {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next().unwrap().parse().unwrap();
        }
    }
    panic!("no uid");
}

fn user_name(uid: u32) -> String {
    for line in std::fs::read_to_string("/etc/passwd").unwrap().lines() {
        let mut fields = line.split(':');
        let name = fields.next().unwrap_or("");
        let _ = fields.next();
        if fields.next() == Some(&uid.to_string()) {
            return name.to_string();
        }
    }
    panic!("uid {uid} is not in /etc/passwd");
}

#[test]
fn help_lists_the_remote_and_mode_flags() {
    let output = Command::new(bin()).arg("--help").output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{text}");
    for flag in [
        "--log-format",
        "--socket-mode",
        "--max-sessions",
        "--personal",
        "--exit-empty",
        "login-server",
    ] {
        assert!(text.contains(flag), "{flag} missing from help");
    }
    let bad = Command::new(bin())
        .args(["--log-format", "xml"])
        .output()
        .unwrap();
    assert!(!bad.status.success());
    let err = String::from_utf8_lossy(&bad.stderr);
    assert!(err.contains("text or json"), "{err}");
}

#[test]
fn socket_mode_rejects_a_non_octal_value() {
    let dir = std::env::temp_dir().join(format!("rux-mode-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("server.sock");
    let output = Command::new(bin())
        .args([
            "--listen",
            socket.to_str().unwrap(),
            "--socket-mode",
            "zz",
            "--log-format",
            "text",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("octal"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn login_server_checks_accounts_and_hands_off_the_local_user() {
    let uid = uid();
    let name = user_name(uid);
    let dir = std::env::temp_dir().join(format!(
        "rux-login-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let accounts = dir.join("accounts.jsonc");
    std::fs::write(
        &accounts,
        format!(
            r#"{{
              // who may log in
              "version": 1,
              "accounts": {{
                "{name}": {{ "principals": ["peer:{uid}"], }},
              }},
            }}"#
        ),
    )
    .unwrap();

    let check = Command::new(bin())
        .args([
            "--log-format",
            "text",
            "login-server",
            "--check",
            "--accounts",
            accounts.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&check.stdout);
    let stderr = String::from_utf8_lossy(&check.stderr);
    assert!(check.status.success(), "{stderr}{stdout}");
    assert!(stdout.contains("accounts ok: 1"), "{stdout}");

    let listen = dir.join("login.sock");
    let log_path = dir.join("login.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let login = Command::new(bin())
        .args([
            "--log-format",
            "text",
            "login-server",
            "--listen",
            listen.to_str().unwrap(),
            "--accounts",
            accounts.to_str().unwrap(),
            "--runtime-root",
            dir.to_str().unwrap(),
            // A non-root process cannot read /etc/shadow, so --pam=false
            // marks every account locked. PAM itself runs only when euid is 0.
            "--pam",
            "true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let login_pid = login.id();
    let pidfile = dir.join("accounts").join(&name).join("server.pid");
    let mut cleanup = Cleanup {
        login,
        pidfile: pidfile.clone(),
        dir: dir.clone(),
    };

    wait_for(&listen, &mut cleanup.login, &log_path);
    let ok = exchange(
        &listen,
        &format!("GET /api/help HTTP/1.1\r\nHost: {name}@login.test\r\nConnection: close\r\n\r\n"),
    );
    assert!(
        ok.contains("200") && ok.contains("server.version"),
        "help via login server:\n{ok}\n{}",
        std::fs::read_to_string(&log_path).unwrap_or_default()
    );
    let denied = exchange(
        &listen,
        "GET /api/help HTTP/1.1\r\nHost: root@login.test\r\nConnection: close\r\n\r\n",
    );
    assert!(
        denied.contains("403") && denied.contains("not allowed"),
        "{denied}"
    );

    let mut held = UnixStream::connect(&listen).unwrap();
    held.set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    held.write_all(
        format!(
            "GET /api/control HTTP/1.1\r\nHost: {name}@login.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGVzdA==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: rex.control.v1\r\n\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let upgraded = read_available(&mut held);
    assert!(
        upgraded.contains("101"),
        "upgrade:\n{upgraded}\n{}",
        std::fs::read_to_string(&log_path).unwrap_or_default()
    );
    let _ = Command::new("kill")
        .args(["-HUP", &login_pid.to_string()])
        .status()
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !held_closed(&mut held),
        "an allowed connection was closed by reload"
    );

    std::fs::write(
        &accounts,
        format!(r#"{{ "version": 1, "accounts": {{ "{name}": {{ "principals": [] }} }} }}"#),
    )
    .unwrap();
    let _ = Command::new("kill")
        .args(["-HUP", &login_pid.to_string()])
        .status()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut closed = String::new();
    while Instant::now() < deadline {
        closed.push_str(&read_available(&mut held));
        if held_closed(&mut held) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        held_closed(&mut held),
        "removed access did not close the connection: {closed:?}"
    );
    let again = exchange(
        &listen,
        &format!("GET /api/help HTTP/1.1\r\nHost: {name}@login.test\r\nConnection: close\r\n\r\n"),
    );
    assert!(again.contains("403"), "{again}");
    assert!(pidfile.exists(), "account server pid file");
    let account_pid: u32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_ne!(account_pid, login_pid);
    let account_sock = dir.join("accounts").join(&name).join("server.sock");
    let _ = Command::new("kill")
        .args(["-TERM", &login_pid.to_string()])
        .stderr(Stdio::null())
        .status();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if cleanup.login.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let survived = exchange(
        &account_sock,
        "GET /api/help HTTP/1.1\r\nHost: login.test\r\nConnection: close\r\n\r\n",
    );
    assert!(
        survived.contains("200") && survived.contains("server.version"),
        "account server did not survive login-server exit:\n{survived}"
    );
    drop(cleanup);
}

#[test]
fn login_session_pam_requires_the_root_login_server() {
    if uid() == 0 {
        return;
    }
    let output = Command::new(bin())
        .args([
            "login-session",
            "--user",
            "nobody",
            "--uid",
            "65534",
            "--gid",
            "65534",
            "--pam",
            "true",
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(
        err.contains("root login server"),
        "stderr did not name the root login server: {err}"
    );
}

#[test]
fn personal_server_uses_the_login_account_paths() {
    let uid = uid();
    let dir = std::env::temp_dir().join(format!(
        "rux-personal-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("home")).unwrap();
    let runtime = dir.join("run");
    let state_home = dir.join("state");
    let serve = dir.join("serve.sock");
    let serve_arg = format!("tailnet-serve://{}", serve.display());
    let log_path = dir.join("server.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut child = Command::new(bin())
        .args([
            "--personal",
            "--log-format",
            "text",
            "--extra-listen",
            serve_arg.as_str(),
        ])
        .env("HOME", dir.join("home"))
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("XDG_STATE_HOME", &state_home)
        .env("USER", user_name(uid))
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let socket = runtime.join("rex/server.sock");
    let state = state_home.join("rex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if socket.exists() && serve.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let log_text = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        child.try_wait().unwrap().is_none(),
        "personal server exited\n{log_text}"
    );
    let status = std::fs::read_to_string(format!("/proc/{}/status", child.id())).unwrap();
    let uid_line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .unwrap();
    assert!(
        uid_line.split_whitespace().nth(1) == Some(&uid.to_string()),
        "{uid_line}"
    );
    assert!(
        state.join("host-id").is_file(),
        "state dir {}\n{log_text}",
        state.display()
    );
    let mode = std::fs::metadata(&serve).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "serve socket mode {mode:o}");
    let mut stream = UnixStream::connect(&serve).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .write_all(b"GET /api/help HTTP/1.1\r\nHost: personal.test\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let body = String::from_utf8_lossy(&buf);
    assert!(
        !body.contains("200"),
        "non-root reached the serve socket:\n{body}"
    );
    let refused = Command::new(bin())
        .args([
            "--tailnet-only",
            "--log-format",
            "text",
            "--extra-listen",
            "http://127.0.0.1:1",
        ])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    let err = String::from_utf8_lossy(&refused.stderr);
    assert!(
        err.contains("tailnet-only"),
        "public bind was not refused: {err}"
    );
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

struct Cleanup {
    login: std::process::Child,
    pidfile: PathBuf,
    dir: PathBuf,
}

impl Cleanup {
    fn finish(&mut self) {
        let _ = self.login.kill();
        let _ = self.login.wait();
        if let Ok(pid) = std::fs::read_to_string(&self.pidfile) {
            let _ = Command::new("kill")
                .args(["-TERM", pid.trim()])
                .stderr(Stdio::null())
                .stdout(Stdio::null())
                .status();
            std::thread::sleep(Duration::from_millis(100));
            let _ = Command::new("kill")
                .args(["-KILL", pid.trim()])
                .stderr(Stdio::null())
                .stdout(Stdio::null())
                .status();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.finish();
    }
}

fn wait_for(socket: &Path, child: &mut std::process::Child, log: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            panic!(
                "login server exited\n{}",
                std::fs::read_to_string(log).unwrap_or_default()
            );
        }
        if socket.exists() && UnixStream::connect(socket).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!(
        "login socket did not appear\n{}",
        std::fs::read_to_string(log).unwrap_or_default()
    );
}

fn exchange(socket: &Path, request: &str) -> String {
    let mut last = String::new();
    for _ in 0..50 {
        match UnixStream::connect(socket) {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                if stream.write_all(request.as_bytes()).is_err() {
                    continue;
                }
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf);
                let text = String::from_utf8_lossy(&buf).into_owned();
                if !text.is_empty() {
                    return text;
                }
                last = text;
            }
            Err(error) => last = error.to_string(),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    last
}

fn read_available(stream: &mut UnixStream) -> String {
    let mut buf = [0u8; 4096];
    match stream.read(&mut buf) {
        Ok(0) => String::new(),
        Ok(n) => String::from_utf8_lossy(&buf[..n]).into_owned(),
        Err(_) => String::new(),
    }
}

fn held_closed(stream: &mut UnixStream) -> bool {
    let mut buf = [0u8; 64];
    match stream.read(&mut buf) {
        Ok(0) => true,
        Ok(_) => false,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => false,
        Err(_) => true,
    }
}

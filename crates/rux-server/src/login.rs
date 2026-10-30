//! Login server: pick an OS account from `/etc/rex/accounts.jsonc` and hand
//! the connection to a server running as that account.
//!
//! When this process is root and PAM is on, a supervisor in its own session
//! calls `pam_start`, `pam_authenticate`, `pam_acct_mgmt`, `pam_setcred`, and
//! `pam_open_session`, then starts the account server. The supervisor stays
//! up until that server exits and then calls `pam_close_session`. With
//! `--pam=false` it reads `/etc/shadow` itself and opens no login session.
//! Either way it refuses `/etc/nologin` and nologin shells.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};

use crate::accounts::{
    Accounts, Caller, OsUser, SelectError, parse_accounts, select_account, still_allowed,
};
use crate::tailscale::{self, ListenSpec, PeerInfo, TailnetGate, TailnetPolicy};

pub struct Options {
    pub accounts_path: PathBuf,
    pub listens: Vec<String>,
    pub runtime_root: PathBuf,
    pub pam: bool,
    pub pam_service: String,
    pub bin: PathBuf,
    pub tls: Option<tokio_rustls::TlsAcceptor>,
}

pub struct LoginSessionOptions {
    pub user: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    pub pam_service: String,
    pub pam: bool,
    pub pid_file: Option<PathBuf>,
    pub server: Vec<String>,
}

struct Shared {
    accounts_path: PathBuf,
    runtime_root: PathBuf,
    pam: bool,
    pam_service: String,
    bin: PathBuf,
    accounts: Mutex<Accounts>,
    live: Mutex<Vec<Live>>,
    gates: Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    next_id: AtomicU64,
    tailnet: TailnetGate,
}

struct Live {
    id: u64,
    caller: Caller,
    account: String,
    kill: tokio::sync::mpsc::Sender<()>,
}

#[derive(Clone)]
pub struct LiveView {
    pub id: u64,
    pub caller: Caller,
    pub account: String,
}

pub async fn serve(opts: Options) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(&opts.accounts_path)
        .with_context(|| format!("reading {}", opts.accounts_path.display()))?;
    let accounts = parse_accounts(&text).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if opts.listens.is_empty() {
        bail!("login-server has no listen address");
    }
    let mut specs = Vec::new();
    for listen in &opts.listens {
        specs.push(tailscale::parse_listen(listen)?);
    }
    let needs_tls = specs
        .iter()
        .any(|spec| matches!(spec, ListenSpec::Https(_)));
    if needs_tls && opts.tls.is_none() {
        bail!("an https:// login-server listener needs --tls-cert and --tls-key");
    }
    let shared = Arc::new(Shared {
        accounts_path: opts.accounts_path,
        runtime_root: opts.runtime_root,
        pam: opts.pam,
        pam_service: opts.pam_service,
        bin: opts.bin,
        accounts: Mutex::new(accounts),
        live: Mutex::new(Vec::new()),
        gates: Mutex::new(std::collections::HashMap::new()),
        next_id: AtomicU64::new(1),
        tailnet: TailnetGate::new(
            tailscale::default_socket_path(),
            TailnetPolicy {
                allow_identified: true,
                http_port: None,
                https_serve: false,
            },
        ),
    });
    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut tasks = tokio::task::JoinSet::new();
    for spec in specs {
        let shared = shared.clone();
        let tls = opts.tls.clone();
        tasks.spawn(async move { accept_spec(spec, shared, tls).await });
    }
    loop {
        tokio::select! {
            _ = hup.recv() => reload(&shared),
            joined = tasks.join_next() => {
                match joined {
                    None => return Ok(()),
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) => return Err(error),
                    Some(Err(error)) => return Err(error.into()),
                }
            }
        }
    }
}

fn reload(shared: &Shared) {
    let text = match std::fs::read_to_string(&shared.accounts_path) {
        Ok(text) => text,
        Err(error) => {
            tracing::error!(%error, path = %shared.accounts_path.display(), "accounts reload failed");
            return;
        }
    };
    let accounts = match parse_accounts(&text) {
        Ok(accounts) => accounts,
        Err(error) => {
            tracing::error!(%error, "accounts reload rejected the file; keeping the previous one");
            return;
        }
    };
    let users = passwd_users(shared.pam);
    let live: Vec<LiveView> = shared
        .live
        .lock()
        .unwrap()
        .iter()
        .map(|live| LiveView {
            id: live.id,
            caller: live.caller.clone(),
            account: live.account.clone(),
        })
        .collect();
    let close = close_denied(&accounts, &users, &live);
    let guard = shared.live.lock().unwrap();
    for id in close {
        if let Some(live) = guard.iter().find(|live| live.id == id) {
            tracing::info!(account = %live.account, "closing a connection the accounts file no longer allows");
            let _ = live.kill.try_send(());
        }
    }
    *shared.accounts.lock().unwrap() = accounts;
    tracing::info!("reloaded accounts");
}

pub fn close_denied(accounts: &Accounts, users: &[OsUser], live: &[LiveView]) -> Vec<u64> {
    live.iter()
        .filter(|live| !still_allowed(accounts, &live.caller, &live.account, users))
        .map(|live| live.id)
        .collect()
}

async fn accept_spec(
    spec: ListenSpec,
    shared: Arc<Shared>,
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> anyhow::Result<()> {
    match spec {
        ListenSpec::Unix(path) => {
            listen_unix(&path, false, shared).await?;
        }
        ListenSpec::TailnetServe(path) => {
            listen_unix(&path, true, shared).await?;
        }
        ListenSpec::Http(address) => {
            let listener = TcpListener::bind(&address)
                .await
                .with_context(|| format!("binding login-server HTTP {address}"))?;
            tracing::info!(%address, "login server listening");
            loop {
                let (stream, peer) = listener.accept().await?;
                let shared = shared.clone();
                tokio::spawn(async move {
                    if let Err(error) =
                        handle(stream, None, PeerSource::Remote { peer }, shared).await
                    {
                        tracing::debug!(%error, "login connection closed");
                    }
                });
            }
        }
        ListenSpec::Https(address) => {
            let Some(acceptor) = tls else {
                bail!("https login listener is missing a certificate");
            };
            let listener = TcpListener::bind(&address)
                .await
                .with_context(|| format!("binding login-server HTTPS {address}"))?;
            tracing::info!(%address, "login server listening");
            loop {
                let (stream, peer) = listener.accept().await?;
                let acceptor = acceptor.clone();
                let shared = shared.clone();
                tokio::spawn(async move {
                    let stream = match tokio::time::timeout(
                        Duration::from_secs(10),
                        acceptor.accept(stream),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => stream,
                        _ => return,
                    };
                    if let Err(error) =
                        handle(stream, None, PeerSource::Remote { peer }, shared).await
                    {
                        tracing::debug!(%error, "login connection closed");
                    }
                });
            }
        }
        ListenSpec::Tailnet { host, port } => {
            let discovered = shared
                .tailnet
                .discover_ips()
                .await
                .map_err(anyhow::Error::msg)?;
            let ips = tailscale::bind_targets(host, &discovered)?;
            let mut tasks = tokio::task::JoinSet::new();
            for ip in ips {
                let addr = tailscale::socket_addr_for(ip, port);
                let listener = TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("binding login-server tailnet {addr}"))?;
                tracing::info!(%addr, "login server listening on tailnet address");
                let shared = shared.clone();
                tasks.spawn(async move {
                    loop {
                        let (stream, peer) = match listener.accept().await {
                            Ok(accepted) => accepted,
                            Err(error) => return Err(anyhow::Error::from(error)),
                        };
                        let shared = shared.clone();
                        tokio::spawn(async move {
                            if let Err(error) =
                                handle(stream, None, PeerSource::Tailnet { peer }, shared).await
                            {
                                tracing::debug!(%error, "login connection closed");
                            }
                        });
                    }
                });
            }
            if let Some(result) = tasks.join_next().await {
                result??;
            }
        }
    }
    Ok(())
}

async fn listen_unix(path: &Path, serve: bool, shared: Arc<Shared>) -> anyhow::Result<()> {
    prepare_socket(path)?;
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    tracing::info!(socket = %path.display(), serve, "login server listening");
    loop {
        let (stream, _) = listener.accept().await?;
        if serve {
            match stream.peer_cred() {
                Ok(cred) if cred.uid() == 0 => {}
                Ok(cred) => {
                    tracing::warn!(
                        uid = cred.uid(),
                        "rejected tailnet-serve connection from a non-root user"
                    );
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, "rejected tailnet-serve connection without peer credentials");
                    continue;
                }
            }
        }
        let uid = stream.peer_cred().ok().map(|cred| cred.uid());
        let shared = shared.clone();
        let source = if serve {
            PeerSource::Serve
        } else {
            PeerSource::Local
        };
        tokio::spawn(async move {
            if let Err(error) = handle(stream, uid, source, shared).await {
                tracing::debug!(%error, "login connection closed");
            }
        });
    }
}

enum PeerSource {
    Local,
    Serve,
    Remote { peer: std::net::SocketAddr },
    Tailnet { peer: std::net::SocketAddr },
}

async fn handle<S>(
    mut inbound: S,
    uid: Option<u32>,
    source: PeerSource,
    shared: Arc<Shared>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = read_http_head(&mut inbound).await?;
    if !head.windows(4).any(|window| window == b"\r\n\r\n") {
        write_status(&mut inbound, 400, "Bad Request", "expected an HTTP request").await;
        return Ok(());
    }
    let split = head
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .unwrap_or(head.len());
    let header_text = String::from_utf8_lossy(&head[..split]);
    if http_header(&header_text, "tailscale-funnel-request").is_some() {
        write_status(
            &mut inbound,
            403,
            "Forbidden",
            "Tailscale Funnel is public; rux refuses Funnel connections",
        )
        .await;
        return Ok(());
    }
    let caller = caller_from_request(uid, &source, &header_text, &shared).await;
    let requested =
        http_header(&header_text, "host").and_then(crate::accounts::account_from_http_host);
    let accounts = shared.accounts.lock().unwrap().clone();
    let users = passwd_users(shared.pam);
    let account = match select_account(&accounts, &caller, requested.as_deref(), &users) {
        Ok(account) => account,
        Err(error) => {
            let (status, reason) = match &error {
                SelectError::Ambiguous => (409, "Conflict"),
                SelectError::Parse(_) => (500, "Internal Server Error"),
                _ => (403, "Forbidden"),
            };
            write_status(&mut inbound, status, reason, &error.to_string()).await;
            return Ok(());
        }
    };
    let Some(user) = users.into_iter().find(|user| user.name == account) else {
        write_status(
            &mut inbound,
            403,
            "Forbidden",
            &format!("account {account} is not in /etc/passwd"),
        )
        .await;
        return Ok(());
    };
    if let Err(error) = crate::accounts::policy_from_files(
        &user,
        std::path::Path::new("/etc/nologin").exists(),
        shared.pam,
    ) {
        write_status(&mut inbound, 403, "Forbidden", &error.to_string()).await;
        return Ok(());
    }
    if let Err(error) = ensure_account_server(&shared, &user).await {
        write_status(&mut inbound, 503, "Service Unavailable", &error.to_string()).await;
        return Ok(());
    }
    let (socket, _) = account_paths(
        &shared.runtime_root,
        &user,
        personal_layout(&shared.runtime_root),
    );
    let mut outbound = UnixStream::connect(&socket).await?;
    outbound.write_all(&head).await?;
    let (kill_tx, mut kill_rx) = tokio::sync::mpsc::channel(1);
    let id = shared.next_id.fetch_add(1, Ordering::SeqCst);
    shared.live.lock().unwrap().push(Live {
        id,
        caller,
        account,
        kill: kill_tx,
    });
    let copy = tokio::io::copy_bidirectional(&mut inbound, &mut outbound);
    tokio::pin!(copy);
    tokio::select! {
        _ = &mut copy => {}
        _ = kill_rx.recv() => {}
    }
    shared.live.lock().unwrap().retain(|live| live.id != id);
    Ok(())
}

async fn caller_from_request(
    uid: Option<u32>,
    source: &PeerSource,
    headers: &str,
    shared: &Shared,
) -> Caller {
    if let Some(login) = http_header(headers, "tailscale-user-login") {
        return tailscale_caller(Some(login.to_string()), Vec::new(), uid);
    }
    let tags = http_header(headers, "x-rux-tsnet-tags")
        .map(|tags| {
            tags.split(',')
                .map(str::trim)
                .filter(|tag| !tag.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if let Some(login) = http_header(headers, "x-rux-tsnet-login") {
        return tailscale_caller(Some(login.to_string()), tags, uid);
    }
    if !tags.is_empty() {
        return tailscale_caller(None, tags, uid);
    }
    let peer = match source {
        PeerSource::Tailnet { peer } => Some(*peer),
        PeerSource::Remote { peer } if tailscale::is_tailscale_ip(peer.ip()) => Some(*peer),
        PeerSource::Serve => forwarded_tailscale(headers),
        _ => None,
    };
    if let Some(peer) = peer
        && let Ok(info) = shared.tailnet.identify_tcp(peer).await
    {
        return caller_from_peer(info, uid);
    }
    match source {
        PeerSource::Local => {
            if let Some(uid) = uid {
                Caller {
                    tailscale_login: None,
                    tags: Vec::new(),
                    uid: Some(uid),
                    identified: true,
                    anonymous: false,
                }
            } else {
                anonymous()
            }
        }
        PeerSource::Serve | PeerSource::Remote { .. } | PeerSource::Tailnet { .. } => anonymous(),
    }
}

fn caller_from_peer(info: PeerInfo, uid: Option<u32>) -> Caller {
    tailscale_caller(info.login_name, info.tags, uid)
}

fn tailscale_caller(login: Option<String>, tags: Vec<String>, uid: Option<u32>) -> Caller {
    Caller {
        tailscale_login: login,
        tags,
        uid,
        identified: true,
        anonymous: false,
    }
}

fn anonymous() -> Caller {
    Caller {
        tailscale_login: None,
        tags: Vec::new(),
        uid: None,
        identified: false,
        anonymous: true,
    }
}

fn forwarded_tailscale(headers: &str) -> Option<std::net::SocketAddr> {
    let forwarded = http_header(headers, "x-forwarded-for")?;
    let first = forwarded.split(',').next()?.trim();
    let ip: std::net::IpAddr = first.parse().ok()?;
    if !tailscale::is_tailscale_ip(ip) {
        return None;
    }
    Some(std::net::SocketAddr::new(ip, 0))
}

async fn ensure_account_server(shared: &Shared, user: &OsUser) -> anyhow::Result<()> {
    let gate = {
        let mut gates = shared.gates.lock().unwrap();
        gates
            .entry(user.name.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _guard = gate.lock().await;
    let personal = personal_layout(&shared.runtime_root);
    let (socket, state_dir) = account_paths(&shared.runtime_root, user, personal);
    if UnixStream::connect(&socket).await.is_ok() {
        return Ok(());
    }
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        chown_if_root(parent, user.uid, user.gid);
    }
    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("creating {}", state_dir.display()))?;
    chown_if_root(&state_dir, user.uid, user.gid);
    let _ = std::fs::remove_file(&socket);
    let server_args = account_server_args(&socket, &state_dir);
    let pid_file = socket.parent().map(|parent| parent.join("server.pid"));
    let euid = unsafe { libc::geteuid() };
    let mut child = if supervisor_needed(euid, user.uid, shared.pam) {
        spawn_supervisor(shared, user, &server_args, pid_file.as_deref())?
    } else {
        spawn_direct(shared, user, &server_args, pid_file.as_deref())?
    };
    let pid = child.id();
    tokio::spawn(async move {
        let _ = tokio::task::spawn_blocking(move || child.wait()).await;
    });
    for _ in 0..50 {
        if UnixStream::connect(&socket).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    bail!("account {} did not open {}", user.name, socket.display())
}

fn account_server_args(socket: &Path, state_dir: &Path) -> Vec<String> {
    vec![
        "--listen".into(),
        socket.display().to_string(),
        "--state-dir".into(),
        state_dir.display().to_string(),
        "--socket-mode".into(),
        "0600".into(),
        "--log-format".into(),
        "text".into(),
    ]
}

/// Root opens a PAM session in a detached supervisor. A non-root login
/// server can only serve its own uid, and it cannot open a PAM session.
pub fn supervisor_needed(euid: u32, target_uid: u32, pam: bool) -> bool {
    euid == 0 && (pam || target_uid != euid)
}

fn spawn_supervisor(
    shared: &Shared,
    user: &OsUser,
    server_args: &[String],
    pid_file: Option<&Path>,
) -> anyhow::Result<std::process::Child> {
    let mut command = std::process::Command::new(&shared.bin);
    command
        .arg("login-session")
        .arg("--user")
        .arg(&user.name)
        .arg("--uid")
        .arg(user.uid.to_string())
        .arg("--gid")
        .arg(user.gid.to_string())
        .arg("--home")
        .arg(&user.home)
        .arg("--shell")
        .arg(&user.shell)
        .arg("--pam-service")
        .arg(&shared.pam_service)
        .arg("--pam")
        .arg(if shared.pam { "true" } else { "false" });
    if let Some(path) = pid_file {
        command.arg("--pid-file").arg(path);
    }
    command.arg("--").arg(&shared.bin).args(server_args);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EPERM) {
                    return Err(err);
                }
            }
            Ok(())
        });
    }
    command
        .spawn()
        .with_context(|| format!("starting a login session for account {}", user.name))
}

fn spawn_direct(
    shared: &Shared,
    user: &OsUser,
    server_args: &[String],
    pid_file: Option<&Path>,
) -> anyhow::Result<std::process::Child> {
    let mut command = std::process::Command::new(&shared.bin);
    command.args(server_args);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());
    if unsafe { libc::geteuid() } == 0 && user.uid != 0 {
        command.env_clear();
        command.env("HOME", &user.home);
        command.env("USER", &user.name);
        command.env("LOGNAME", &user.name);
        command.env("SHELL", &user.shell);
        command.env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        );
        if !user.home.is_empty() {
            command.current_dir(&user.home);
        }
    }
    let uid = user.uid;
    let gid = user.gid;
    unsafe {
        command.pre_exec(move || drop_privileges(uid, gid));
    }
    let child = command
        .spawn()
        .with_context(|| format!("starting a server for account {}", user.name))?;
    if let Some(path) = pid_file {
        let _ = std::fs::write(path, child.id().to_string());
    }
    Ok(child)
}

static LOGIN_SESSION_STOP: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn on_login_session_stop(_signal: libc::c_int) {
    LOGIN_SESSION_STOP.store(true, Ordering::SeqCst);
}

pub fn run_login_session(opts: LoginSessionOptions) -> anyhow::Result<()> {
    if opts.server.is_empty() {
        bail!("login-session needs the account server command after --");
    }
    if shell_refused(&opts.shell) {
        bail!("account {} has a nologin shell", opts.user);
    }
    if opts.pam && unsafe { libc::geteuid() } != 0 {
        bail!("a PAM login session has to be opened by the root login server");
    }
    unsafe {
        libc::signal(
            libc::SIGTERM,
            on_login_session_stop as *const () as libc::sighandler_t,
        );
        if libc::setsid() < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EPERM) {
                return Err(err).context("setsid");
            }
        }
    }
    let mut pam_session = if opts.pam {
        Some(crate::pam::open_login_session(
            &opts.pam_service,
            &opts.user,
        )?)
    } else {
        None
    };
    if LOGIN_SESSION_STOP.load(Ordering::SeqCst) {
        bail!("login session stopped before the account server started");
    }
    let mut command = std::process::Command::new(&opts.server[0]);
    command.args(&opts.server[1..]);
    command
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());
    if let Some(session) = &pam_session {
        for (key, value) in session.env() {
            command.env(key, value);
        }
    }
    let shell = if opts.shell.is_empty() {
        "/bin/sh"
    } else {
        opts.shell.as_str()
    };
    command.env("HOME", &opts.home);
    command.env("USER", &opts.user);
    command.env("LOGNAME", &opts.user);
    command.env("SHELL", shell);
    command.env(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    let runtime = format!("/run/user/{}", opts.uid);
    if Path::new(&runtime).is_dir() {
        command.env("XDG_RUNTIME_DIR", &runtime);
    }
    if !opts.home.is_empty() && Path::new(&opts.home).is_dir() {
        command.current_dir(&opts.home);
    }
    let c_user = CString::new(opts.user.clone()).context("account name")?;
    if unsafe { libc::initgroups(c_user.as_ptr(), opts.gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("initgroups");
    }
    let uid = opts.uid;
    let gid = opts.gid;
    unsafe {
        command.pre_exec(move || drop_to_account(uid, gid));
    }
    let child = command
        .spawn()
        .with_context(|| format!("starting the server for account {}", opts.user))?;
    if let Some(path) = &opts.pid_file {
        let _ = std::fs::write(path, format!("{}\n", child.id()));
    }
    let pid = child.id() as libc::pid_t;
    let status = wait_for_account(pid)?;
    if let Some(session) = pam_session.as_mut() {
        session.close();
    }
    drop(pam_session);
    if !status.success() {
        bail!("account server for {} exited: {status}", opts.user);
    }
    Ok(())
}

fn wait_for_account(pid: libc::pid_t) -> anyhow::Result<std::process::ExitStatus> {
    loop {
        let mut raw = 0;
        let rc = unsafe { libc::waitpid(pid, &mut raw, libc::WNOHANG) };
        if rc == pid {
            return Ok(std::process::ExitStatus::from_raw(raw));
        }
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(err).context("waiting for the account server");
            }
        }
        if LOGIN_SESSION_STOP.load(Ordering::SeqCst) {
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            let mut raw = 0;
            unsafe { libc::waitpid(pid, &mut raw, 0) };
            return Ok(std::process::ExitStatus::from_raw(raw));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn drop_to_account(uid: u32, gid: u32) -> std::io::Result<()> {
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
        if libc::getppid() == 1 {
            libc::raise(libc::SIGTERM);
        }
        if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

fn shell_refused(shell: &str) -> bool {
    matches!(shell.rsplit('/').next(), Some("nologin" | "false"))
}

fn drop_privileges(uid: u32, gid: u32) -> std::io::Result<()> {
    unsafe {
        if libc::setsid() < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let euid = libc::geteuid();
        if euid == uid {
            return Ok(());
        }
        if euid != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "login-server must run as root to start another account",
            ));
        }
        if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

fn chown_if_root(path: &Path, uid: u32, gid: u32) {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let Ok(bytes) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    unsafe {
        libc::chown(bytes.as_ptr(), uid, gid);
    }
}

/// Personal sockets when this is the real `/run/rex` login server on a
/// logind machine. Any other runtime root, including tests, uses
/// `<root>/accounts/<name>`.
pub fn personal_layout(runtime_root: &Path) -> bool {
    runtime_root == Path::new("/run/rex") && Path::new("/run/systemd/system").exists()
}

pub fn account_paths(runtime_root: &Path, user: &OsUser, personal: bool) -> (PathBuf, PathBuf) {
    if personal {
        let runtime = PathBuf::from(format!("/run/user/{}", user.uid));
        let state = if user.home.is_empty() {
            PathBuf::from(".local/state/rex")
        } else {
            PathBuf::from(&user.home).join(".local/state/rex")
        };
        (runtime.join("rex/server.sock"), state)
    } else {
        let dir = runtime_root.join("accounts").join(&user.name);
        (dir.join("server.sock"), dir.join("state"))
    }
}

pub fn passwd_users(pam: bool) -> Vec<OsUser> {
    let text = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let shadow = if pam {
        String::new()
    } else {
        std::fs::read_to_string("/etc/shadow").unwrap_or_default()
    };
    text.lines()
        .filter_map(|line| parse_passwd_line(line, &shadow, pam))
        .collect()
}

pub fn parse_passwd_line(line: &str, shadow: &str, pam: bool) -> Option<OsUser> {
    let mut fields = line.split(':');
    let name = fields.next()?.to_string();
    let _password = fields.next()?;
    let uid: u32 = fields.next()?.parse().ok()?;
    let gid: u32 = fields.next()?.parse().ok()?;
    let _gecos = fields.next()?;
    let home = fields.next()?.to_string();
    let shell = fields.next().unwrap_or("").to_string();
    let locked = if pam {
        false
    } else {
        shadow_locked(shadow, &name)
    };
    Some(OsUser {
        name,
        uid,
        gid,
        home,
        shell,
        locked,
    })
}

pub fn shadow_locked(shadow: &str, name: &str) -> bool {
    let Some(field) = shadow_password(shadow, name) else {
        return true;
    };
    password_locked(&field)
}

pub fn shadow_password(shadow: &str, name: &str) -> Option<String> {
    for line in shadow.lines() {
        let mut fields = line.split(':');
        if fields.next() == Some(name) {
            return fields.next().map(str::to_string);
        }
    }
    None
}

pub fn password_locked(field: &str) -> bool {
    field.is_empty() || field.starts_with('!') || field.starts_with('*')
}

pub fn http_header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    for line in head.split("\r\n").skip(1) {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            return Some(value.trim());
        }
    }
    None
}

async fn read_http_head<R: AsyncRead + Unpin>(io: &mut R) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 2048];
    while !buf.windows(4).any(|window| window == b"\r\n\r\n") {
        if buf.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request headers too large",
            ));
        }
        let n = tokio::time::timeout(Duration::from_secs(10), io.read(&mut tmp))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "reading request headers")
            })??;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(buf)
}

async fn write_status<S: AsyncWrite + Unpin>(io: &mut S, status: u16, reason: &str, message: &str) {
    let body = message.as_bytes();
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = io.write_all(head.as_bytes()).await;
    let _ = io.write_all(body).await;
}

fn prepare_socket(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::Caller;

    fn alice() -> Caller {
        Caller {
            tailscale_login: Some("alice@example.com".into()),
            tags: Vec::new(),
            uid: Some(1000),
            identified: true,
            anonymous: false,
        }
    }

    fn user(name: &str) -> OsUser {
        OsUser {
            name: name.into(),
            uid: 1000,
            gid: 1000,
            home: format!("/home/{name}"),
            shell: "/bin/bash".into(),
            locked: false,
        }
    }

    #[test]
    fn root_uses_a_supervisor_for_pam_and_for_other_accounts() {
        assert!(supervisor_needed(0, 1000, true));
        assert!(supervisor_needed(0, 0, true));
        assert!(supervisor_needed(0, 1000, false));
        assert!(!supervisor_needed(0, 0, false));
        assert!(!supervisor_needed(1000, 1000, true));
        assert!(!supervisor_needed(1000, 0, false));
    }

    #[test]
    fn shadow_lock_and_account_paths() {
        let shadow = "alice:$6$hash:1:0:99999:7:::\nnobody:!:19000::::::\n";
        assert!(!shadow_locked(shadow, "alice"));
        assert!(shadow_locked(shadow, "nobody"));
        assert!(password_locked(""));
        assert!(password_locked("*"));
        assert!(shadow_locked(shadow, "missing"));
        let user = parse_passwd_line(
            "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
            shadow,
            false,
        )
        .unwrap();
        assert_eq!(user.home, "/home/alice");
        assert!(!user.locked);
        let locked = parse_passwd_line(
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
            shadow,
            false,
        )
        .unwrap();
        assert!(locked.locked);
        let (socket, state) = account_paths(Path::new("/tmp/rex-runtime"), &user, false);
        assert_eq!(
            socket,
            Path::new("/tmp/rex-runtime/accounts/alice/server.sock")
        );
        assert_eq!(state, Path::new("/tmp/rex-runtime/accounts/alice/state"));
        let (socket, state) = account_paths(Path::new("/run/rex"), &user, true);
        assert_eq!(socket, Path::new("/run/user/1000/rex/server.sock"));
        assert_eq!(state, Path::new("/home/alice/.local/state/rex"));
        let head = "GET /api/help HTTP/1.1\r\nHost: root@build.example.ts.net\r\nTailscale-User-Login: alice@example.com\r\n\r\n";
        assert_eq!(http_header(head, "host"), Some("root@build.example.ts.net"));
        assert_eq!(
            crate::accounts::account_from_http_host(http_header(head, "host").unwrap()).as_deref(),
            Some("root")
        );
    }

    #[test]
    fn reload_closes_only_removed_access() {
        let before = parse_accounts(
            r#"{ "version": 1, "accounts": { "alice": { "principals": ["tailscale:alice@example.com"] }, "root": { "principals": ["tailscale:alice@example.com"] } } }"#,
        )
        .unwrap();
        let after = parse_accounts(
            r#"{ "version": 1, "accounts": { "alice": { "principals": ["tailscale:alice@example.com"] } } }"#,
        )
        .unwrap();
        let users = vec![user("alice"), user("root")];
        let live = vec![
            LiveView {
                id: 1,
                caller: alice(),
                account: "alice".into(),
            },
            LiveView {
                id: 2,
                caller: alice(),
                account: "root".into(),
            },
        ];
        assert!(close_denied(&before, &users, &live).is_empty());
        assert_eq!(close_denied(&after, &users, &live), vec![2]);
    }
}

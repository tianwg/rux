mod accounts;
mod api;
mod config;
mod login;
mod pam;
mod apple;
mod remote;
mod schema;
mod script;
mod state;
mod tailscale;
mod terminal;
mod tsnet;
mod vt;
mod ws;

use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::Parser;
use serde_json::Value;
use tokio::task::JoinSet;

use crate::config::LuaConfig;
use crate::state::State;
use crate::tailscale::{ListenSpec, TailnetGate, TailnetPolicy};

#[derive(Parser, Debug)]
#[command(
    name = "rux-server",
    about = "A Rex-compatible server written in Rust"
)]
struct Args {
    /// Listen on a Unix socket or an HTTP endpoint (http://HOST:PORT).
    #[arg(long, default_value = "/tmp/rux.sock")]
    listen: String,
    /// Add another Unix socket or HTTP endpoint. May be repeated.
    #[arg(long = "extra-listen")]
    extra_listen: Vec<String>,
    /// Give unauthenticated HTTP clients full server access. Only use on a
    /// trusted network or behind an authenticating reverse proxy.
    #[arg(long)]
    allow_anonymous: bool,
    /// PEM certificate chain used by https:// listeners.
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// PEM private key used by https:// listeners.
    #[arg(long)]
    tls_key: Option<PathBuf>,
    /// Require this bearer token on remote HTTP/HTTPS control and data requests.
    #[arg(long)]
    bearer_token_file: Option<PathBuf>,
    /// Refuse every plain HTTP/HTTPS listener. Remote access is then only
    /// `tailnet://` or `tailnet-serve://`, plus a local Unix socket.
    #[arg(long)]
    tailnet_only: bool,
    /// Admit any peer tailscaled can identify, not only the node owner.
    /// Required for a tagged node, which has no owner. Tailnet ACLs still apply.
    #[arg(long, env = "RUX_TAILNET_ALLOW_IDENTIFIED")]
    tailnet_allow_identified: bool,
    /// Join the tailnet as this server's own device, via the rux-tsnet sidecar.
    #[arg(long)]
    tailscale: bool,
    /// One-time Tailscale auth key. `-` reads it from stdin. Never logged.
    #[arg(long)]
    tailscale_auth_key_file: Option<PathBuf>,
    /// Device name for built-in Tailscale. Defaults to `rex`.
    #[arg(long)]
    tailscale_hostname: Option<String>,
    /// Tailscale tag for the built-in device, such as `tag:rex`. Repeatable.
    /// Requires `--tailscale-allow-tailnet-members`.
    #[arg(long = "tailscale-advertise-tag")]
    tailscale_advertise_tag: Vec<String>,
    /// Let any tailnet member your ACLs allow connect to the built-in device.
    #[arg(long)]
    tailscale_allow_tailnet_members: bool,
    /// tailscaled LocalAPI socket used for status and whois.
    #[arg(long, default_value = tailscale::DEFAULT_SOCKET)]
    tailscale_socket: PathBuf,
    /// Directory for persistent host records and the stable host ID.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Lua configuration file. Defaults to REX_CONFIG or rex/init.lua in the config directory.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Log file path reported in server.status.
    #[arg(long, default_value = "")]
    log_path: String,
    /// `text` or `json`.
    #[arg(long, default_value = "text", global = true)]
    log_format: String,
    /// Unix socket mode, such as `0660` for a shared server. Default `0600`.
    #[arg(long, default_value = "0600")]
    socket_mode: String,
    /// Refuse `session.create` once this many sessions exist. `0` means no cap.
    #[arg(long, default_value_t = 0)]
    max_sessions: u64,
    /// Personal server: socket under `$XDG_RUNTIME_DIR/rex`, state under `$XDG_STATE_HOME/rex`.
    #[arg(long)]
    personal: bool,
    /// Stop about 10 seconds after the last session and the last connection close.
    #[arg(long)]
    exit_empty: bool,
    /// API catalog JSON. Defaults to the catalog generated for the methods rux implements.
    /// Point this at help text you saved from a server you run.
    #[arg(long, env = "RUX_API_HELP")]
    api_help: Option<PathBuf>,
    /// Block-creator catalog JSON. Defaults to the catalog shipped with rux.
    #[arg(long = "block-creators", env = "RUX_BLOCK_CREATORS")]
    block_creators_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Run a Lua script against an in-process server, the way `rex do` does.
    Do {
        /// Inline script source.
        #[arg(short = 'e')]
        eval: Option<String>,
        /// Session id filled into `rex.session` calls.
        #[arg(short = 's', long = "session")]
        session: Option<String>,
        /// Block id filled into `rex.block.call`.
        #[arg(short = 'b', long = "block")]
        block: Option<String>,
        /// JSON object of arguments. `@path` reads a file.
        #[arg(long = "args")]
        args_json: Option<String>,
        /// Indent the JSON value the script returns.
        #[arg(long)]
        json: bool,
        /// A `.lua` path, `-` for stdin, then `key=value` arguments.
        script: Vec<String>,
    },
    /// Check `/etc/rex/accounts.jsonc` and serve the login-server selection.
    LoginServer {
        /// Accounts file. JSON with comments and trailing commas.
        #[arg(long, default_value = "/etc/rex/accounts.jsonc")]
        accounts: PathBuf,
        /// Listen socket. The documented path is `/run/rex/login-server.sock`.
        #[arg(long, default_value = "unix:///run/rex/login-server.sock")]
        listen: String,
        /// Runtime directory shared with per-account servers.
        #[arg(long, default_value = "/run/rex")]
        runtime_root: PathBuf,
        /// PAM service name. `--pam=false` uses nologin and shadow instead.
        #[arg(long, default_value = "rex-login-server")]
        pam_service: String,
        /// Exit after parsing the accounts file.
        #[arg(long)]
        check: bool,
        /// Use PAM. `--pam=false` checks `/etc/nologin` and `/etc/shadow` only.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        pam: bool,
    },
    /// Internal supervisor: open the account's PAM login session, then run
    /// its server. The login server spawns this. It is not a Rex mode.
    #[command(hide = true)]
    LoginSession {
        #[arg(long)]
        user: String,
        #[arg(long)]
        uid: u32,
        #[arg(long)]
        gid: u32,
        #[arg(long, default_value = "")]
        home: String,
        #[arg(long, default_value = "")]
        shell: String,
        #[arg(long, default_value = "rex-login-server")]
        pam_service: String,
        /// `--pam=false` opens no login session.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        pam: bool,
        /// Where to write the account server's pid.
        #[arg(long)]
        pid_file: Option<PathBuf>,
        /// Account-server argv. Pass it after `--`.
        #[arg(last = true)]
        server: Vec<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let mut args = Args::parse();
    init_tracing(&args.log_format)?;
    if let Some(Command::LoginSession { .. }) = &args.command {
        let Some(Command::LoginSession {
            user,
            uid,
            gid,
            home,
            shell,
            pam_service,
            pam,
            pid_file,
            server,
        }) = args.command.take()
        else {
            unreachable!("login-session command");
        };
        // No tokio runtime here. PAM and the following fork must run in a
        // single-threaded process.
        return login::run_login_session(login::LoginSessionOptions {
            user,
            uid,
            gid,
            home,
            shell,
            pam_service,
            pam,
            pid_file,
            server,
        });
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    runtime.block_on(async_main(args))
}

fn load_catalog(path: Option<&PathBuf>, embedded: &str, label: &str) -> anyhow::Result<Value> {
    let text = if let Some(path) = path {
        std::fs::read_to_string(path)
            .with_context(|| format!("reading {label} {}", path.display()))?
    } else {
        embedded.to_string()
    };
    serde_json::from_str(&text).with_context(|| format!("parsing {label}"))
}

fn init_tracing(log_format: &str) -> anyhow::Result<()> {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    match log_format {
        "text" => tracing_subscriber::fmt().with_env_filter(filter).init(),
        "json" => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
        other => bail!("--log-format must be text or json, not {other}"),
    }
    Ok(())
}

async fn async_main(mut args: Args) -> anyhow::Result<()> {
    if let Some(command) = args.command.take() {
        return match command {
            Command::Do { .. } => run_do_command(&args, command),
            Command::LoginServer { .. } => run_login_server(&args, command).await,
            Command::LoginSession { .. } => {
                unreachable!("login-session runs before the runtime")
            }
        };
    }
    if args.tailnet_only && args.allow_anonymous {
        bail!("--tailnet-only cannot be combined with --allow-anonymous");
    }
    let remote_token = args
        .bearer_token_file
        .as_ref()
        .map(|path| read_bearer_token(path))
        .transpose()?;
    let help = load_catalog(
        args.api_help.as_ref(),
        include_str!("../assets/api-help.json"),
        "API catalog",
    )?;
    let creators = load_catalog(
        args.block_creators_file.as_ref(),
        include_str!("../assets/block-creators.json"),
        "block creators",
    )?;
    let config_path = args.config.unwrap_or_else(LuaConfig::default_path);
    if args.personal {
        let uid = unsafe { state::libc_getuid() };
        let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from);
        let state_home = std::env::var_os("XDG_STATE_HOME").map(std::path::PathBuf::from);
        let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        let (socket, state_dir) = accounts::personal_paths(
            runtime.as_deref(),
            state_home.as_deref(),
            home.as_deref(),
            uid,
        );
        if args.listen == "/tmp/rux.sock" {
            args.listen = socket.to_string_lossy().into_owned();
        }
        if args.state_dir.is_none() {
            args.state_dir = Some(state_dir);
        }
    }
    let state = Arc::new(State::new(
        help,
        creators,
        args.log_path.clone(),
        args.state_dir.clone(),
        config_path,
    ));
    state
        .max_sessions
        .store(args.max_sessions, std::sync::atomic::Ordering::SeqCst);
    state
        .exit_empty
        .store(args.exit_empty, std::sync::atomic::Ordering::SeqCst);
    {
        // Terminal children get this as REX_SERVER (see state::State).
        let addr = if args.listen.contains("://") {
            args.listen.clone()
        } else {
            format!("unix://{}", args.listen)
        };
        *state.server_addr.lock().unwrap() = Some(addr);
    }
    if args.tailscale && tsnet::locate_binary().is_none() {
        bail!(
            "built-in Tailscale needs the rux-tsnet sidecar next to rux-server, or RUX_TSNET_BIN"
        );
    }
    if let Some(bin) = tsnet::locate_binary() {
        let dir = state.state_dir.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("rux-tsnet-{}", state.instance_id))
        });
        *state.tsnet_launch.lock().unwrap() = Some(state::TsnetLaunch {
            bin,
            state_dir: dir.join("tsnet"),
            backend: tsnet_backend(&args.listen),
        });
        if args.tailscale {
            let node = state
                .ensure_tsnet()
                .map_err(|error| anyhow::anyhow!(error))?;
            let auth_key = args
                .tailscale_auth_key_file
                .as_ref()
                .map(|path| tsnet::read_auth_key(path))
                .transpose()
                .map_err(|error| anyhow::anyhow!(error))?;
            node.enable(tsnet::EnableRequest {
                hostname: args.tailscale_hostname.clone(),
                allow_members: args.tailscale_allow_tailnet_members,
                auth_key,
                advertise_tags: args.tailscale_advertise_tag.clone(),
            })
            .map_err(|error| anyhow::anyhow!(error.message))?;
        } else {
            tracing::info!("host tailscaled mode; not starting the rux-tsnet sidecar");
        }
    }

    let mut endpoints = vec![args.listen.clone()];
    endpoints.extend(args.extra_listen.iter().cloned());
    let mut specs = Vec::with_capacity(endpoints.len());
    for endpoint in &endpoints {
        let spec = tailscale::parse_listen(endpoint)?;
        tailscale::enforce_tailnet_only(&spec, args.tailnet_only)?;
        specs.push(spec);
    }
    let http_port = specs.iter().find_map(|spec| match spec {
        ListenSpec::Tailnet { port, .. } => Some(*port),
        _ => None,
    });
    let https_serve = specs
        .iter()
        .any(|spec| matches!(spec, ListenSpec::TailnetServe(_)));
    let tailscale_socket = if args.tailscale_socket == PathBuf::from(tailscale::DEFAULT_SOCKET) {
        tailscale::default_socket_path()
    } else {
        args.tailscale_socket.clone()
    };
    let tailnet = (http_port.is_some() || https_serve).then(|| {
        Arc::new(TailnetGate::new(
            tailscale_socket.clone(),
            TailnetPolicy {
                allow_identified: args.tailnet_allow_identified,
                http_port,
                https_serve,
            },
        ))
    });
    if tailnet.is_some() {
        tracing::info!(
            socket = %tailscale_socket.display(),
            allow_identified = args.tailnet_allow_identified,
            tailnet_only = args.tailnet_only,
            "tailnet identity uses the host tailscaled LocalAPI"
        );
    }

    let mut servers = JoinSet::new();
    for spec in specs {
        match spec {
            ListenSpec::Unix(path) => {
                prepare_socket_path(&path)?;
                let listener = tokio::net::UnixListener::bind(&path)
                    .with_context(|| format!("binding unix socket {}", path.display()))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = parse_socket_mode(&args.socket_mode)?;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                        .with_context(|| format!("setting permissions on {}", path.display()))?;
                }
                tracing::info!(socket = %path.display(), "listening on unix socket");
                let app = ws::router(
                    state.clone(),
                    ws::Ingress::Local,
                    args.allow_anonymous,
                    remote_token.clone(),
                    None,
                );
                servers.spawn(async move {
                    axum::serve(UnixListenerStream(listener), app)
                        .await
                        .context("serving unix socket")
                });
            }
            ListenSpec::Http(address) => {
                let listener = tokio::net::TcpListener::bind(&address)
                    .await
                    .with_context(|| format!("binding HTTP endpoint {address}"))?;
                let bound = listener.local_addr()?;
                tracing::info!(address = %bound, allow_anonymous = args.allow_anonymous, "listening on HTTP endpoint");
                if !args.allow_anonymous {
                    tracing::warn!(
                        "HTTP control access is disabled; pass --allow-anonymous only on a trusted network or behind an authenticating proxy"
                    );
                }
                let app = ws::router(
                    state.clone(),
                    ws::Ingress::Remote,
                    args.allow_anonymous,
                    remote_token.clone(),
                    None,
                );
                servers.spawn(async move {
                    axum::serve(listener, app)
                        .await
                        .context("serving HTTP endpoint")
                });
            }
            ListenSpec::Https(address) => {
                let cert_path = args
                    .tls_cert
                    .as_ref()
                    .context("https:// listeners require --tls-cert")?;
                let key_path = args
                    .tls_key
                    .as_ref()
                    .context("https:// listeners require --tls-key")?;
                let listener = tokio::net::TcpListener::bind(&address)
                    .await
                    .with_context(|| format!("binding HTTPS endpoint {address}"))?;
                let bound = listener.local_addr()?;
                let acceptor = load_tls_acceptor(cert_path, key_path)?;
                tracing::info!(address = %bound, allow_anonymous = args.allow_anonymous, "listening on HTTPS endpoint");
                if !args.allow_anonymous {
                    tracing::warn!(
                        "HTTPS control access is disabled; pass --allow-anonymous only on a trusted network or behind an authenticating proxy"
                    );
                }
                let tls_listener = TlsListener::new(listener, acceptor);
                let app = ws::router(
                    state.clone(),
                    ws::Ingress::Remote,
                    args.allow_anonymous,
                    remote_token.clone(),
                    None,
                );
                servers.spawn(async move {
                    axum::serve(tls_listener, app)
                        .await
                        .context("serving HTTPS endpoint")
                });
            }
            ListenSpec::Tailnet { host, port } => {
                let gate = tailnet
                    .clone()
                    .context("internal: tailnet listener has no identity gate")?;
                let state = state.clone();
                servers.spawn(async move {
                    let mut attempt: u32 = 0;
                    loop {
                        attempt += 1;
                        match serve_tailnet(state.clone(), gate.clone(), host, port).await {
                            Ok(()) => return Ok(()),
                            Err(err) => {
                                tracing::error!(
                                    %err,
                                    attempt,
                                    "tailnet listener not ready; retrying"
                                );
                                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            }
                        }
                    }
                });
            }
            ListenSpec::TailnetServe(path) => {
                let gate = tailnet
                    .clone()
                    .context("internal: tailnet-serve listener has no identity gate")?;
                let state = state.clone();
                servers.spawn(async move {
                    let mut attempt: u32 = 0;
                    loop {
                        attempt += 1;
                        match serve_tailnet_socket(state.clone(), gate.clone(), path.clone()).await
                        {
                            Ok(()) => return Ok(()),
                            Err(err) => {
                                tracing::error!(
                                    %err,
                                    attempt,
                                    "tailnet-serve listener not ready; retrying"
                                );
                                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            }
                        }
                    }
                });
            }
        }
    }

    if servers.is_empty() {
        bail!("no listener endpoints configured");
    }
    if args.exit_empty {
        let watch = state.clone();
        tokio::spawn(async move {
            let mut idle_since: Option<std::time::Instant> = None;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                if watch.busy() {
                    idle_since = None;
                    continue;
                }
                let start = idle_since.get_or_insert_with(std::time::Instant::now);
                if state::idle_exit_ready(true, false, start.elapsed()) {
                    tracing::info!("exit-empty: no sessions and no clients for 10s");
                    watch
                        .shutting_down
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    api::schedule_process_exit();
                    break;
                }
            }
        });
    }
    if let Some(result) = servers.join_next().await {
        result.context("listener task panicked")??;
    }
    Ok(())
}

async fn serve_tailnet(
    state: Arc<State>,
    gate: Arc<TailnetGate>,
    host: Option<std::net::IpAddr>,
    port: u16,
) -> anyhow::Result<()> {
    let discovered = gate.discover_ips().await.map_err(anyhow::Error::msg)?;
    let ips = tailscale::bind_targets(host, &discovered)?;
    let mut listeners = JoinSet::new();
    for ip in ips {
        let addr = tailscale::socket_addr_for(ip, port);
        if addr.ip().is_unspecified() || !tailscale::is_tailscale_ip(addr.ip()) {
            bail!("refusing to listen on {addr}");
        }
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(err) => {
                tracing::warn!(%addr, %err, "could not bind this Tailscale address");
                continue;
            }
        };
        let bound = listener.local_addr()?;
        if bound.ip().is_unspecified() || !tailscale::is_tailscale_ip(bound.ip()) {
            bail!("bound {bound}, which is not a Tailscale address; refusing to serve");
        }
        tracing::info!(address = %bound, "listening on tailnet address");
        let app = ws::router(
            state.clone(),
            ws::Ingress::Tailnet,
            false,
            None,
            Some(gate.clone()),
        );
        listeners.spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .context("serving tailnet address")
        });
    }
    if listeners.is_empty() {
        bail!("no Tailscale address accepted a listener; refusing 0.0.0.0");
    }
    if let Ok(status) = gate.status().await {
        for command in tailscale::client_commands(&status, gate.policy()) {
            tracing::info!(%command, "rex client connect");
        }
        if status.backend_state != "Running" {
            tracing::warn!(
                state = %status.backend_state,
                "tailscaled is not Running; whois will fail until it is"
            );
        }
    }
    if let Some(result) = listeners.join_next().await {
        result.context("tailnet task panicked")??;
    }
    Ok(())
}

async fn serve_tailnet_socket(
    state: Arc<State>,
    gate: Arc<TailnetGate>,
    path: PathBuf,
) -> anyhow::Result<()> {
    prepare_socket_path(&path)?;
    let listener = tokio::net::UnixListener::bind(&path)
        .with_context(|| format!("binding tailnet-serve socket {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {}", path.display()))?;
    }
    tracing::info!(
        socket = %path.display(),
        "listening for Tailscale Serve; only root (tailscaled) may connect, Funnel is refused"
    );
    let app = ws::router(state, ws::Ingress::TailnetServe, false, None, Some(gate));
    axum::serve(RootOnlyUnixListener(listener), app)
        .await
        .context("serving tailnet-serve socket")
}

fn parse_socket_mode(text: &str) -> anyhow::Result<u32> {
    u32::from_str_radix(text.trim_start_matches("0o").trim_start_matches('0'), 8)
        .with_context(|| format!("--socket-mode {text} is not an octal mode"))
}

async fn run_login_server(args: &Args, command: Command) -> anyhow::Result<()> {
    let Command::LoginServer {
        accounts,
        listen,
        runtime_root,
        pam_service,
        check,
        pam,
    } = command
    else {
        unreachable!("login-server command");
    };
    let text = std::fs::read_to_string(&accounts)
        .with_context(|| format!("reading {}", accounts.display()))?;
    let parsed =
        accounts::parse_accounts(&text).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    tracing::info!(
        path = %accounts.display(),
        accounts = parsed.accounts.len(),
        pam,
        service = %pam_service,
        "login server accounts"
    );
    if check {
        println!("accounts ok: {}", parsed.accounts.len());
        return Ok(());
    }
    let mut listens = vec![listen];
    listens.extend(args.extra_listen.iter().cloned());
    let needs_tls = listens.iter().any(|listen| listen.starts_with("https://"));
    let tls = if needs_tls {
        let cert = args
            .tls_cert
            .as_ref()
            .context("an https:// login-server listener needs --tls-cert")?;
        let key = args
            .tls_key
            .as_ref()
            .context("an https:// login-server listener needs --tls-key")?;
        Some(load_tls_acceptor(cert, key)?)
    } else {
        None
    };
    login::serve(login::Options {
        accounts_path: accounts,
        listens,
        runtime_root,
        pam,
        pam_service,
        bin: std::env::current_exe().context("finding rux-server")?,
        tls,
    })
    .await
}

fn tsnet_backend(listen: &str) -> String {
    if listen.starts_with("http://") || listen.starts_with("https://") {
        listen.to_string()
    } else if let Some(path) = listen.strip_prefix("unix://") {
        format!("unix://{path}")
    } else {
        format!("unix://{listen}")
    }
}

fn load_tls_acceptor(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    let cert_file = std::fs::File::open(cert_path)
        .with_context(|| format!("opening TLS certificate {}", cert_path.display()))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .context("reading PEM TLS certificate chain")?;
    if certs.is_empty() {
        bail!("TLS certificate file contains no certificates");
    }
    let key_file = std::fs::File::open(key_path)
        .with_context(|| format!("opening TLS private key {}", key_path.display()))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("reading PEM TLS private key")?
        .context("TLS private key file contains no supported private key")?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building TLS server configuration")?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

fn run_do_command(args: &Args, do_args: Command) -> anyhow::Result<()> {
    let Command::Do {
        eval,
        session,
        block,
        args_json,
        json: pretty,
        script,
    } = do_args
    else {
        unreachable!("do command");
    };
    let (source, name, pairs) = script_source(eval, &script)?;
    let mut script_args = match args_json.as_deref() {
        Some(text) => {
            let text = if let Some(path) = text.strip_prefix('@') {
                std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?
            } else {
                text.to_string()
            };
            serde_json::from_str::<Value>(&text).context("--args must be a JSON object")?
        }
        None => serde_json::json!({}),
    };
    if !script_args.is_object() {
        bail!("--args must be a JSON object");
    }
    for pair in pairs {
        let Some((key, value)) = pair.split_once('=') else {
            bail!("script argument {pair} must be key=value");
        };
        script_args[key] = script_arg_value(value);
    }
    let help = load_catalog(
        args.api_help.as_ref(),
        include_str!("../assets/api-help.json"),
        "API catalog",
    )?;
    let creators = load_catalog(
        args.block_creators_file.as_ref(),
        include_str!("../assets/block-creators.json"),
        "block creators",
    )?;
    let config_path = args.config.clone().unwrap_or_else(LuaConfig::default_path);
    let state = Arc::new(State::new(
        help,
        creators,
        String::new(),
        args.state_dir.clone(),
        config_path,
    ));
    let (hosts, host_endpoints) =
        script::host_labels_and_endpoints(&state.config.lock().unwrap().hosts());
    let handle = tokio::runtime::Handle::current();
    let session_id = session.clone();
    let block_id = block.clone();
    let worker = std::thread::spawn(move || {
        let api: crate::config::ApiCall = Arc::new(move |method, payload| {
            handle
                .block_on(api::dispatch(&state, "client:do", true, &method, payload))
                .map_err(|error| error.message)
        });
        script::run_script(
            script::ScriptRequest {
                name,
                source,
                session_id,
                block_id,
                client_id: Some("client:do".into()),
                args: script_args,
                hosts,
                host_endpoints,
            },
            std::sync::mpsc::channel().1,
            api,
            None,
        )
    });
    let result = worker
        .join()
        .map_err(|_| anyhow::anyhow!("script thread panicked"))?
        .map_err(|error| anyhow::anyhow!(error))?;
    if !result.value.is_null() {
        let text = if pretty {
            serde_json::to_string_pretty(&result.value)?
        } else {
            serde_json::to_string(&result.value)?
        };
        println!("{text}");
    }
    for diagnostic in &result.diagnostics {
        if let Some(message) = diagnostic.get("message").and_then(Value::as_str) {
            eprintln!("{message}");
        }
    }
    if result.code != 0 {
        std::process::exit(result.code);
    }
    Ok(())
}

fn script_source(
    eval: Option<String>,
    script: &[String],
) -> anyhow::Result<(String, String, Vec<String>)> {
    if let Some(source) = eval {
        if script
            .iter()
            .any(|arg| arg.ends_with(".lua") || arg.contains('/'))
        {
            bail!("-e cannot be combined with a script file");
        }
        return Ok((source, "-e".into(), script.to_vec()));
    }
    let Some((first, rest)) = script.split_first() else {
        bail!("pass a script file, -e, or - for stdin");
    };
    if first == "-" {
        let mut source = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut source)?;
        return Ok((source, "stdin.lua".into(), rest.to_vec()));
    }
    if first.ends_with(".lua") || first.contains('/') {
        let source = std::fs::read_to_string(first).with_context(|| format!("reading {first}"))?;
        return Ok((source, first.clone(), rest.to_vec()));
    }
    bail!("{first} is not a .lua script; action names are run with rex.invoke inside a script");
}

fn script_arg_value(value: &str) -> Value {
    if value == "true" {
        return serde_json::json!(true);
    }
    if value == "false" {
        return serde_json::json!(false);
    }
    if let Ok(number) = value.parse::<i64>() {
        return serde_json::json!(number);
    }
    if value.contains('.')
        && let Ok(number) = value.parse::<f64>()
    {
        return serde_json::json!(number);
    }
    serde_json::json!(value)
}

fn read_bearer_token(path: &std::path::Path) -> anyhow::Result<Arc<str>> {
    let token = std::fs::read_to_string(path)
        .with_context(|| format!("reading bearer token file {}", path.display()))?;
    let token = token.trim();
    if token.len() < 32 || token.chars().any(char::is_whitespace) {
        bail!("bearer token must be at least 32 non-whitespace characters");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!("bearer token file must not be accessible by group or other users");
        }
    }
    Ok(Arc::from(token))
}

fn prepare_socket_path(path: &std::path::Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating socket directory {}", parent.display()))?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                if !metadata.file_type().is_socket() {
                    bail!("refusing to replace non-socket path {}", path.display());
                }
            }
            std::fs::remove_file(path)
                .with_context(|| format!("removing stale socket {}", path.display()))?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("checking socket {}", path.display())),
    }
    Ok(())
}

/// axum listener over a unix socket.
struct UnixListenerStream(tokio::net::UnixListener);

impl axum::serve::Listener for UnixListenerStream {
    type Io = tokio::net::UnixStream;
    type Addr = PathBuf;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.0.accept().await {
                Ok((stream, _)) => return (stream, PathBuf::new()),
                Err(err) => {
                    tracing::warn!(%err, "accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(PathBuf::new())
    }
}

/// Unix listener that accepts only uid 0. tailscaled, which dials a Serve
/// backend, runs as root. Any other local user is dropped before HTTP so
/// identity headers cannot be spoofed by a process that can see the socket.
struct RootOnlyUnixListener(tokio::net::UnixListener);

impl axum::serve::Listener for RootOnlyUnixListener {
    type Io = tokio::net::UnixStream;
    type Addr = PathBuf;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, _) = match self.0.accept().await {
                Ok(accepted) => accepted,
                Err(err) => {
                    tracing::warn!(%err, "tailnet-serve accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            };
            match stream.peer_cred() {
                Ok(cred) if cred.uid() == 0 => return (stream, PathBuf::new()),
                Ok(cred) => {
                    tracing::warn!(
                        uid = cred.uid(),
                        "rejected tailnet-serve connection from a non-root user"
                    );
                }
                Err(err) => {
                    tracing::warn!(%err, "rejected tailnet-serve connection without peer credentials");
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(PathBuf::new())
    }
}

type TlsIo = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

struct TlsListener {
    accepted: tokio::sync::mpsc::Receiver<(TlsIo, SocketAddr)>,
    local_addr: SocketAddr,
}

impl TlsListener {
    fn new(listener: tokio::net::TcpListener, acceptor: tokio_rustls::TlsAcceptor) -> Self {
        let local_addr = listener.local_addr().expect("bound TCP listener");
        let (tx, accepted) = tokio::sync::mpsc::channel(128);
        tokio::spawn(async move {
            loop {
                let (stream, address) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        tracing::warn!(%err, "TLS listener accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        acceptor.accept(stream),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => {
                            let _ = tx.send((stream, address)).await;
                        }
                        Ok(Err(err)) => tracing::debug!(%address, %err, "TLS handshake rejected"),
                        Err(_) => tracing::debug!(%address, "TLS handshake timed out"),
                    }
                });
            }
        });
        Self {
            accepted,
            local_addr,
        }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsIo;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.accepted.recv().await {
            Some(accepted) => accepted,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_socket_mode;

    #[test]
    fn socket_mode_accepts_octal() {
        assert_eq!(parse_socket_mode("0600").unwrap(), 0o600);
        assert_eq!(parse_socket_mode("0660").unwrap(), 0o660);
        assert_eq!(parse_socket_mode("0o660").unwrap(), 0o660);
        assert!(parse_socket_mode("zz").is_err());
    }
}

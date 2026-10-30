//! PTY-backed terminal block.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use serde_json::{Value, json};

use crate::vt::Screen;

pub struct TerminalOptions {
    pub shell: Option<String>,
    pub command: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub cols: u16,
    pub rows: u16,
    pub initial_input: Option<String>,
    pub env: Vec<(String, String)>,
}

impl Default for TerminalOptions {
    fn default() -> Self {
        Self {
            shell: None,
            command: None,
            cwd: None,
            cols: 80,
            rows: 24,
            initial_input: None,
            env: Vec::new(),
        }
    }
}

impl TerminalOptions {
    pub fn from_json(v: &Value) -> Self {
        let mut o = TerminalOptions::default();
        if let Some(s) = v.get("shell").and_then(|x| x.as_str()) {
            if !s.is_empty() {
                o.shell = Some(s.to_string());
            }
        }
        if let Some(arr) = v.get("command").and_then(|x| x.as_array()) {
            let cmd: Vec<String> = arr
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect();
            if !cmd.is_empty() {
                o.command = Some(cmd);
            }
        }
        if let Some(c) = v.get("cwd").and_then(|x| x.as_str()) {
            if !c.is_empty() {
                o.cwd = Some(c.to_string());
            }
        }
        if let Some(size) = v.get("size") {
            if let Some(c) = size.get("columns").and_then(|x| x.as_u64()) {
                o.cols = c.clamp(1, 65535) as u16;
            }
            if let Some(r) = size.get("rows").and_then(|x| x.as_u64()) {
                o.rows = r.clamp(1, 65535) as u16;
            }
        }
        if let Some(t) = v.get("initial_input").and_then(|x| x.as_str()) {
            if !t.is_empty() {
                o.initial_input = Some(t.to_string());
            }
        }
        o
    }
}

fn resolve_executable(executable: &str) -> String {
    let path = std::path::Path::new(executable);
    if path.is_absolute() {
        return std::fs::canonicalize(path)
            .unwrap_or_else(|_| path.to_path_buf())
            .to_string_lossy()
            .into_owned();
    }
    if let Some(path_env) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path_env) {
            let candidate = directory.join(executable);
            if candidate.is_file() {
                return std::fs::canonicalize(&candidate)
                    .unwrap_or(candidate)
                    .to_string_lossy()
                    .into_owned();
            }
        }
    }
    executable.to_string()
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        unsafe extern "C" {
            fn getuid() -> u32;
        }
        unsafe { getuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// The login shell for a terminal. `$SHELL` is the account environment
/// (systemd and PAM set it from the passwd shell). An empty value falls
/// back to that account's passwd shell, then `/bin/sh`.
pub fn account_shell() -> String {
    let from_env = std::env::var("SHELL").ok();
    choose_shell(from_env.as_deref(), passwd_shell(current_uid()).as_deref())
}

pub fn choose_shell(env_shell: Option<&str>, passwd_shell: Option<&str>) -> String {
    for candidate in [env_shell, passwd_shell] {
        if let Some(shell) = candidate.map(str::trim).filter(|shell| !shell.is_empty()) {
            return shell.to_string();
        }
    }
    "/bin/sh".to_string()
}

fn passwd_shell(uid: u32) -> Option<String> {
    #[cfg(unix)]
    {
        let mut buf = vec![0u8; 16 * 1024];
        let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut result = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut pwd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if rc != 0 || result.is_null() {
            return None;
        }
        let shell = unsafe { std::ffi::CStr::from_ptr((*result).pw_shell) };
        shell
            .to_str()
            .ok()
            .map(str::to_string)
            .filter(|shell| !shell.is_empty())
    }
    #[cfg(not(unix))]
    {
        let _ = uid;
        None
    }
}

/// Byte budget for one data-stream subscriber's queued output. Past
/// the soft budget the subscriber counts as behind; the reader paces
/// the child only when *every* subscriber is behind, so one slow
/// client never throttles the terminal for the others — the official
/// mux pauses clients individually the same way. Past the hard
/// budget the subscriber is cut: its stream closes 1013 and the
/// client resyncs from a snapshot (the old shared-ring Lagged, but
/// scoped to the one client that actually fell behind).
const OUTPUT_SOFT_BUDGET: usize = 2 * 1024 * 1024;
const OUTPUT_HARD_BUDGET: usize = 8 * 1024 * 1024;
/// Message-count bound per subscriber queue. The byte budget is the
/// real limit; this only caps pathological tiny-chunk counts.
const OUTPUT_QUEUE_MESSAGES: usize = 1024;

/// How long a terminal may stay quiet before its scrollback is
/// packed (see vt::Screen::suspend_scrollback). Overridable for
/// tests and operations.
fn idle_suspend_after() -> std::time::Duration {
    static AFTER: std::sync::OnceLock<std::time::Duration> = std::sync::OnceLock::new();
    *AFTER.get_or_init(|| {
        std::env::var("RUX_IDLE_SUSPEND_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(std::time::Duration::from_secs)
            .unwrap_or(std::time::Duration::from_secs(60))
    })
}

struct OutputSubscriber {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    queued_bytes: Arc<AtomicUsize>,
    cut: Arc<AtomicBool>,
}

/// One data stream's subscription to a terminal's output: its own
/// queue, its queued-byte counter (the stream decrements it as it
/// drains), and a flag the terminal sets when it cuts the stream for
/// falling past the hard budget.
pub struct OutputSubscription {
    pub id: u64,
    pub rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    pub queued_bytes: Arc<AtomicUsize>,
    pub cut: Arc<AtomicBool>,
}

impl OutputSubscription {
    /// Note that `n` queued bytes were taken by the stream, keeping
    /// the terminal's per-subscriber accounting exact.
    pub fn drained(&self, n: usize) {
        self.queued_bytes.fetch_sub(n, Ordering::SeqCst);
    }
}

pub struct Terminal {
    master: Mutex<Box<dyn MasterPty + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
    output_subscribers: Mutex<Vec<(u64, OutputSubscriber)>>,
    next_output_subscriber: AtomicU64,
    pub events: tokio::sync::broadcast::Sender<Value>,
    pub screen: Mutex<Screen>,
    cols: AtomicU16,
    rows: AtomicU16,
    pub exit_code: Mutex<Option<i32>>,
    /// Fired once when exit_code is recorded, so data streams can close
    /// promptly instead of waiting for their next poll tick.
    pub exit_notify: tokio::sync::Notify,
    pub pid: Option<u32>,
    initial_cwd: String,
    home: String,
    program_path: String,
    program_name: String,
    user_id: u32,
    user_name: String,
    process_generation: AtomicU64,
    last_foreground: Mutex<Option<Value>>,
    blobs: Mutex<HashMap<u64, (String, Instant)>>,
    next_blob_id: AtomicU64,
    /// Fingerprint and arrival time of the last wheel/mouse input
    /// event, for dropping duplicate copies (see `accept_input_event`).
    last_input_event: Mutex<Option<(u64, Instant)>>,
    /// When the last motion report was forwarded (see `accept_motion`).
    last_motion_at: Mutex<Option<Instant>>,
    /// The client that most recently claimed the geometry, and when
    /// (see `resize_from`).
    resize_claim: Mutex<Option<(Instant, String)>>,
}

/// How long a resize claim holds against competing clients. Long
/// enough to absorb the burst when two attached clients both push
/// their geometry at once, short enough that a deliberate resize
/// from another client a moment later still lands.
const RESIZE_CLAIM_WINDOW: std::time::Duration = std::time::Duration::from_millis(250);

impl Terminal {
    pub fn spawn(
        opts: TerminalOptions,
        on_exit: impl Fn(i32, Option<String>) + Send + 'static,
    ) -> anyhow::Result<Arc<Self>> {
        let pty_system = native_pty_system();
        let pair = pty_system.openpty(PtySize {
            rows: opts.rows,
            cols: opts.cols,
            pixel_width: 0,
            pixel_height: 0,
        })?;

        let executable = opts
            .command
            .as_ref()
            .and_then(|argv| argv.first())
            .cloned()
            .or_else(|| opts.shell.clone())
            .unwrap_or_else(account_shell);
        let mut cmd = CommandBuilder::new(executable.clone());
        if let Some(argv) = &opts.command {
            for a in argv.iter().skip(1) {
                cmd.arg(a);
            }
        }
        if let Some(cwd) = &opts.cwd {
            cmd.cwd(cwd);
        } else if let Some(home) = std::env::var_os("HOME") {
            cmd.cwd(home);
        }
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        // The official server reports TERM_PROGRAM lowercase with its
        // version, and tells children where the server binary lives.
        // REX_SESSION / REX_BLOCK / REX_SERVER arrive via TerminalOptions
        // (set by block creation) and are applied after these defaults.
        cmd.env("TERM_PROGRAM", "rex");
        cmd.env("TERM_PROGRAM_VERSION", crate::state::rex_version());
        if let Some(dir) = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|p| p.to_string_lossy().into_owned()))
        {
            cmd.env("REX_BIN_DIR", dir);
        }
        cmd.env("REX", "1");
        for (k, v) in &opts.env {
            cmd.env(k, v);
        }

        let initial_cwd = opts
            .cwd
            .clone()
            .or_else(|| std::env::var("HOME").ok())
            .unwrap_or_default();
        let home = std::env::var("HOME").unwrap_or_default();
        let resolved_program = resolve_executable(&executable);
        let program_name = std::path::Path::new(&resolved_program)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&executable)
            .to_string();
        let user_name = std::env::var("USER").unwrap_or_default();
        let child = pair.slave.spawn_command(cmd)?;
        let pid = child.process_id();
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader()?;
        let writer = pair.master.take_writer()?;
        // The reader thread polls this fd to coalesce output (below). It
        // is the same PTY master the cloned reader reads from.
        #[cfg(unix)]
        let master_fd = pair.master.as_raw_fd();
        #[cfg(not(unix))]
        let master_fd: Option<i32> = None;
        let (event_tx, _) = tokio::sync::broadcast::channel(128);

        let term = Arc::new(Terminal {
            master: Mutex::new(pair.master),
            writer: Mutex::new(writer),
            output_subscribers: Mutex::new(Vec::new()),
            next_output_subscriber: AtomicU64::new(1),
            events: event_tx,
            screen: Mutex::new(Screen::new(opts.cols, opts.rows)),
            cols: AtomicU16::new(opts.cols),
            rows: AtomicU16::new(opts.rows),
            exit_code: Mutex::new(None),
            exit_notify: tokio::sync::Notify::new(),
            pid,
            initial_cwd,
            home,
            program_path: resolved_program,
            program_name,
            user_id: current_uid(),
            user_name,
            process_generation: AtomicU64::new(0),
            last_foreground: Mutex::new(None),
            blobs: Mutex::new(HashMap::new()),
            next_blob_id: AtomicU64::new(1),
            last_input_event: Mutex::new(None),
            last_motion_at: Mutex::new(None),
            resize_claim: Mutex::new(None),
        });

        if let Some(input) = opts.initial_input {
            term.write(input.as_bytes());
        }

        let term2 = term.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 65536];
            let mut last_output = Instant::now();
            let mut idle_packed = false;
            loop {
                // Idle suspension: wait on poll() with a deadline
                // instead of a bare blocking read, so a terminal that
                // goes quiet can pack its scrollback. The official
                // server's idle lifecycle also parks the reader; a
                // blocked poll is already parked, so the wait itself
                // is the parking. Output wakes the poll at once, so
                // latency is unchanged, and once packed the wait has
                // no deadline until the next chunk resets the clock.
                #[cfg(unix)]
                if let Some(fd) = master_fd {
                    let after = idle_suspend_after();
                    let wait_ms: i32 = if idle_packed {
                        -1
                    } else {
                        let elapsed = last_output.elapsed();
                        if elapsed >= after {
                            0
                        } else {
                            (after - elapsed).as_millis() as i32 + 1
                        }
                    };
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    if unsafe { libc::poll(&mut pfd, 1, wait_ms) } == 0 {
                        if last_output.elapsed() >= after {
                            let mut screen = term2.screen.lock().unwrap();
                            if let Some(packed) = screen.suspend_scrollback() {
                                tracing::info!(
                                    lines = screen.scrollback_len(),
                                    packed_bytes = packed,
                                    "idle terminal: scrollback packed"
                                );
                            }
                            idle_packed = true;
                        }
                        continue;
                    }
                    // Data, hangup, or an error: fall through to the
                    // read, which surfaces all three as before.
                }
                let first = match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                // Coalesce before publishing. The blocking read returns
                // as soon as any data is ready, so a fast child otherwise
                // produces thousands of small chunks, and every chunk
                // costs a screen lock, a broadcast and one socket frame
                // per subscriber. Gather whatever else is already
                // sitting in the PTY buffer: poll() with a zero timeout
                // only takes bytes that are ready now, so interactive
                // traffic (nothing more ready) is published immediately
                // and echo latency is unchanged, while a flood leaves
                // as a handful of 64 KiB chunks.
                let mut chunk = Vec::with_capacity(65536);
                chunk.extend_from_slice(&buf[..first]);
                let mut eof = false;
                #[cfg(unix)]
                if let Some(fd) = master_fd {
                    while chunk.len() < 65536 {
                        let mut pfd = libc::pollfd {
                            fd,
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        let ready = unsafe { libc::poll(&mut pfd, 1, 0) };
                        if ready <= 0 || pfd.revents & libc::POLLIN == 0 {
                            break;
                        }
                        match reader.read(&mut buf) {
                            Ok(0) => {
                                eof = true;
                                break;
                            }
                            Ok(n) => chunk.extend_from_slice(&buf[..n]),
                            Err(_) => {
                                eof = true;
                                break;
                            }
                        }
                    }
                }
                last_output = Instant::now();
                idle_packed = false;
                // Pace a flood only when every subscriber is behind
                // its soft budget: production slows to the streams'
                // collective drain rate instead of buffering without
                // bound or cutting streams that are merely slower
                // than the child. A subscriber that falls behind
                // alone is not paced for — if it reaches the hard
                // budget it is cut individually in publish_output
                // and resyncs, while the others keep flowing. The
                // wait is capped so stalled consumers cannot freeze
                // the terminal for long; past the cap the hard
                // budget is the backstop.
                if term2.output_all_behind() {
                    let mut waited_ms = 0;
                    while term2.output_all_behind() && waited_ms < 100 {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                        waited_ms += 2;
                    }
                }
                let (responses, status_events) = {
                    let mut screen = term2.screen.lock().unwrap();
                    screen.feed(&chunk);
                    let responses = screen.take_responses();
                    let status_events = screen.take_status_events();
                    // Publish while holding the screen lock. A data
                    // subscriber takes the same lock before snapshot +
                    // subscribe, so it cannot miss or duplicate the
                    // bytes represented by its initial snapshot.
                    term2.publish_output(chunk);
                    (responses, status_events)
                };
                if !responses.is_empty() {
                    term2.write(&responses);
                }
                for (name, payload) in status_events {
                    let payload = decorate_owner(&term2, &name, payload);
                    let _ = term2
                        .events
                        .send(json!({ "name": name, "payload": payload }));
                }
                if eof {
                    break;
                }
            }
            let mut child = child;
            let code = child.wait().map(|s| s.exit_code() as i32).unwrap_or(-1);
            *term2.exit_code.lock().unwrap() = Some(code);
            term2.exit_notify.notify_waiters();
            let events = {
                let mut screen = term2.screen.lock().unwrap();
                screen.clear_transient_program_status("child_exited");
                screen.take_status_events()
            };
            for (name, payload) in events {
                let payload = decorate_owner(&term2, &name, payload);
                let _ = term2
                    .events
                    .send(json!({ "name": name, "payload": payload }));
            }
            on_exit(code, None);
        });

        Ok(term)
    }

    /// Whether to forward a wheel/mouse input event. The Rex app
    /// currently delivers every input event twice (it arrives over two
    /// control connections a few hundred microseconds apart), and
    /// forwarding both copies doubles the program's input queue and
    /// its redraws, which reads as scroll lag. An event identical to
    /// the previous one inside 3 ms is treated as that duplicate.
    pub fn accept_input_event(&self, fingerprint: u64) -> bool {
        let now = Instant::now();
        let mut last = self.last_input_event.lock().unwrap();
        let duplicate = matches!(
            *last,
            Some((fp, at)) if fp == fingerprint
                && now.duration_since(at) < std::time::Duration::from_millis(3)
        );
        if !duplicate {
            *last = Some((fingerprint, now));
        }
        !duplicate
    }

    /// Whether a motion report may be forwarded: at most one per
    /// 16 ms. The client's raw motion stream runs at ~100 Hz, far
    /// faster than a program can usefully consume positions.
    pub fn accept_motion(&self) -> bool {
        let now = Instant::now();
        let mut last = self.last_motion_at.lock().unwrap();
        if matches!(
            *last,
            Some(at) if now.duration_since(at) < std::time::Duration::from_millis(16)
        ) {
            return false;
        }
        *last = Some(now);
        true
    }

    pub fn write(&self, data: &[u8]) -> usize {
        let mut w = self.writer.lock().unwrap();
        match w.write_all(data) {
            Ok(()) => {
                let _ = w.flush();
                data.len()
            }
            Err(_) => 0,
        }
    }

    pub fn resize(&self, cols: u16, rows: u16) {
        self.resize_from(cols, rows, None);
    }

    /// Resize with arbitration between attached clients, mirroring
    /// the official mux's pending-resize owner. The first resize in
    /// a burst claims the geometry for RESIZE_CLAIM_WINDOW; a
    /// competing resize from a different client inside the window
    /// is dropped (returns false) instead of flip-flopping the size
    /// back and forth, while the claimant's own resizes always apply
    /// (a drag in progress keeps refreshing its claim). Ownerless
    /// resizes (internal actions) always apply and clear the claim.
    /// A dropped caller learns the true size from the next snapshot
    /// or resized event, as before.
    pub fn resize_from(&self, cols: u16, rows: u16, owner: Option<&str>) -> bool {
        match owner {
            Some(owner) => {
                let mut claim = self.resize_claim.lock().unwrap();
                let now = Instant::now();
                if let Some((when, holder)) = &*claim
                    && holder != owner
                    && now.duration_since(*when) < RESIZE_CLAIM_WINDOW
                {
                    return false;
                }
                *claim = Some((now, owner.to_string()));
            }
            None => {
                *self.resize_claim.lock().unwrap() = None;
            }
        }
        self.apply_resize(cols, rows);
        true
    }

    fn apply_resize(&self, cols: u16, rows: u16) {
        self.cols.store(cols, Ordering::SeqCst);
        self.rows.store(rows, Ordering::SeqCst);
        self.screen.lock().unwrap().resize(cols, rows);
        let master = self.master.lock().unwrap();
        let _ = master.resize(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        });
        // Data streams re-push a snapshot on this event: a connected client
        // renders from the snapshot it received at connect time, so without
        // a refresh it keeps drawing the old geometry (e.g. a 24-row pane
        // stranded in the top half of a 50-row window) until it reconnects.
        let _ = self.events.send(json!({
            "name": "resized",
            "payload": { "columns": cols, "rows": rows },
        }));
    }

    /// The resize APC for a connected data stream, in the same shape the
    /// bootstrap sends, carrying the terminal's current size.
    pub fn resize_message(&self, nonce: u64, owner: Option<&str>) -> Vec<u8> {
        self.screen
            .lock()
            .unwrap()
            .initial_resize_message(nonce, owner)
    }

    pub fn size(&self) -> (u16, u16) {
        (
            self.cols.load(Ordering::SeqCst),
            self.rows.load(Ordering::SeqCst),
        )
    }

    pub fn title(&self) -> String {
        self.screen.lock().unwrap().title().to_string()
    }

    pub fn pwd(&self) -> String {
        self.screen.lock().unwrap().pwd().to_string()
    }

    pub fn program_status_records(&self) -> Vec<Value> {
        self.screen.lock().unwrap().program_status_records()
    }

    pub fn set_theme(&self, options: &Value) -> Result<(), String> {
        self.screen.lock().unwrap().set_theme(options)
    }

    /// Register a data-stream subscriber with its own output queue.
    /// The caller must hold the screen lock (data_bootstrap does), so
    /// no output is missed or duplicated relative to the snapshot:
    /// the reader publishes under the same lock.
    fn subscribe_output_locked(&self) -> OutputSubscription {
        let (tx, rx) = tokio::sync::mpsc::channel(OUTPUT_QUEUE_MESSAGES);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let cut = Arc::new(AtomicBool::new(false));
        let id = self.next_output_subscriber.fetch_add(1, Ordering::SeqCst);
        self.output_subscribers.lock().unwrap().push((
            id,
            OutputSubscriber {
                tx,
                queued_bytes: queued_bytes.clone(),
                cut: cut.clone(),
            },
        ));
        OutputSubscription {
            id,
            rx,
            queued_bytes,
            cut,
        }
    }

    pub fn subscribe_output(&self) -> OutputSubscription {
        let _screen = self.screen.lock().unwrap();
        self.subscribe_output_locked()
    }

    pub fn unsubscribe_output(&self, id: u64) {
        self.output_subscribers
            .lock()
            .unwrap()
            .retain(|(sid, _)| *sid != id);
    }

    /// Whether output production should slow down: at least one
    /// subscriber exists and every one of them is past the soft
    /// budget. A single laggard among healthy subscribers returns
    /// false — it will be cut on its own if it reaches the hard
    /// budget, without throttling anyone else.
    fn output_all_behind(&self) -> bool {
        let subs = self.output_subscribers.lock().unwrap();
        !subs.is_empty()
            && subs
                .iter()
                .all(|(_, sub)| sub.queued_bytes.load(Ordering::SeqCst) >= OUTPUT_SOFT_BUDGET)
    }

    /// Fan one coalesced chunk out to every subscriber. Called by
    /// the reader thread while holding the screen lock. A subscriber
    /// past the hard budget (or with a full message queue) is cut:
    /// removing it drops its sender, and its stream sees the closed
    /// queue plus the cut flag and closes 1013 so the client
    /// resyncs — the other subscribers are unaffected.
    fn publish_output(&self, chunk: Vec<u8>) {
        let mut subs = self.output_subscribers.lock().unwrap();
        subs.retain(|(_, sub)| {
            if sub.queued_bytes.load(Ordering::SeqCst) >= OUTPUT_HARD_BUDGET {
                sub.cut.store(true, Ordering::SeqCst);
                return false;
            }
            match sub.tx.try_send(chunk.clone()) {
                Ok(()) => {
                    sub.queued_bytes
                        .fetch_add(chunk.len(), Ordering::SeqCst);
                    true
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    sub.cut.store(true, Ordering::SeqCst);
                    false
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
            }
        });
    }

    pub fn data_bootstrap(
        &self,
        nonce: u64,
        owner: Option<&str>,
    ) -> (
        Vec<u8>,
        OutputSubscription,
        tokio::sync::broadcast::Receiver<Value>,
    ) {
        let screen = self.screen.lock().unwrap();
        let output = self.subscribe_output_locked();
        let events = self.events.subscribe();
        let mut bootstrap = screen.ghostty_snapshot();
        bootstrap.extend(screen.initial_resize_message(nonce, owner));
        if let Some(theme) = screen.initial_theme_message(nonce) {
            bootstrap.extend(theme);
        }
        (bootstrap, output, events)
    }

    fn child_process_info(&self) -> Option<Value> {
        self.pid.map(|pid| {
            json!({
                "pid": pid,
                "user_id": self.user_id,
                "user": self.user_name,
                "name": self.program_name,
                "path": self.program_path,
                "argv0": self.program_name,
                "cwd": self.initial_cwd,
            })
        })
    }

    pub fn input_mode(&self) -> Value {
        #[cfg(unix)]
        {
            if let Some(fd) = self.master.lock().unwrap().as_raw_fd()
                && let Some(mode) = lflag_mode(fd)
            {
                return mode;
            }
        }
        json!({ "echo": true, "canonical": true, "signals": true })
    }

    fn foreground_pid(&self) -> Option<u32> {
        #[cfg(unix)]
        {
            unsafe extern "C" {
                fn tcgetpgrp(fd: i32) -> i32;
            }
            let fd = self.master.lock().unwrap().as_raw_fd()?;
            let pid = unsafe { tcgetpgrp(fd) };
            if pid > 0 { Some(pid as u32) } else { None }
        }
        #[cfg(not(unix))]
        {
            self.pid
        }
    }

    fn process_info_for_pid(&self, pid: u32) -> Option<Value> {
        let output = Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "uid=,comm="])
            .output()
            .ok()?;
        if !output.status.success() {
            return (self.pid == Some(pid))
                .then(|| self.child_process_info())
                .flatten();
        }
        let line = String::from_utf8_lossy(&output.stdout);
        let Some((uid, command)) = line.trim().split_once(char::is_whitespace) else {
            return (self.pid == Some(pid))
                .then(|| self.child_process_info())
                .flatten();
        };
        let Some(uid) = uid.trim().parse::<u32>().ok() else {
            return (self.pid == Some(pid))
                .then(|| self.child_process_info())
                .flatten();
        };
        let command = command.trim();
        if command.is_empty() {
            return None;
        }
        let path = std::path::Path::new(command);
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(command);
        let mut process = json!({
            "pid": pid,
            "user_id": uid,
            "name": name,
            "cwd": self.cwd(),
        });
        if path.is_absolute() {
            process["path"] = json!(command);
            process["argv0"] = json!(name);
        }
        if uid == self.user_id && !self.user_name.is_empty() {
            process["user"] = json!(self.user_name);
        }
        Some(process)
    }

    fn foreground_process_info(&self) -> Option<Value> {
        if self.exit_code.lock().unwrap().is_some() {
            return None;
        }
        self.foreground_pid()
            .and_then(|pid| self.process_info_for_pid(pid))
            .or_else(|| self.child_process_info())
    }

    pub fn emit_process_changed(&self, force: bool) {
        let foreground = self.foreground_process_info();
        let ancestors = self.ancestors_of_foreground();
        let generation = {
            let mut previous = self.last_foreground.lock().unwrap();
            if !force && *previous == foreground {
                return;
            }
            *previous = foreground.clone();
            self.process_generation.fetch_add(1, Ordering::SeqCst) + 1
        };
        let _ = self.events.send(json!({
            "name": "process_changed",
            "payload": {
                "generation": generation,
                "foreground": foreground,
                "ancestors": ancestors,
            },
        }));
    }

    pub fn event_owner(&self) -> Option<Value> {
        let info = self.foreground_process_info()?;
        Some(json!({
            "pid": info.get("pid")?.clone(),
            "name": info.get("name")?.clone(),
        }))
    }

    fn ancestors_of_foreground(&self) -> Vec<Value> {
        let Some(pid) = self.foreground_pid().or(self.pid) else {
            return Vec::new();
        };
        process_ancestors(pid, self.pid)
    }

    /// True once the block's child process has exited (its exit code has
    /// been recorded). Lets callers sweep panes whose process ended before
    /// an app client took ownership of them.
    pub fn has_exited(&self) -> bool {
        self.exit_code.lock().unwrap().is_some()
    }

    pub fn process_info(&self) -> Value {
        let exit_code = *self.exit_code.lock().unwrap();
        let child = if exit_code.is_none() {
            self.child_process_info()
        } else {
            None
        };
        let foreground = if exit_code.is_none() {
            self.foreground_process_info()
        } else {
            None
        };
        let last_exit = exit_code.map(|code| {
            if code == 0 {
                json!({ "exit_code": code })
            } else {
                json!({ "exit_code": code, "error": format!("exit status {code}") })
            }
        });
        let ancestors = if exit_code.is_none() {
            Value::Array(self.ancestors_of_foreground())
        } else {
            Value::Null
        };
        json!({
            "last_exit": last_exit,
            "child": child,
            "foreground": foreground,
            "ancestors": ancestors,
            "home": self.home,
        })
    }

    pub fn clipboard_copy(&self, id: u64) -> Option<(u64, String)> {
        self.screen.lock().unwrap().clipboard_copy(id)
    }

    pub fn cwd(&self) -> String {
        let reported = self.pwd();
        let path = file_url_path(&reported).unwrap_or(reported);
        if !path.is_empty() {
            path
        } else {
            self.initial_cwd.clone()
        }
    }

    pub fn store_blob(&self, data: String) -> u64 {
        let id = self.next_blob_id.fetch_add(1, Ordering::SeqCst).max(1);
        let mut blobs = self.blobs.lock().unwrap();
        let now = Instant::now();
        blobs.retain(|_, (_, expires)| *expires > now);
        blobs.insert(id, (data, now + Duration::from_secs(300)));
        id
    }

    pub fn blob(&self, id: u64) -> Option<(u64, String)> {
        let mut blobs = self.blobs.lock().unwrap();
        let now = Instant::now();
        blobs.retain(|_, (_, expires)| *expires > now);
        let id = if id == 0 { *blobs.keys().max()? } else { id };
        blobs.get(&id).map(|(data, _)| (id, data.clone()))
    }

    pub fn clear_screen(&self) {
        self.screen.lock().unwrap().clear();
    }

    pub fn reset_screen(&self) {
        let events = {
            let mut screen = self.screen.lock().unwrap();
            screen.reset();
            screen.take_status_events()
        };
        self.emit_screen_events(events);
    }

    fn emit_screen_events(&self, events: Vec<(String, Value)>) {
        for (name, payload) in events {
            let payload = decorate_owner(self, &name, payload);
            let _ = self
                .events
                .send(json!({ "name": name, "payload": payload }));
        }
    }

    /// Ask the child process to hang up.
    pub fn close(&self) {
        if let Some(pid) = self.pid {
            unsafe extern "C" {
                fn kill(pid: i32, sig: i32) -> i32;
            }
            unsafe {
                kill(pid as i32, 1);
            }
        }
    }
}

fn decorate_owner(term: &Terminal, name: &str, mut payload: Value) -> Value {
    if matches!(name, "title_changed" | "pwd_changed")
        && let Some(owner) = term.event_owner()
        && let Some(object) = payload.as_object_mut()
    {
        object.insert("owner".into(), owner);
    }
    payload
}

fn file_url_path(pwd: &str) -> Option<String> {
    let rest = pwd.strip_prefix("file://")?;
    Some(
        rest.find('/')
            .map(|index| rest[index..].to_string())
            .unwrap_or_else(|| "/".to_string()),
    )
}

/// Ancestors of `foreground_pid`, starting at its parent and stopping at pid 1
/// or `stop_at` (the terminal's own child), inclusive, capped at 32.
fn process_ancestors(foreground_pid: u32, stop_at: Option<u32>) -> Vec<Value> {
    let Some(mut pid) = proc_ppid(foreground_pid) else {
        return Vec::new();
    };
    let mut ancestors = Vec::new();
    for _ in 0..32 {
        if pid == 0 {
            break;
        }
        ancestors.push(proc_snapshot(pid).unwrap_or_else(|| {
            json!({
                "pid": pid,
                "user_id": 0,
                "name": "",
            })
        }));
        if pid == 1 || Some(pid) == stop_at {
            break;
        }
        let Some(parent) = proc_ppid(pid) else {
            break;
        };
        if parent == pid {
            break;
        }
        pid = parent;
    }
    ancestors
}

#[cfg(unix)]
pub(crate) fn lflag_mode(fd: i32) -> Option<Value> {
    unsafe {
        let mut termios = std::mem::zeroed::<libc::termios>();
        if libc::tcgetattr(fd, &mut termios) != 0 {
            return None;
        }
        let flags = termios.c_lflag;
        Some(json!({
            "echo": flags & libc::ECHO != 0,
            "canonical": flags & libc::ICANON != 0,
            "signals": flags & libc::ISIG != 0,
        }))
    }
}

fn proc_ppid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.rsplit_once(')')?.1.trim_start();
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse().ok()
}

fn proc_snapshot(pid: u32) -> Option<Value> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let name = stat.split_once('(')?.1.rsplit_once(')')?.0;
    let user_id = proc_uid(pid).unwrap_or(0);
    let mut process = json!({
        "pid": pid,
        "user_id": user_id,
        "name": name,
    });
    if let Ok(cwd) = std::fs::read_link(format!("/proc/{pid}/cwd"))
        && let Some(cwd) = cwd.to_str()
    {
        process["cwd"] = json!(cwd);
    }
    if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe"))
        && let Some(path) = exe.to_str()
    {
        process["path"] = json!(path);
        if let Some(argv0) = exe.file_name().and_then(|file| file.to_str()) {
            process["argv0"] = json!(argv0);
        }
    }
    Some(process)
}

fn proc_uid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_prefers_the_environment_then_the_passwd_shell() {
        assert_eq!(
            choose_shell(Some("/bin/bash"), Some("/bin/zsh")),
            "/bin/bash"
        );
        assert_eq!(choose_shell(Some("  "), Some("/bin/zsh")), "/bin/zsh");
        assert_eq!(choose_shell(None, None), "/bin/sh");
        assert_eq!(choose_shell(Some(""), Some("")), "/bin/sh");
        let shell = passwd_shell(current_uid()).expect("passwd shell");
        assert!(shell.starts_with('/'), "{shell}");
    }

    #[test]
    #[test]
    fn fast_exiting_child_output_is_not_lost() {
        // Delivery contract: a child that floods the PTY and exits
        // at once must still deliver every byte to a subscriber that
        // keeps draining. Over the data channel this used to fail
        // under load: thousands of small chunks overflowed a shared
        // broadcast ring faster than the stream task drained it, the
        // receiver lagged, and the stream closed (1013) with most of
        // the output undelivered. The fan-out is now a per-subscriber
        // queue with byte budgets: this subscriber drains in bursts,
        // stays far under its hard budget, and the reader paces only
        // when every subscriber is behind, so a consumer that keeps
        // making progress receives every byte. (The quiet unit-test
        // environment does not reproduce the original contention;
        // the delivery path is what this test exercises end to end.)
        // Digits plus the PTY's ONLCR translation (\n -> \r\n).
        let expected: usize = (1..=200_000u32).map(|n| n.to_string().len() + 2).sum();
        let term = Terminal::spawn(
            TerminalOptions {
                command: Some(vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "sleep 0.3; seq 1 200000".into(),
                ]),
                ..TerminalOptions::default()
            },
            |_, _| {},
        )
        .unwrap();
        let mut output = term.subscribe_output();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let collector = std::thread::spawn(move || {
            let mut total = 0usize;
            let mut tail: Vec<u8> = Vec::new();
            let mut chunks = 0usize;
            while let Some(chunk) = output.rx.blocking_recv() {
                output.drained(chunk.len());
                total += chunk.len();
                tail.extend_from_slice(&chunk);
                if tail.len() > 4096 {
                    tail.drain(..tail.len() - 4096);
                }
                chunks += 1;
                // Drain in bursts, like the async stream task that
                // also waits on socket sends: the pause between
                // bursts is what used to overflow the ring.
                if chunks % 16 == 0 {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            let _ = done_tx.send((total, tail));
        });
        let deadline = Instant::now() + Duration::from_secs(20);
        while term.exit_code.lock().unwrap().is_none() {
            assert!(Instant::now() < deadline, "child never exited");
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(term);
        let (total, tail) = done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("collector finished");
        collector.join().unwrap();
        assert_eq!(total, expected, "output bytes were lost");
        assert!(
            tail.ends_with(b"200000\r\n"),
            "tail ends with {:?}",
            String::from_utf8_lossy(&tail[tail.len().saturating_sub(32)..])
        );
    }

    #[test]
    fn resize_claims_arbitrate_between_clients() {
        let term = Terminal::spawn(
            TerminalOptions {
                command: Some(vec!["/bin/sh".into(), "-c".into(), "sleep 3".into()]),
                ..TerminalOptions::default()
            },
            |_, _| {},
        )
        .unwrap();
        // First resize claims the geometry.
        assert!(term.resize_from(100, 40, Some("client-a")));
        assert_eq!(term.size(), (100, 40));
        // A competing client inside the window is dropped.
        assert!(!term.resize_from(120, 50, Some("client-b")));
        assert_eq!(term.size(), (100, 40));
        // The claimant's own resizes keep applying (a drag).
        assert!(term.resize_from(110, 44, Some("client-a")));
        assert_eq!(term.size(), (110, 44));
        // An ownerless resize always applies and clears the claim,
        // so the other client can resize right after.
        assert!(term.resize_from(90, 30, None));
        assert!(term.resize_from(120, 50, Some("client-b")));
        assert_eq!(term.size(), (120, 50));
        // After the window lapses the claim expires on its own.
        std::thread::sleep(Duration::from_millis(300));
        assert!(term.resize_from(80, 24, Some("client-a")));
        assert_eq!(term.size(), (80, 24));
    }

    #[test]
    fn a_stalled_subscriber_is_cut_without_starving_others() {
        use std::sync::atomic::Ordering as Ord;
        // Per-client queues: a subscriber that never drains is cut at
        // its hard budget, while a subscriber that keeps draining
        // receives everything. Production pacing needs *every*
        // subscriber behind, so the laggard never throttles the
        // healthy one (publish_output itself never blocks, either).
        let term = Terminal::spawn(
            TerminalOptions {
                command: Some(vec!["/bin/sh".into(), "-c".into(), "sleep 3".into()]),
                ..TerminalOptions::default()
            },
            |_, _| {},
        )
        .unwrap();
        let mut fast = term.subscribe_output();
        let fast_cut = fast.cut.clone();
        let received = std::sync::Arc::new(AtomicUsize::new(0));
        let received2 = received.clone();
        let drainer = std::thread::spawn(move || {
            while let Some(chunk) = fast.rx.blocking_recv() {
                fast.drained(chunk.len());
                received2.fetch_add(chunk.len(), Ord::SeqCst);
            }
        });
        let mut slow = term.subscribe_output();
        // 9 MiB in 64 KiB chunks, published directly; the sleeping
        // child produces nothing of its own.
        let chunk = vec![7u8; 65536];
        for _ in 0..144 {
            term.publish_output(chunk.clone());
        }
        // The stalled subscriber was cut at exactly the hard budget:
        // the flag is set, its queued bytes remain readable, and then
        // the channel is closed.
        assert!(slow.cut.load(Ord::SeqCst), "stalled subscriber not cut");
        let mut slow_total = 0usize;
        while let Some(c) = slow.rx.blocking_recv() {
            slow_total += c.len();
        }
        assert_eq!(slow_total, OUTPUT_HARD_BUDGET);
        // The healthy subscriber was not cut and received everything.
        assert!(!fast_cut.load(Ord::SeqCst), "healthy subscriber was cut");
        let deadline = Instant::now() + Duration::from_secs(10);
        while received.load(Ord::SeqCst) < 144 * 65536 {
            assert!(Instant::now() < deadline, "healthy subscriber starved");
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(term);
        let _ = drainer.join();
    }

    #[test]
    fn terminal_child_runs_as_this_user() {
        let dir = std::env::temp_dir().join(format!(
            "rux-term-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("id");
        let script = format!("id -u > '{}'", marker.display());
        let term = Terminal::spawn(
            TerminalOptions {
                command: Some(vec!["/bin/sh".into(), "-c".into(), script]),
                ..TerminalOptions::default()
            },
            |_, _| {},
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && !marker.exists() {
            std::thread::sleep(Duration::from_millis(20));
        }
        let text = std::fs::read_to_string(&marker).unwrap_or_default();
        assert_eq!(text.trim(), current_uid().to_string(), "marker {text:?}");
        drop(term);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn terminal_child_env_matches_official_context() {
        // The official server tells terminal children where they live:
        // TERM_PROGRAM is lowercase "rex" with a version, and REX_BIN_DIR
        // points at the server binary's directory. REX_SESSION / REX_BLOCK /
        // REX_SERVER are layered in by block creation (api.rs) through
        // TerminalOptions.env, which spawn applies after these defaults.
        let dir = std::env::temp_dir().join(format!(
            "rux-term-env-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("env");
        let script = format!("env > '{}'", marker.display());
        let term = Terminal::spawn(
            TerminalOptions {
                command: Some(vec!["/bin/sh".into(), "-c".into(), script]),
                env: vec![("REX_SESSION".into(), "session:test".into())],
                ..TerminalOptions::default()
            },
            |_, _| {},
        )
        .unwrap();
        // Poll the contents, not just existence: the shell creates the
        // marker before env's output lands in it.
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut text = String::new();
        while Instant::now() < deadline {
            text = std::fs::read_to_string(&marker).unwrap_or_default();
            if text.contains("REX_SESSION=session:test") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(text.contains("TERM_PROGRAM=rex\n"), "env {text:?}");
        assert!(
            text.contains(&format!(
                "TERM_PROGRAM_VERSION={}\n",
                crate::state::rex_version()
            )),
            "env {text:?}"
        );
        assert!(text.contains("REX_BIN_DIR="), "env {text:?}");
        assert!(text.contains("REX_SESSION=session:test\n"), "env {text:?}");
        drop(term);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ancestors_start_at_the_parent_and_include_the_stop_pid() {
        let me = std::process::id();
        let parent = proc_ppid(me).expect("ppid");
        let chain = process_ancestors(me, Some(parent));
        assert_eq!(chain[0]["pid"], parent);
        assert_eq!(chain.len(), 1);
        assert!(chain[0]["name"].is_string());
        assert!(chain[0].get("user_id").is_some());
    }

    #[test]
    fn input_mode_reads_the_pty_termios() {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("pty");
        let fd = pair.master.as_raw_fd().expect("fd");
        let mode = lflag_mode(fd).expect("termios");
        assert_eq!(mode["echo"], true);
        assert_eq!(mode["canonical"], true);
        assert_eq!(mode["signals"], true);
        unsafe {
            let mut termios = std::mem::zeroed::<libc::termios>();
            assert_eq!(libc::tcgetattr(fd, &mut termios), 0);
            termios.c_lflag &= !(libc::ECHO | libc::ICANON);
            assert_eq!(libc::tcsetattr(fd, libc::TCSANOW, &termios), 0);
        }
        let mode = lflag_mode(fd).expect("termios");
        assert_eq!(mode["echo"], false);
        assert_eq!(mode["canonical"], false);
        assert_eq!(mode["signals"], true);
    }

    #[test]
    fn file_urls_reduce_to_the_path_used_as_cwd() {
        assert_eq!(
            file_url_path("file://host.example/tmp/work").as_deref(),
            Some("/tmp/work")
        );
    }
}

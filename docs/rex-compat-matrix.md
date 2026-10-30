# Rex public-docs compatibility matrix

Audit date: 2026-10-25. Rows are updated as the handlers change.

Sources:

- [llms.txt](https://www.superlogical.com/rex/docs/llms.txt) and [llms-full.txt](https://www.superlogical.com/rex/docs/llms-full.txt)
- [search.json](https://www.superlogical.com/rex/docs/search.json)
- [Server API](https://www.superlogical.com/rex/docs/automate/server-api)
- [Lua API](https://www.superlogical.com/rex/docs/reference/lua), [Lua scripts](https://www.superlogical.com/rex/docs/automate/lua-scripts), [Lua events](https://www.superlogical.com/rex/docs/automate/lua-events)
- [Events](https://www.superlogical.com/rex/docs/reference/events)
- [CLI](https://www.superlogical.com/rex/docs/automate/cli) and [shell scripting](https://www.superlogical.com/rex/docs/automate/shell-scripting)
- [Remote access](https://www.superlogical.com/rex/docs/linux/remote-access), [server modes](https://www.superlogical.com/rex/docs/linux/server-modes), [login server](https://www.superlogical.com/rex/docs/linux/login-server)
- [Program status (OSC 7501)](https://www.superlogical.com/rex/docs/build/program-status), revision 0.4 (2026-10-10)

Rux compared: `crates/rux-server` handlers, `crates/rux-server/assets/api-help.json` (what `help.all` and `GET /api/help` return), Lua in `config.rs` and `script.rs`, events in `api.rs` / `state.rs` / `vt.rs` / `terminal.rs`, listeners in `main.rs` and `tailscale.rs`.

## How a row is scored

The public Server API page does not list every method. It says the connected server is the catalog: `rex api list`, `rex api describe`, and `rex api call`, with JSON Schema on each method. Rux serves its own catalog from `assets/api-help.json`, not by reflecting on the handlers. A method is scored against that served schema plus any rule the public page states. `--api-help` can replace the file with a document you supply.

| Status | Meaning |
| --- | --- |
| Implemented | The handler does the documented job, and the result uses the documented names. |
| Partial | A handler exists, and a documented field, rule, or flag differs. The difference is in the notes. |
| Missing | No handler, or the handler returns `not_supported` / an empty stand-in. |
| Not applicable | The docs describe the `rex` CLI or a NixOS module. Rux is a server binary and does not ship those. |

`additionalProperties: false` is enforced on control-method inputs and on block-method `args`. A misspelled argument fails with `bad_request` and a message of the form `input: validating: unexpected property lable`. A missing payload is treated as `{}`.

## Coverage

Percentages use Implemented / all rows in the category. "With partial" counts Implemented and Partial. Not applicable is excluded from the percentage.

| Category | Rows | Implemented | Partial | Missing | Not applicable | Implemented | With partial |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Server methods (`help.all`) | 73 | 73 | 0 | 0 | 0 | 100% | 100% |
| Block methods | 18 | 18 | 0 | 0 | 0 | 100% | 100% |
| Events | 30 | 30 | 0 | 0 | 0 | 100% | 100% |
| Lua API | 32 | 32 | 0 | 0 | 0 | 100% | 100% |
| OSC 7501 | 15 | 14 | 0 | 0 | 1 | 100% | 100% |
| Remote-access listeners and flags | 16 | 15 | 0 | 0 | 1 | 100% | 100% |
| Server modes and login server | 14 | 13 | 1 | 0 | 0 | 93% | 100% |
| CLI commands | 29 | 0 | 0 | 0 | 29 | — | — |

A Rex GUI that opens a session, splits panes, and types into a terminal is on the implemented side of the server-method table. Built-in Tailscale is implemented beside host `tailnet://` and `tailnet-serve://`. The default remote-host install is a personal server: it runs as the invoking login account, and its terminals run as that account. The login server, when it is root, opens a PAM login session before it starts a per-account server. Personal auto-start is still the `rex` CLI, which this binary does not install.

## Catalog

[Server API](https://www.superlogical.com/rex/docs/automate/server-api)

| Item | Status | What differs |
| --- | --- | --- |
| `rex api list` / `describe` / `call` | Not applicable | Those are CLI commands. The server side is `help.all` and `GET /api/help`. |
| Method record fields `name`, `description`, `input_schema`, `output_schema` | Implemented | Present on the served catalog. The file also adds `invoke`, and `local` on local-only methods, which the page does not mention. Descriptions are one line. Per-field description strings are omitted. |
| `request_example`, `response_example`, `validation_notes` | Omitted | Not in the built-in catalog. `output_schema` is present, including on `session.help` and `help.all`. Pass `--api-help` to serve a document that includes examples. |
| Published `session.set_block_label` schema | Implemented | Served schema: `session_id` required, `block_id` string or null, `label` string, `additionalProperties: false`, result `revision` integer minimum 0. |
| Published `server.version` example (`rex_version`, `platform` such as `darwin_arm64`) | Implemented | `platform` uses Go names (`linux_arm64`). `rex_version` is the rux package version with a `-rux` suffix. `commit` and `built_at` are omitted unless the build sets `RUX_COMMIT` / `RUX_BUILT_AT`. `api_revision` and `api_min_revision` are present. |
| Error `code=bad_request` and `code=method_not_found` | Implemented | Unknown method name returns `method_not_found`. Missing required fields return `bad_request` with `input: validating: …`. |
| `additionalProperties: false` rejects typos | Implemented | `{"session_id","block_id","lable":"x"}` fails for `lable`. Block `args` are checked against `args_schema` the same way. |
| Describe output is generated from the running server | Partial | The built-in catalog is generated by `crates/rux-server/catalog/generate.py` from the field schemas and rux's wording, then embedded. Handlers validate against it. It is not produced by reflecting on the Rust functions. A test calls every catalog method and expects a handler. |
| `GET /api/help`, `/api/control`, `/api/data`, `/llms.txt` | Implemented | Paths match the `http` object in the catalog, including `/llms.html`. |

## Server methods

Source: the 73 methods in `help.all`. Link for every row: [Server API](https://www.superlogical.com/rex/docs/automate/server-api). Schemas live in `crates/rux-server/assets/api-help.json`.

### Implemented

These dispatch to real handlers. Inputs are schema-validated.

`help.all`, `server.apple.grant_file_access`, `server.apple.privacy_status`, `server.config_reload`, `server.status`, `server.stop`, `server.tailscale.disable`, `server.tailscale.enable`, `server.tailscale.login`, `server.tailscale.logout`, `server.tailscale.rename`, `server.version`, `server.whoami`, `session.help`, `block.close`, `block.event`, `block.method`, `block_creator.list`, `client.action`, `client.inspect`, `client.key`, `client.keymap`, `client.list`, `client.perform`, `client.reply`, `client.set_label`, `client.set_script`, `data.connect`, `hosts.list`, `hosts.put`, `hosts.remove`, `session.attach`, `session.attach_all`, `session.bootstrap`, `session.close_layer`, `session.close_window`, `session.create`, `session.describe_block`, `session.destroy`, `session.detach`, `session.detach_block`, `session.disown_block`, `session.float_block`, `session.focus_block`, `session.focus_direction`, `session.focus_next_pane`, `session.focus_next_window`, `session.focus_previous_pane`, `session.focus_previous_window`, `session.focus_window`, `session.list`, `session.list_blocks`, `session.list_clients`, `session.lower_layer`, `session.move`, `session.move_block`, `session.move_window`, `session.new_block`, `session.new_layer`, `session.new_split`, `session.new_window`, `session.own_block`, `session.raise_layer`, `session.resize_layer`, `session.resize_pane`, `session.set_block_label`, `session.set_label`, `session.set_window_label`, `session.swap_blocks`, `session.view`, `session.zoom_block`, `target.complete`, `target.resolve`.

`server.apple.privacy_status` reports real services on macOS — full disk access (a probe of the user TCC database), accessibility (`AXIsProcessTrusted`), screen recording (`CGPreflightScreenCaptureAccess`), camera and microphone (AVFoundation authorization status) — plus `responsible_path`. Off macOS the services list is empty, which the contract allows. `server.apple.grant_file_access` reports `readable` for paths that already open; otherwise it consumes a supplied sandbox token (`sandbox_extension_consume`) and re-checks, reporting `granted` when the path opens then. The macOS code paths are compile-checked for `aarch64-apple-darwin` but have not run on a Mac yet. `server.tailscale.enable` is local-only and requires `allow_tailnet_members`. A repeat call only updates that flag. Tags without it, and a hostname that is not 1–63 letters, digits, and hyphens, are `bad_request`. `auth_key` is passed to the sidecar and is not logged or returned. `server.tailscale.login` is `conflict` while Tailscale is off. `server.tailscale.logout` while it is off leaves the saved sign-in alone. `server.tailscale.rename` is `conflict` while it is off, and the returned `dns_name` can still be the previous name. `server.tailscale.disable` closes tailnet clients and keeps the sign-in. `server.status` includes `tailscale` only when `rux-tsnet` is installed. Without that sidecar the five methods return `not_supported`.

`session.list` returns `{"sessions":[{"session_id","label"}]}`, which matches the [CLI](https://www.superlogical.com/rex/docs/automate/cli) `rex ls --json` example. A session created by `session.create` stays in that list after the creating client disconnects, and a block stays after `child_exited`, which is what `rex new --keep-open` needs for a later `rex ls` or `rex capture`. `target.resolve` matches Rex's order and stops at the first kind that hits: full ID (kind prefix optional, case-insensitive), label, window position, then the end of the ID (at least four hex digits; listings print the last six). The match uses that kind's own ID, so a block short ID is not compared to the session. A `context.session_id` that no longer exists is ignored. `scope.session` and, for a block-only search, `scope.window` narrow the search; a client search with `scope.session` includes only clients attached to that session. `session.create` can take `initial_windows` with a `com.superlogical.terminal.shell` layout. `session.new_split` takes `direction`, `side`, and `layout`.

## Block methods

[Server API, Block methods](https://www.superlogical.com/rex/docs/automate/server-api#block-methods) and [Lua API, terminal methods](https://www.superlogical.com/rex/docs/reference/lua). Called as `block.method` with the block's own arguments under `args`. Creator: `com.superlogical.terminal` unless noted.

| Method | Status | What differs |
| --- | --- | --- |
| `format` | Implemented | `text`, `html`, and `vt`. `trim` and `unwrap` are honored. Large screens can return `id` / `eof` via `max_bytes`. The `vt` form also replays graphics anchored to each row: Kitty images are re-transmitted once and re-placed, sixel is re-emitted verbatim. |
| `process` | Implemented | Returns `last_exit`, `child`, `foreground`, `home`, and `ancestors` (parent chain from `/proc`, omitted as JSON null after the child has exited). |
| `pwd` | Implemented | OSC 7 is kept as a `file://` URL (`file://host/path`, or `file://<hostname>/path` when the program sends a bare absolute path). The field is left out until a directory is reported. `owner` is included when the foreground process is known. |
| `title` | Implemented | `title` is returned. `owner` (`pid`, `name`) is included when the title is non-empty and a foreground process is known. |
| `size` | Implemented | Cells, and pixel fields when present. |
| `write` | Implemented | Writes bytes to the PTY. |
| `reset` | Implemented | Full reset, and OSC 7501 records are removed. |
| `resize` | Implemented | Requests a PTY size. |
| `set_theme` | Implemented | Replaces default colors from the documented option object. |
| `program_status` | Implemented | Returns `records` with `state`, `kind`, `progress`, `app`, `effective_app`, `title`, `msg`, `updated_at`. |
| `list_dir` | Implemented | Lists directories under a path. |
| `clear` | Implemented | Clears the grid and scrollback. Not in the short Lua table; it is in the served catalog. |
| `modes` | Implemented | `screen` is `primary` or `alternate`, plus the active mode names, including mouse tracking (DECSET 9/1000/1002/1003), the mouse report format (1005/1006/1015), and focus reporting (1004). |
| `clipboard_read` | Implemented | Reads a stored OSC 52 copy by id. |
| `blob_read` | Implemented | Reads a stored large payload by id. |
| `input_mode` | Implemented | `echo`, `canonical`, and `signals` come from the PTY master's termios (`ECHO`, `ICANON`, `ISIG`). |
| `com.superlogical.onboarding.state` | Implemented | Onboarding flavor only. |
| `com.superlogical.onboarding.set_step` | Implemented | Onboarding flavor only. |

The Lua page's terminal table (`format`, `process`, `pwd`, `title`, `size`, `write`, `reset`, `resize`, `set_theme`, `program_status`, `list_dir`) is the same set, minus `clear`, `modes`, `input_mode`, `clipboard_read`, and `blob_read`, which the served catalog adds.

## Terminal emulation

The VT model in `vt.rs`, beyond the grid behavior the block methods expose.

| Area | Status | What differs |
| --- | --- | --- |
| Device attributes and version | Implemented | Primary DA answers `\x1b[?62;4;22c` (VT220 with sixel), secondary DA `\x1b[>41;1;0c`, and XTVERSION names rux with the package version. |
| Mode reports (DECRQM) | Implemented | DEC modes 1, 7, 9, 25, 47, 80, 1000, 1002, 1003, 1004, 1005, 1006, 1015, 1047, 1049, 2004, and 2026, and ANSI modes 4 and 20, answered from live state. |
| Setting reports (DECRQSS) | Implemented | The scroll region (`r`) and the current SGR rendition (`m`) are reported; other queries get the invalid-query reply. |
| XTGETTCAP | Partial | Only the terminal-name query is answered (`xterm-256color`); other names get the invalid reply. |
| Window reports (XTWINOPS) | Implemented | Reports 11, 13, 18, and 19 answer; title push/pop (22/23) keeps a ten-deep stack and emits `title_changed` on pop. The pixel-size reports (14, 16) are not answered because the server does not know the client's pixel size. |
| Kitty keyboard protocol | Implemented | Query replies with the current flags; push, pop, and set (OR / AND-NOT / replace) maintain the flag stack, and the snapshot's SCREEN record carries the real stack and flags. |
| OSC color queries | Implemented | OSC 52 read-back returns the newest stored copy; OSC 4 palette set/query with OSC 104 resets; OSC 10/11/12 dynamic colors set and query, with OSC 110/111/112 resets. A query for an unset dynamic color gets no reply, because the client's own default is unknowable. |
| Kitty graphics | Partial | Direct transmissions in formats 24, 32, and 100 (PNG kept in wire form), zlib-compressed payloads, chunked transfers, query replies, placements with cell offsets, source rectangles and z-order, and the delete variants (all, at cursor, by image, by placement, by column/row/z; capitals also drop the data) all work. Animation frames (`a=f`) return an error, and Unicode-placeholder placements are not modeled. The GHOSTSNP snapshot format has no image records, so a late attach restores no images, and a placement scrolled into scrollback leaves the model. |
| Sixel graphics | Implemented | DCS sixel is decoded (RGB and HLS color definitions, repeats, raster attributes, opaque or transparent background) and placed at the cursor. DECSET 80 (sixel scrolling) is tracked, reported, and moves the cursor below the image when on. The original sequence replays through `format`. |

## Events

[Events](https://www.superlogical.com/rex/docs/reference/events). Rux emits session events as `session_event` and terminal events as `block_event` with `creator_name` `com.superlogical.terminal`, which matches the CLI wrapping on that page. A script handler sees the unwrapped name (`terminal.bell`) and the event fields (`ev.exit_code`). There is no `rex events` stream in this binary.

Client-sent `block.event` input covers `key`, `paste`, `wheel`, `mouse`, and `focus`: wheel and mouse events are encoded into terminal mouse reports (X10, UTF-8, SGR, or urxvt, per the modes the program set) and written to the PTY, and focus events become `CSI I` / `CSI O` when focus reporting (1004) is on. The snapshot's terminal record reports the negotiated mouse mode and format instead of a fixed "disabled". Snapshots also carry the primary screen's scrollback: the SCREEN record declares the logical history extent and the rows follow READY as HISTORY PAGE records, newest chunk first.

### Session events

| Event | Status | What differs |
| --- | --- | --- |
| `window_created` | Implemented | `window_id`, `label`. |
| `window_closed` | Implemented | `window_id`. |
| `window_label_changed` | Implemented | `window_id`, `label`. |
| `active_window_changed` | Implemented | `window_id` of the window that became active, including after empty windows are dropped. Omitted only when no window remains. |
| `block_created` | Implemented | `block_id`. |
| `block_closed` | Implemented | `block_id`. |
| `session_label_changed` | Implemented | `label`. |
| `session_view_changed` | Implemented | `revision` only, as the `session.view` notes require. |
| `client_connected` | Implemented | `client_id`, `principal`, `connected_at`. |
| `client_disconnected` | Implemented | `client_id`, `principal`. |
| `client_connection_changed` | Implemented | `client_id`, `principal`, `connection_state`. A disconnect emits `lost` before `client_disconnected`. `restored` is emitted when a still-registered client is marked restored. |
| `creator_changed` | Implemented | Session event with an empty payload, sent to every session when the creator catalog is published as changed. |

`block_owner_changed` is emitted and is not on the public event list.

### Terminal events

| Event | Status | What differs |
| --- | --- | --- |
| `terminal.child_exited` | Implemented | `exit_code`. `error` (`exit status N`) is present only when the code is not zero, on both the control channel and the data channel. On the data channel the server flushes any queued terminal output, delivers the frame, then closes the socket (code 1000, `child exited`). The block then stays in the session for keep-open callers — unless its owner is an `app` client, in which case the server closes the block (and an emptied window, and a session left empty) exactly as the GUI flow expects. |
| `terminal.pwd_changed` | Implemented | `pwd` is a `file://` URL. `owner` (`pid`, `name`) is added from the foreground process when the event leaves the terminal. |
| `terminal.title_changed` | Implemented | `title` from OSC 0 and OSC 2. `owner` (`pid`, `name`) is added from the foreground process when the event leaves the terminal. |
| `terminal.bell` | Implemented | BEL (`0x07`) emits `bell`. |
| `terminal.process_changed` | Implemented | `generation`, `foreground`, and `ancestors` (parent chain from `/proc`, up to pid 1 or the terminal child, at most 32). `process` returns the same `ancestors` list. |
| `terminal.desktop_notification` | Implemented | OSC 9 (non-progress) and OSC 777 `notify`, with `title` and `body`. |
| `terminal.progress_report` | Implemented | OSC 9;4 as its own event (`state`, `progress`). Until a real OSC 7501 report, the same sequence also updates the root program-status record. |
| `terminal.clipboard_written` | Implemented | Every copy is stored and carries `id` and `bytes`. `text` is included up to 48 KiB and left out above that, as the event's own schema describes ("left out when the text is empty or too large for the event"). Copies in quick succession coalesce to the newest. Any stored copy, small or large, can be read back with `clipboard_read`, and a program-side OSC 52 query is answered with the newest copy. |
| `terminal.program_status_changed` | Implemented | `id`, `record`, `reason`. |
| `terminal.program_status_removed` | Implemented | `ids`, `reason` (`clear`, `prompt`, `child_exited`, `evicted`, `reset`). |

### Server events

| Event | Status | What differs |
| --- | --- | --- |
| `session_created` | Implemented | `session` with `session_id` and `label`. |
| `session_destroyed` | Implemented | `session_id`. |
| `client_joined` | Implemented | `client` object. The joining connection itself does not receive it. |
| `client_left` | Implemented | `client_id`. |
| `client_changed` | Implemented | Emitted when the label changes. |
| `keymap_changed` | Implemented | `generation`, `hash`, on config reload. |
| `hosts_changed` | Implemented | `hash`. |
| `tailscale_status_changed` | Implemented | Sent only to connections that asked for every server event (`session.attach_all` / `session.bootstrap`). The payload is the `tailscale` object. The sidecar emits one when its status changes. |

## Lua API

[Lua API](https://www.superlogical.com/rex/docs/reference/lua). Rux runs Lua 5.1 (mlua) for the configuration file and for scripts. Scripts run through `client.set_script` and through `rux-server do` (file, `-e`, or stdin, plus `-s`, `-b`, `--args`, and `key=value`). `io.popen` and `os.execute` raise. Names the page marks Missing in a configuration file (`rex.sleep`, `rex.wait`, `rex.stop`, `rex.after`, `rex.every`, `rex.args`, `rex.session_id`, `rex.block_id`) are nil there.

| Function | Status | What differs |
| --- | --- | --- |
| `rex.bind` | Implemented | Config load binds a key, a sequence, or a mode prefix to an action or a function. After load, only a function is accepted. A script bind is accepted and does not change a keymap. `client.set_script` reports the single function keys bound while that script loaded. Clients still fetch `client.keymap` for the configuration file's bindings. |
| `rex.unbind` | Implemented | Key, mode, and binding-table forms remove this file's bindings and record a removal for the client's defaults. The call returns how many of this file's bindings it removed. After load, only function bindings are removed. A function passed as `target` (or as the value) is matched by identity against the file's function bindings; one function can back several bindings, and all of them are removed. |
| `rex.mode` | Implemented | Config load declares a mode with `exclusive` (default false). After load, and in a script after load, the call errors. A script call at load is accepted and does nothing. |
| `rex.bindings` | Implemented | At config load, returns this file's bindings, filtered by `key`, `mode`, or `action`. A function binding returns the function as `fn` and omits `action`. Errors after load. A script call at load returns an empty list. |
| `rex.modes` | Implemented | At config load, returns the modes this file declared. Errors after load. A script call at load returns an empty list. |
| `rex.action` | Implemented | At load, defines `name`, `title`, `run`, and the optional metadata. A duplicate name errors. After load, the call errors. A script can define actions the same way and invoke them by name. |
| `rex.invoke` | Implemented | Returns the action's result, or nil and a message. Config load warns and does nothing. Later, only that file's actions run, nested at most 16 deep. A script name it did not define is sent as `client.action`. |
| `rex.client.queue` | Implemented | Inside a configuration action, queued actions are returned on `client.action` after `run` and dropped when `run` fails. Outside an action the call errors. In a script, the call dispatches to the script's client through `client.perform`: the target's declared actions are validated, the request is sent as `client_perform_requested`, and the call waits for the client's `client.reply` (10 seconds by default, 30 at most) and raises when it reports an error — the page's "is performed immediately" behavior. With no client, the call errors. |
| `rex.call` | Implemented | Any method. Does not fill `session_id` or `block_id`. A failure returns nil and a message. In a configuration file it is only available inside an action. |
| `rex.session.<method>` | Implemented | The documented helper names fill `session_id` and leave `block_id` alone. The same names on `rex.server(label)` do not fill either id. |
| `rex.block.call` | Implemented | Builds a `block.method` call and fills `session_id` and `block_id` when they are missing. `creator_name` is not sent. A missing `block_id` returns nil and a message. |
| `rex.layout.block` | Implemented | Builds a layout table and calls nothing. |
| `rex.layout.horizontal` | Implemented | `ratio` plus two children. |
| `rex.layout.vertical` | Implemented | Same. |
| `rex.on` | Implemented | Config load warns and does nothing. A script registers the handler while it is loading. After load, both places error. A handler sees the unwrapped event name and fields. |
| `rex.wait` | Implemented | Script only. A table filter matches fields. A function filter is `filter(ev, ctx)`. A timeout returns nil and `"timeout"`. |
| `rex.sleep` | Implemented | Script only. Fractional seconds are allowed. |
| `rex.stop` | Implemented | Script only. `rux-server do` exits with that code, or 0. |
| `rex.host` | Implemented | Config load stores `label`, `endpoints` (or one `endpoint`), and an id derived from the file and label. After load the call errors. A script call at load is accepted and does not register a host. |
| `rex.servers` | Implemented | Returns host labels, or the action context's `servers[].name` when that list is set. |
| `rex.server` | Implemented | Unknown labels error. The proxy has `call`, `session.*`, and `block.call`, and those calls do not fill `session_id` or `block_id`, as the page documents. When the named host declares endpoints, the calls leave the process: they open a `rex.control.v1` connection to the endpoint (`unix://`, `tcp://`, `ws://`, `wss://` with the system CA bundle, or a bare `host:port`) and forward the request. A host with no declared endpoints is served by this process. |
| `rex.exec` | Implemented | Waits and returns `code`, `signal`, `stdout`, `stderr`, `timed_out`, `ok`. Supports `cwd`, `env`, `clear_env`, `stdin`, `timeout`, and boolean `stdout`/`stderr`. A timeout sends `SIGTERM`, then `SIGKILL` if the process is still alive after two seconds. Timeout is capped at 600s. `text` is ignored on Linux. An unknown option warns. A command that never starts returns nil and a string. |
| `rex.exec.start` | Implemented | Returns a handle with `wait`, `write`, `close_stdin`, `kill`, `running`, and `pid`, or nil and a message. `detach` lets the command outlive its frame. Otherwise the command is sent `SIGTERM` when the action, handler, timer, or top-level script that started it returns. |
| `rex.after` | Implemented | Script only. Returns a timer with `cancel` and `active`. |
| `rex.every` | Implemented | Script only. `seconds` must be greater than zero. The 1,025th live timer stops the script with status 1. |
| `rex.json.encode` | Implemented | Returns text, or nil and a message. `opts.indent = true` pretty-prints. |
| `rex.json.decode` | Implemented | Returns a value, or nil and a message. JSON null becomes nil, and a null in an array is dropped. |
| `rex.log` | Implemented | `level` is `debug`, `info`, `warn`, or `error`, and defaults to info. A script also prints the message to stderr, which is what `rux-server do` shows. |
| `rex.args` | Implemented | Script only. The table passed to `rux-server do` or left empty. |
| `rex.session_id` | Implemented | Script only. Set when the script was given a session. Nil in a configuration file. |
| `rex.block_id` | Implemented | Script only. Nil when the script has no block. |
| `io.popen` and `os.execute` disabled | Implemented | Both raise. The page says to use `rex.exec` instead. |

Layout options documented for a terminal (`command`, `shell`, `cwd`, `initial_input`, `exit.on_completion`) are accepted by terminal spawn, separate from the Lua functions above.

## OSC 7501

[Program status protocol](https://www.superlogical.com/rex/docs/build/program-status), revision 0.4.

| Feature | Status | What differs |
| --- | --- | --- |
| Pair syntax, skip a malformed pair, ignore unknown keys, last key wins | Implemented | |
| States `idle`, `working`, `done`, `blocked`, `error` | Implemented | An unknown `state` drops the report. |
| `clear` removes the record and its children; no id clears every record | Implemented | A bad id does not fall through to the root record. |
| Keys `id`, `kind`, `progress`, `app`, `title`, `msg` | Implemented | `kind` only on `blocked`. `progress` only on `working` or `blocked`, integer 0–100, otherwise absent. `app` inherits through `effective_app`. |
| Each report replaces that record | Implemented | Missing keys are missing afterwards. |
| Feature detection `OSC 7501 ; ?` | Implemented | Reply is `OSC 7501 ; ?:states=idle,working,done,blocked,error:kinds=permission,question,auth ST`. The page's example has spaces; the grammar strips them. The state and kind lists match revision 0.4. |
| Base64 `msg` and `title`, discard the report on bad base64 or control characters | Implemented | Padding is optional. Limits are checked on the encoded size first. |
| Limits (4096-byte sequence, key 16, msg 2732/2048, title 256/192, app 32, id 128 / 32 / 8 levels, 256 records, LRU eviction) | Implemented | The sequence cap counts `ESC ] 7501 ;` plus ST as 9 bytes. Record cap is 256, above the required minimum of 64. |
| Drop `working` and `blocked` on process exit and on OSC 133 `A`; keep `done` and `error` | Implemented | `idle` is kept. The page says a terminal MAY drop it. |
| Records survive alternate-screen switches | Implemented | |
| RIS (`ESC c`) removes every record | Implemented | Theme is kept across that reset. The page only requires the records to go. |
| DECSTR does not remove records | Implemented | `CSI ! p` resets modes and the pen. Records, text, title, and the working directory stay. |
| OSC 9;4 mapped onto the root record, then stopped after the first OSC 7501 | Implemented | `working` / `error` / clear on the root record, and `terminal.progress_report` still fires. Mapping stops after the first accepted OSC 7501 report until a full reset. |
| Do not put report text in the feature-detection reply | Implemented | The reply is a fixed string. |
| Rate-limit desktop notifications caused by records | Not applicable | The server emits events and does not raise notifications itself. |

## Remote access

[Remote access](https://www.superlogical.com/rex/docs/linux/remote-access). Host `tailscaled` still serves `tailnet://` and `tailnet-serve://`. Built-in Tailscale is the `rux-tsnet` sidecar (`tailscale.com/tsnet` v1.68.2). The process starts only for `--tailscale`, or on the first `server.tailscale.enable` when the binary sits next to `rux-server` or `RUX_TSNET_BIN` points at it. The default service does not pass `--tailscale` and does not spawn the sidecar; it keeps using the host tailnet.

| Flag or listener | Status | What differs |
| --- | --- | --- |
| `--tailscale` | Implemented | Starts the sidecar device. Its HTTPS address is `https://<dns name>`, which is `https://rex.<tailnet>.ts.net` once MagicDNS reports the name. |
| `--tailscale-auth-key-file` | Implemented | Read once and handed to tsnet. `-` reads stdin. The key is not written to the log, the unit, or the status object. The deploy kit's `TS_AUTHKEY` is still only for the machine's own `tailscale up`. |
| `--tailscale-hostname` | Implemented | Device name, default `rex`. `server.tailscale.rename` changes it afterwards. |
| `--tailscale-advertise-tag` | Implemented | Repeatable. Refused unless `--tailscale-allow-tailnet-members` is set. The sidecar requests the tags with `EditPrefs` after the node starts. |
| `--tailscale-allow-tailnet-members` | Implemented | Anyone the tailnet ACLs allow, including a tagged peer. Off means only the user who owns the device. |
| `--tailnet-allow-identified` | Implemented | Admits any peer Tailscale can identify. Default remains owner-only. Env `RUX_TAILNET_ALLOW_IDENTIFIED` also sets it. |
| `tailnet://:PORT` | Implemented | Binds only `100.64.0.0/10` and `fd7a:115c:a1e0::/48`. Refuses `0.0.0.0`, `::`, and loopback. Whois identifies the TCP peer. Plain HTTP on that port, as documented. |
| `tailnet-serve://ABS_PATH` | Implemented | Unix socket mode `0600`, uid 0 only. Funnel (`Tailscale-Funnel-Request`) is refused. Tagged devices have no Serve identity headers; the page says they must use `tailnet://` instead. |
| `--allow-anonymous` | Implemented | Required for a plain HTTP listener to accept unidentified clients. Refused together with `--tailnet-only`. |
| `--extra-listen` | Implemented | Repeats. Accepts `http://`, `https://`, `tailnet://`, `tailnet-serve://`, Unix paths, and the plain-HTTP form `:7297` (`0.0.0.0:7297`). `--tailnet-only` still refuses that HTTP bind. |
| `--listen` | Implemented | Unix socket or `http://` / `https://`. Default is `/tmp/rux.sock`, not `/run/rex/server.sock`. |
| `--state-dir` | Implemented | Host records and the stable host id. |
| `--socket-mode` | Implemented | Octal mode for the main Unix socket, default `0600`. The shared unit passes `0660`. `tailnet-serve://` stays `0600`. |
| `--log-format` | Implemented | `text` (default) or `json`. |
| `--max-sessions` | Implemented | `session.create` returns `conflict` with `session limit reached` once the cap is hit. `0` means no cap. |
| NixOS module options | Not applicable | Rux has no NixOS module. This row is excluded from the percentage. |

Who may connect, for the listeners rux does implement: owner-only by default, and `--tailnet-allow-identified` for everyone Tailscale can identify. That matches the Serve and tailnet-address column of the page. The built-in Tailscale column does not apply.

Plain HTTP without `--allow-anonymous` does not grant access. Rux can also require a bearer token. The public pages do not mention that header, and the stock `rex` CLI has no way to send it.

## Server modes and login server

[Server modes](https://www.superlogical.com/rex/docs/linux/server-modes), [shared server](https://www.superlogical.com/rex/docs/linux/shared-server), [login server](https://www.superlogical.com/rex/docs/linux/login-server), [remote access](https://www.superlogical.com/rex/docs/linux/remote-access). Those pages describe three ways to run a server:

| Mode | Who it's for | Runs as | Started by |
| --- | --- | --- | --- |
| Personal | Just you | Your account | Any `rex` command, or `rex server start` |
| Shared | A few people you trust with one account | `rex` | `rex.service` |
| Login | Several people, each as themselves | root, then each person's account | `rex-login-server.service` |

The shared unit's command keeps the four options from the documented drop-in: `--listen /run/rex/server.sock`, `--state-dir /var/lib/rex`, `--socket-mode 0660`, `--log-format text`.

The Tailscale identity is the machine node's owner from LocalAPI whois. It is not the OS account the process runs as. The remote-access table lists Tailscale Serve and a tailnet address for the shared and login servers. The default install is still the personal account, and it keeps the tailnet-only listeners: `tailnet://:7297` and `tailnet-serve://` on `$XDG_RUNTIME_DIR/rex/serve.sock`. Official `rex` does not ship a personal systemd unit. `install.sh` enables a systemd user unit for `SUDO_USER` (or `RUX_USER`) and `loginctl enable-linger`, which is the boot-persistent form of `rex server start`: same account, home, and runtime directory, and no `--exit-empty`.

| Feature | Status | What differs |
| --- | --- | --- |
| Personal server, started by any `rex` command | Partial | `--exit-empty` stops the process about 10 seconds after the last session and the last client. Nothing auto-starts: that is a `rex` CLI behavior, and rux does not install `rex`. The remote-host install enables a user unit for the invoking login account instead of a `rux` system user. |
| Personal socket under `$XDG_RUNTIME_DIR/rex` and state under `$XDG_STATE_HOME/rex` | Implemented | `--personal` uses those paths (`/run/user/<uid>/rex/server.sock` when `XDG_RUNTIME_DIR` is unset). The user unit passes `--personal`. Without the flag the default stays `/tmp/rux.sock`. |
| Shared server as user `rex`, group `rex`, unit `rex.service` | Implemented | `deploy/rex.service` listens on `/run/rex/server.sock` with `--socket-mode 0660` and state `/var/lib/rex`. It is not sandboxed. `install.sh` installs the unit and creates the `rex` user with a nologin shell. It does not enable the unit. The default install is the personal user unit, not user `rux`. On macOS the same account is a LaunchAgent. |
| Shared and login units cannot both use `/run/rex` | Implemented | Each unit has `Conflicts=` the other. `rex.service` refuses to start while `/run/rex/accounts` exists. |
| Login server (`rex-login-server.service`, runs as root) | Implemented | `rux-server login-server` reads the accounts file, identifies a Unix peer, Tailscale Serve headers, or a tailnet whois result, starts `rux-server` as that account when it is root (or the same uid), and proxies the connection. On a logind machine the account socket is the personal socket. The unit is installed and not enabled. |
| `/etc/rex/accounts.jsonc` | Implemented | JSON with comments and trailing commas. `version`, `accounts`, `principals`, `"*"`, and `defaults`. `login-server --check` prints `accounts ok: N`. `install.sh` writes an empty accounts object when the file is absent. |
| Principal forms `tailscale:user@host`, `tailscale:tag:ci`, `tailscale:*`, `tailscale:tag:*`, `peer:UID`, `identified`, `anonymous` | Implemented | A tagged device does not match a login or `tailscale:*`. `"*"` adds passwd users with uid 1000 or higher. |
| Default-account specificity (login, then tag, then wildcard, then `identified`, then `anonymous`) | Implemented | Equal rank keeps the first entry in the file. |
| `anonymous` forbidden under `"*"` and never allowed as root | Implemented | The file fails to parse if `"*"` lists `anonymous`. An anonymous caller cannot select root. |
| Account in the URL (`https://root@host`) | Implemented | The HTTP `Host` header is parsed as `user@host`. |
| PAM `/etc/pam.d/rex-login-server`, `/etc/nologin`, nologin shells | Implemented | The root login server's supervisor calls `pam_start`, `pam_authenticate`, `pam_acct_mgmt`, `pam_setcred`, and `pam_open_session`, passes the PAM environment to the account server, and calls `pam_close_session` when that server exits. The conversation refuses a password prompt. `/etc/nologin` and `nologin` / `false` shells are still refused first. A non-root process cannot open that session. |
| `--pam=false` with `/etc/shadow` checks | Implemented | A shadow password that is empty or starts with `!` or `*` is locked. A name missing from the shadow file is locked. No PAM session is opened. |
| `systemctl reload` of the accounts file, keeping allowed sessions | Implemented | `SIGHUP` re-reads the file. Connections that are no longer allowed are closed. The unit's `ExecReload` sends that signal. A bad file keeps the previous accounts. |
| Per-account server survives login-server restart | Implemented | The supervisor calls `setsid`. The unit uses `KillMode=process`. A test still reaches the account socket after the login server exits. |

## CLI commands

[CLI](https://www.superlogical.com/rex/docs/automate/cli), [shell scripting](https://www.superlogical.com/rex/docs/automate/shell-scripting), [Lua scripts](https://www.superlogical.com/rex/docs/automate/lua-scripts). Rux does not install a `rex` binary, does not put itself on `PATH`, and does not set `REX_BIN_DIR`. Every command below is Not applicable as a program. The last column is the server method a `rex` client calls for that command.

| Command | Status | Server surface |
| --- | --- | --- |
| `rex help` | Not applicable | None. |
| `rex version` | Not applicable | `server.version` is Implemented. |
| `rex ls` | Not applicable | `session.list` is Implemented. |
| `rex new` | Not applicable | `session.create`. |
| `rex split` | Not applicable | `session.new_split`. |
| `rex run` | Not applicable | `session.new_window` with a terminal layout. |
| `rex zoom` | Not applicable | `session.zoom_block`. |
| `rex send` | Not applicable | `com.superlogical.terminal.write`. |
| `rex send-key` | Not applicable | `client.key` / `block.event`. |
| `rex capture` | Not applicable | `com.superlogical.terminal.format`. |
| `rex wait` | Not applicable | Would wait on `terminal.child_exited`. |
| `rex session inspect` | Not applicable | `session.view` and `session.list_clients`. |
| `rex block inspect` | Not applicable | `session.describe_block`. |
| `rex api list` | Not applicable | `help.all`. |
| `rex api describe` | Not applicable | One method object from that catalog. |
| `rex api call` | Not applicable | The control WebSocket. |
| `rex events` | Not applicable | The same events, without a CLI stream. |
| `rex do` | Not applicable | The `rex` program is not installed. `rux-server do` and `client.set_script` run the same script runtime. |
| `rex client ls` | Not applicable | `client.list` and `server.whoami`. |
| `rex hosts` | Not applicable | `hosts.list`, `hosts.put`, `hosts.remove`. The page says hosts are CLI-only and do not sync to the GUI. |
| `rex server start` | Not applicable | No auto-start supervisor. |
| `rex server run` | Not applicable | This is the long-running server. Rux's binary is that process, with a different flag set. |
| `rex server status` | Not applicable | `server.status`. |
| `rex server logs` | Not applicable | No follow command. `--log-path` is kept for the process and is not a `server.status` field. |
| `rex server stop` | Not applicable | `server.stop`. |
| `rex config check` / `rex config reload` | Not applicable | `server.config_reload` reloads `init.lua`. There is no separate check command. |
| `rex keymap` / `rex actions` | Not applicable | `client.keymap` and config actions. |
| `rex skill` | Not applicable | Agent skill install is outside the server. |
| `rex home` | Not applicable | Not a server method. |

Environment variables the CLI page says Rex sets in every terminal: `REX_SESSION` and `REX_BLOCK` are set when a terminal starts. `REX_SERVER` is not. `REX_BIN_DIR` is not.

## Contradictions

These are places rux used to differ from the public docs. Each one is fixed in the current handlers.

1. Fixed. Misspelled arguments fail schema validation.
2. Fixed. `server.whoami`'s `account` is the OS account string, omitted when unknown.
3. Fixed. `server.status` no longer sends `log_path` or `you`, and it includes `api_min_revision`. `tailscale` stays omitted until built-in Tailscale can run.
4. Fixed. `server.version` omits `commit` and `built_at` when the build did not record them, and it includes `api_min_revision`.
5. Fixed. `server.stop` is local-socket-only (403 otherwise). `if_idle` returns `conflict` while a session or another client is present.
6. Fixed. `session.help` returns `http`, the session's own methods, `block.close` / `block.method` / `block.event`, and `block_types`.
7. Fixed. `client.set_script` runs. `server.tailscale.*` runs when `rux-tsnet` is installed, and returns `not_supported` when it is not, which is the catalog's own rule for a server that cannot run built-in Tailscale.
8. Fixed. `terminal.child_exited` includes `error` only when the exit code is not zero.
9. Fixed. `active_window_changed` includes `window_id` when a window is active after cleanup.
10. Fixed. `--extra-listen :7297` is plain HTTP on `0.0.0.0:7297`.
11. Fixed. OSC 7 is stored as a `file://` URL and emits `terminal.pwd_changed`.
12. Fixed. `rex.exec` sends `SIGTERM` on timeout, then `SIGKILL` two seconds later.

Host `tailnet://` and `tailnet-serve://` follow the "Tailscale on the machine" rows, including owner-only admission and the tagged-device exception for Serve. Built-in Tailscale follows the other column when `rux-tsnet` is installed. The personal server's OS account is the invoking login user. Tailscale whois remains the tailnet identity.

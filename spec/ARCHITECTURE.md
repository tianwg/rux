# rux wire protocol

Interoperability notes for the protocol this server speaks. A Rex client
connects the same way it connects to any compatible server: a WebSocket
control channel, plus a separate data channel per terminal.

## 1. Process model

One `rux-server` process owns sessions, PTYs, the Lua config, and block
state. Clients are WebSocket connections. Listeners:

- a Unix socket (`--listen`, or `$XDG_RUNTIME_DIR/rex/server.sock` with
  `--personal`)
- optional `http://` and `https://` (`--extra-listen`)
- `tailnet://` and `tailnet-serve://` on the host's tailscaled
- a built-in Tailscale device when `--tailscale` is set or
  `server.tailscale.enable` runs and the `rux-tsnet` sidecar is installed

## 2. Wire protocol

Transport: HTTP/1.1 over a Unix socket or TCP/TLS, upgraded to WebSocket.

| Path | Subprotocol | Purpose |
|---|---|---|
| `/api/help` | — | API catalog (JSON) |
| `/api/control` | `rex.control.v1` | Request/response and the event stream |
| `/api/data` | `rex.data.terminal.v1` | Per-block terminal data stream |
| `/llms.txt`, `/llms.html` | — | Short text and HTML lists of the methods |

Frames are JSON text. The server may negotiate `permessage-deflate`.
`max_message_bytes` is 1 MiB.

### Handshake

```jsonc
// C→S
{"type":"hello","client":{"kind":"cli","platform":"macos","name":"rex","version":"0.0.…"},"api_revision":7}
// S→C
{"type":"welcome","protocol":"rex.control.v1","limits":{"max_message_bytes":1048576},
 "client":{"id":"client:<uuidv7>","reconnect_token":"<opaque>"},"api_revision":7,"api_server_revision":7}
```

`reconnect_token` is an opaque per-connection value. rux includes it on
`welcome` and does not yet redeem it to resume a control connection.

### Requests

```jsonc
{"type":"request","id":"control-1","method":"session.view","payload":{"session_id":"session:…"}}
{"type":"response","id":"control-1","seq":3,"payload":{…}}
{"type":"response","id":"control-1","seq":3,"error":{"code":"bad_request","message":"…","status":400}}
```

- The arguments field is `payload`.
- `id` is any non-empty string and is echoed back.
- `seq` is the last event sequence number queued on this connection before
  the reply. Clients apply events with a higher `seq` on top of the reply.
- Errors carry an HTTP-style `status` and a stable `code`
  (`bad_request`, `not_found`, `conflict`, `session_not_found`,
  `method_not_found`, `too_large`, and others).

### Events

```jsonc
{"type":"event","seq":1,"payload":{"type":"session_event","payload":{
  "session_id":"session:…",
  "event":{"type":"block_event","payload":{
    "block_id":"block:…","creator_name":"com.superlogical.terminal",
    "name":"child_exited","payload":{"exit_code":0}}}}}}
```

Three scopes: session events (`window_created`, `block_created`,
`session_view_changed`, `client_connected`, …), terminal/block events
(`bell`, `title_changed`, `pwd_changed`, `process_changed`, `child_exited`, …),
and server events (`session_created`, `client_joined`, `keymap_changed`, …).
`session_view_changed` follows nearly every structural change.

### Data channel

1. `data.connect` with `{session_id, block_id, data_ref_id:"terminal", subprotocol:"rex.data.terminal.v1"}`
   returns `{ticket, expires_in_ms}`. Tickets are single-use, URL-safe
   unpadded base64 (not UUID text). The data connection checks the source
   and the subprotocol.
2. Open `WS /api/data` with that subprotocol and send a binary `HELLO`
   carrying the ticket.
3. The server streams terminal output as binary frames. The client sends
   input and resize frames.

A dropped data stream can resume. The byte layout is in
[notes/data-resume.md](notes/data-resume.md).

### Remote access

`--extra-listen http://HOST:PORT` opens a TCP listener. `https://HOST:PORT`
requires `--tls-cert` and `--tls-key`. Remote control and data connections
are rejected by default. `--allow-anonymous` grants full API access to every
network client. `--bearer-token-file` authorizes HTTP clients that send
`Authorization: Bearer <token>`. Do not expose anonymous access to an
untrusted network.

Tailnet listeners:

- `tailnet://:7297` binds only addresses in `100.64.0.0/10` and
  `fd7a:115c:a1e0::/48`. `0.0.0.0` and `::` are refused. Each TCP peer is
  authorized with LocalAPI `whois` (`GET /localapi/v0/whois`). The default
  policy admits only the node owner. `--tailnet-allow-identified` admits any
  identified peer, which a tagged node needs because it has no owner.
- `tailnet-serve://SOCKET` is the backend for `tailscale serve`. The socket
  is mode `0600` and accepts only uid 0. Identity comes from
  `X-Forwarded-For` plus whois, or from `Tailscale-User-Login`. A
  `Tailscale-Funnel-Request` header is refused.
- `--tailnet-only` refuses plain `http://` and `https://` listeners.

The client URL is `http://<magicdns>:7297`, or `https://<magicdns>` once
Serve is up. [deploy/README.md](../deploy/README.md) is the install path.

`server.tailscale.enable`, `disable`, `login`, `logout`, and `rename` drive
the `rux-tsnet` sidecar when that binary is installed. Otherwise they return
`not_supported` and the host `tailscaled` listeners still work.

`hosts.list`, `hosts.put`, and `hosts.remove` persist records as `hosts.json`
under the state directory. Sessions stay in memory.

## 3. API surface (api revision 7)

73 control methods, two block creators.

- **server.*** `status`, `version`, `whoami`, `stop`, `config_reload`,
  `tailscale.{enable,disable,login,logout,rename}`,
  `apple.{privacy_status,grant_file_access}`
- **session.*** lifecycle (`create`, `destroy`, `attach`, `attach_all`,
  `detach`, `bootstrap`, `list`, `view`), layout (`new_window`, `new_split`,
  `new_layer`, `new_block`, `move_block`, `swap_blocks`, `resize_pane`,
  `resize_layer`, `float_block`, `detach_block`, `close_window`,
  `close_layer`, `zoom_block`, `focus_*`, `move_window`, `move`), naming
  (`set_label`, `set_window_label`, `set_block_label`), ownership
  (`own_block`, `disown_block`), introspection (`list_blocks`,
  `list_clients`, `describe_block`, `help`)
- **block.*** `close`, `event`, `method`; `block_creator.list`
- **client.*** `list`, `inspect`, `action`, `key`, `keymap`, `perform`,
  `reply`, `set_label`, `set_script`
- **data.connect**, **help.all**, **hosts.{list,put,remove}**,
  **target.{resolve,complete}**

Block creators: `com.superlogical.onboarding` and `com.superlogical.terminal`
(flavor `com.superlogical.terminal.shell`). Terminal block methods:
`write`, `format`, `resize`, `size`, `modes`, `title`, `pwd`, `process`,
`input_mode`, `clear`, `reset`, `set_theme`, `clipboard_read`,
`program_status`, `list_dir`, `blob_read`.

Schemas are the catalog in `crates/rux-server/assets/api-help.json`
(`input_schema` and `output_schema`), generated from
`crates/rux-server/catalog`. `--api-help` and `--block-creators`
replace those files at startup. See the README.

## 4. Data model

```
Server
├── sessions: session:<uuidv7>
│   ├── label, revision
│   ├── windows: window:<uuidv7>
│   │   ├── label, focused_block_id, zoomed_block_id
│   │   └── layers[]
│   │       ├── tiled   (fills the window, one per window)
│   │       └── floating (bounds [x,y,w,h] fractions)
│   │       └── layout: recursive split tree
│   │           ├── leaf  {rect, block_id}
│   │           └── split {rect, split:{split_id, direction, ratio, before, after}}
│   └── blocks: block:<uuidv7>        (may be detached)
│       ├── creator_name, flavor, host_id, label, owner(client_id)
│       └── creator state (PTY, screen buffer, …)
├── clients: client:<uuidv7>          (kind, name, platform, version, principal)
└── persistent host records, config generation/hash, Tailscale state
```

Rects and bounds are normalized fractions `[x, y, w, h]`. `direction` is
`horizontal` (before is left) or `vertical` (before is top). `ratio` is the
before side's share. A split changes only the anchor subtree; existing split
ids stay.

Identity is a `principal` with `kind` of `peer`, `windows_peer`, `tailscale`,
or `anonymous`, plus `transport`, `display`, and when known `uid`, `gid`, and
`pid`. Local Unix peers are identified with `SO_PEERCRED`. The host id is
stable across restarts. It is read from `host-id` in the state directory
(on macOS, `~/Library/Application Support/rex/host-id`). A new installation
creates a UUID there.

## 5. Compatibility harness

`spec/tools/rexclient.py` is a small client for the control protocol
(handshake, framing, deflate, requests, events). `scripts/compat.sh` drives
a `rex` CLI against Unix, HTTP, and HTTPS listeners, including host
persistence, Lua actions and keymaps, client perform/reply, layout, and
terminal capture. `probe_perform.py`, `probe_terminal_status.py`, and
`probe_data_channel.py` are the protocol checks that script calls.

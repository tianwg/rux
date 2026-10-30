# rux

rux is a Rex-compatible server written in Rust. It was made out of curiosity
while waiting for the official Linux server, vibe coded with AI. It is a
learning project, not a replacement.

rux is unofficial and independent. It is not affiliated with or endorsed by
Rex or its developers. "Rex" is a trademark of its owner. This project
contains no official source code, binaries, or assets. It will be taken down
on the rights holder's request.

> Status: the control plane, layout model, PTY terminals, event stream,
> terminal data channel, Lua surface, and terminal graphics work. The
> remaining known gaps are listed below and in
> [docs/rex-compat-matrix.md](docs/rex-compat-matrix.md).

## What works

| Area | Implemented |
|---|---|
| Wire protocol | `rex.control.v1` WebSocket handshake (`hello`/`welcome`), requests with `payload`, responses with `seq`, per-connection event sequence, 1 MiB limit |
| HTTP/network | `/api/help`, `/llms.txt`, `/api/control`, `/api/data`; Unix sockets, TCP/HTTP, and HTTPS listeners |
| Server | `server.version`, `status`, `whoami`, `stop`, `config_reload`, `help.all`, `block_creator.list`, persistent `hosts.list/put/remove`, `server.apple.privacy_status` / `server.apple.grant_file_access` (real TCC reporting and sandbox-token consumption on macOS builds) |
| Sessions | `create`, `list`, `attach`, `attach_all`, `bootstrap`, `detach`, `destroy`, `view`, session ordering |
| Layout | `new_window`, `new_split`, `new_layer`, `new_block`, directional/cyclic focus, window/layer/block moves, swaps, pane/layer resize, floating/detached blocks, raise/lower layers, zoom, labels, close operations |
| Ownership | `own_block` / `disown_block`, owner-change events, creation-order results |
| Lua config | Lua 5.1 config load; `rex.bind`, `rex.unbind` (including by function), `rex.mode`, `rex.host`, `rex.action`, `rex.exec` / `rex.exec.start`, event handlers and timers; `rex.client.queue` performs through the client; `rex.server(label)` forwards calls over a real control connection to the host's declared endpoints |
| Blocks | PTY-backed terminals and onboarding step state; `block.method` for `write`, `resize`, `size`, paged `format`/`blob_read`, `list_dir`, `program_status`, `clipboard_read`, `set_theme`, `title`, `pwd`, `modes`, `process`, `input_mode`, `clear`, `reset`; `block.close`; `block.event` |
| Terminal | VT screen model with scrollback, SGR colors/attributes, wide characters, cursor addressing, erase/insert/delete, scroll regions, alternate screen, mouse reporting, title/cwd, OSC 7501 status records, and OSC 52 clipboard writes with query read-back; terminal queries (primary/secondary DA, XTVERSION, DECRQM, DECRQSS, XTGETTCAP, XTWINOPS with a title stack, Kitty keyboard negotiation, OSC 4/10/11/12 colors); Kitty graphics and sixel images are parsed, stored, placed, and replayed by `format`; `format` renders `text`, `html`, or `vt`; resize reflows both grids |
| Clients | `client.list/inspect/set_label`, `client.key`, `client.perform/reply`, join/leave events |
| Targets | `target.resolve` / `target.complete` over session/window/block/client labels, full IDs, short IDs, window ordinals, and empty-query defaults |
| Data channel | base64url one-time tickets via `data.connect`, subprotocol validation, initial screen + live PTY output as binary frames, input passthrough |
| Tailnet | `tailnet://:PORT` binds only Tailscale addresses and authorizes peers with tailscaled LocalAPI whois; `tailnet-serve://` accepts Tailscale Serve (Funnel refused). `--tailnet-only` refuses public HTTP/HTTPS binds |
| Events | session events (`session_view_changed`, `block_created`, `client_connected`, …), block events (`child_exited`), server events (`session_created`, `client_joined`, …) |

## Not implemented yet

- **Terminal graphics, the edges**: Kitty animation frames (`a=f`) and
  Unicode-placeholder placements are not modeled. The `GHOSTSNP`
  snapshot format has no image records, so images do not survive a
  late attach, and a placement scrolled into scrollback leaves the
  model (a client that watched the live stream keeps its own copy).
- **Lua runtime**: full argument schema validation for Lua-defined
  actions, and complete keymap conflict resolution.
- **macOS verification**: the TCC and sandbox-token code paths compile
  for macOS (`aarch64-apple-darwin` is type-checked) but have not run
  on a Mac yet. The personal server itself installs as a LaunchAgent.

## Quick start

```sh
cargo build

./target/debug/rux-server --listen unix:///tmp/rux.sock

# in another shell — a Rex CLI against this server:
rex -S unix:///tmp/rux.sock api call server.version
rex -S unix:///tmp/rux.sock new demo --json
rex -S unix:///tmp/rux.sock ls
rex -S unix:///tmp/rux.sock split -s demo -- htop
rex -S unix:///tmp/rux.sock send -s demo 'echo hello'
rex -S unix:///tmp/rux.sock send-key -s demo enter
rex -S unix:///tmp/rux.sock capture -s demo
rex -S unix:///tmp/rux.sock capture -s demo --format=html
rex -S unix:///tmp/rux.sock kill demo
```

The server also accepts `--listen /tmp/rux.sock` and `--log-path PATH`.

### Remote listeners

HTTP and HTTPS listeners are opt-in. `--allow-anonymous` gives every network
client full server access; use it only on a trusted network or behind an
authenticating proxy. For direct HTTPS clients that can send an Authorization
header, use a private token file instead:

```sh
rux-server --listen unix:///tmp/rux.sock \
  --extra-listen https://0.0.0.0:8443 \
  --tls-cert fullchain.pem --tls-key private-key.pem \
  --bearer-token-file /secure/path/rux-token
```

The token file must be readable only by its owner and contain at least 32
non-whitespace characters. The current `rex` CLI has no bearer-token option.
For a Rex client, use the tailnet listeners instead of a bearer token.

### Tailnet (the way a Rex client connects)

`rux-server` uses the machine's `tailscaled`. It does not embed Tailscale.
`--tailnet-only` refuses `http://` and `https://` listeners, including
`0.0.0.0`. `tailnet://:7297` binds only this node's Tailscale IPs and admits
the peer only after LocalAPI `whois`. By default that peer must be the node
owner. `tailnet-serve://` is the socket `tailscale serve` proxies, and
Funnel requests are rejected.

```sh
rux-server --personal \
  --extra-listen tailnet://:7297 \
  --extra-listen tailnet-serve:///run/user/$(id -u)/rex/serve.sock \
  --tailnet-only
```

`--personal` is the personal server: the process runs as the account that
started it, the socket is `$XDG_RUNTIME_DIR/rex/server.sock`, and state is
`~/.local/state/rex`. Terminals use that account's shell.

From another machine on the tailnet:

```sh
rex -S http://<magicdns>:7297 ls
rex -S https://<magicdns> ls    # after `tailscale serve --bg --https=443`
```

Linux and macOS install: [deploy/README.md](deploy/README.md) has the
systemd user unit, the macOS LaunchAgent, the installer (`TS_AUTHKEY` is
never committed), the host firewall, and `verify-tailnet.sh`.

## API catalog

`help.all` and `GET /api/help` serve a catalog rux ships in the binary:

- `crates/rux-server/assets/api-help.json` — method names and the JSON
  Schema used to validate calls
- `crates/rux-server/assets/block-creators.json` — terminal and onboarding
  creators

That catalog is rux's own. `crates/rux-server/catalog/generate.py` writes
it from the field schemas this server validates (`api-help.schema.json`,
`block-creators.schema.json`) and from `wording.json`. Descriptions are
one line each, written for rux. Per-field prose, request examples, and
validation notes are not included. Method names, argument names, and
wire identifiers such as `com.superlogical.terminal` stay, because
clients send them.

`block_creator.list` fills `host_id` from this process; the file does not
contain one.

To serve a document of your own (for example help text you saved from a
server you run), pass paths or the matching environment variables:

```sh
rux-server \
  --api-help ./my-api-help.json \
  --block-creators ./my-block-creators.json
```

`RUX_API_HELP` and `RUX_BLOCK_CREATORS` are the same settings. The API file
needs `methods`, and may include `block_types` and `http`. The creator file
needs `creators`. Inputs are checked against `input_schema` when a method
has one, and block `args` are checked against `block_types[].methods[].args_schema`.

## Compatibility harness

```sh
./scripts/compat.sh
```

Builds the server with isolated state, starts Unix, HTTP, and HTTPS listeners,
and drives a `rex` CLI through the checks in that script: host persistence and
config declarations, remote transport, Lua actions/keymaps, client
action/reply, OSC 7501/52, tiled/floating layout, ownership, PTY inspection,
paged capture, and cleanup. The script exits non-zero on any failure. It
expects `rex` on `PATH`.

## Repository layout

```
crates/rux-proto/        wire envelopes, view/layout types, ID helpers
crates/rux-server/
  src/main.rs            CLI, listeners
  src/ws.rs              HTTP routes, control/data WebSocket loops
  src/api.rs             control API dispatch
  src/config.rs          Lua 5.1 config loading and action runtime
  src/state.rs           sessions/windows/layers/blocks/clients, events, layout ops
  src/terminal.rs        PTY spawn/read/write/resize
  src/vt.rs              VT screen model, scrollback, text/html/vt rendering
  assets/api-help.json   API catalog this server validates and serves
  assets/block-creators.json
spec/
  ARCHITECTURE.md        wire protocol and data model
  notes/                 data-channel notes, Lua 5.1 compatibility notes
  tools/rexclient.py     small control-protocol client used by the harness
scripts/compat.sh        CLI compatibility suite
deploy/                  systemd user unit, LaunchAgent, installer, tailnet verify
```

## Caveats

- Not production ready: sessions and most configuration are in-memory, and
  anonymous network access grants full control. Use HTTPS plus a token-capable
  client or a trusted proxy; do not expose `--allow-anonymous` to the Internet.

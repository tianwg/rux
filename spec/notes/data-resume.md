# Data stream resume

The terminal data WebSocket speaks a short binary handshake after the HTTP
upgrade. rux implements the frames below. A control-connection resume is
not implemented.

## Handshake frames (first message on the data WebSocket)

- HELLO, 17 bytes: `0x01` + 16 ticket bytes. The ticket is the
  16 bytes behind the base64url token `data.connect` returns on
  the control connection. Single-use, limited lifetime, same-user
  only. A HELLO consumes its ticket even when refused.
- RESUME, 25 bytes: `0x02` + 16 bytes of the latest reconnect
  token + u64 LE count of stream bytes the client has used.
- The server ignores any bytes after the fixed part of a HELLO or
  RESUME, and ignores all client messages after the handshake.

## WELCOME (server, exactly 32 bytes)

`0x81` + 16-byte reconnect token + 3 zero bytes + u32 LE grace in
milliseconds (how long the stream is kept for a resume) + u64 LE channel
nonce (never zero). A resume answers with a WELCOME carrying a
new reconnect token and the same channel nonce.

## REJECT (server, 2 bytes: `0x82` + reason)

- `0x01` ticket/token unknown, expired, used, wrong user, or
  session gone
- `0x02` this client already has a connection to the same data
  source of that block (one at a time; a RESUME replaces a
  dropped one)
- `0x03` stream unavailable (block closed, or RESUME counted
  fewer bytes than the server sent and retained)
- `0x04` limits (reserved; rux does not send it)
- `0x05` malformed/late handshake, or RESUME counted more bytes
  than the server sent
- `0x06` server failure
- `0x07` wrong subprotocol

After a refused RESUME the stream is over; the client starts
again with a new ticket and a HELLO. Handshake refusals close
with `data handshake rejected` (1002/1008/1011/1013 by reason).

## Resume semantics

- The client opens a new WebSocket at the data path with the
  same subprotocol and sends RESUME with the token from the
  latest WELCOME and the exact count of stream bytes its own
  code has used across every connection of the stream, excluding
  WELCOMEs and excluding anything the WebSocket library read
  ahead. The count must be exact or the server refuses the
  resume and ends the stream.
- The server continues from the first unreceived byte. Frame
  boundaries carry no meaning.
- A resume needs no ticket and no control connection.
- Starting over with a fresh HELLO ends the waiting stream.

## Close semantics

- Client close with 1000 ends the stream at once. Any other
  close, or a dropped connection, leaves the stream waiting out
  the grace with output held.
- Close table: 1001 `keepalive timeout` (resume the stream),
  1001 `data provider canceled`, 1008 `data provider
  unavailable`, 1011 `data provider failed`, 1013 `data
  reconnect required` (also when more output piled up while the
  client was away than the server could keep). Block-closed
  status and reason are server-config values.

## rux parameters

- Grace: 30,000 ms, advertised in every WELCOME.
- Replay window: the last 8 MiB of sent stream bytes. A resume
  counting below the window is refused 0x03; counting above the
  total sent is refused 0x05; both end the stream.
- While parked, output keeps queueing under the per-client hard
  budget (8 MiB); if the stream is cut for exceeding it, a later
  resume is refused 0x01.

## Not implemented

`welcome` on the control connection includes a `reconnect_token`.
rux does not accept that token to resume a control connection.

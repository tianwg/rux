#!/usr/bin/env bash
# Drive the real Rex CLI against the Rust server and report compatibility.
set -uo pipefail
cd "$(dirname "$0")/.."

SOCK="${RUX_SOCK:-/tmp/rux-compat.sock}"
BIN="target/debug/rux-server"
LOG="/tmp/rux-compat.log"
R=(rex -S "unix://$SOCK" --timeout 8s)
NET_PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
NR=(rex -S "127.0.0.1:$NET_PORT" --timeout 8s)
TLS_PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
PASS=0
FAIL=0
SERVER_PID=""
if [ -n "${RUX_STATE_DIR:-}" ]; then
  STATE_DIR="$RUX_STATE_DIR"
  CLEANUP_STATE=0
  mkdir -p "$STATE_DIR"
else
  STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rux-compat-state.XXXXXX")
  CLEANUP_STATE=1
fi
TLS_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rux-compat-tls.XXXXXX")
TLS_CERT="$TLS_DIR/cert.pem"
TLS_KEY="$TLS_DIR/key.pem"
CONFIG_FILE="$TLS_DIR/init.lua"
cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
  fi
  rm -rf "$TLS_DIR"
  if [ "$CLEANUP_STATE" -eq 1 ]; then rm -rf "$STATE_DIR"; fi
}
trap cleanup EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$TLS_KEY" -out "$TLS_CERT" -subj /CN=127.0.0.1 \
  -addext 'subjectAltName=IP:127.0.0.1' >/dev/null 2>&1
cat >"$CONFIG_FILE" <<'LUA'
rex.mode("resize", { exclusive = true })
rex.bind("ctrl+shift+p", "probe_action", { value = "bound" })
rex.bind("ctrl+shift+f", function(ctx, ev)
  return { handled = true, origin = ctx.origin, binding_id = ev.binding_id }
end)
rex.host { label = "declared-host", endpoint = "https://example.invalid" }
rex.action{
  name = "probe_action",
  title = "Probe action",
  args = { value = "string?" },
  run = function(ctx, args)
    local view, err = rex.session.view{}
    if not view then error(err) end
    local command, command_err = rex.exec({"printf", "lua-exec"})
    if not command then error(command_err) end
    rex.client.queue("pane.zoom", {})
    return { label = view.label, value = args.value, origin = ctx.origin, exec = command.stdout }
  end,
}
LUA
TR=(env SSL_CERT_FILE="$TLS_CERT" rex -S "https://127.0.0.1:$TLS_PORT" --timeout 8s)

cargo build -q || { echo "build failed"; exit 1; }
rm -f "$SOCK"
"$BIN" --listen "unix://$SOCK" --extra-listen "http://127.0.0.1:$NET_PORT" \
  --extra-listen "https://127.0.0.1:$TLS_PORT" --tls-cert "$TLS_CERT" \
  --tls-key "$TLS_KEY" --allow-anonymous --state-dir "$STATE_DIR" \
  --config "$CONFIG_FILE" >"$LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 100); do [ -S "$SOCK" ] && break; sleep 0.05; done
[ -S "$SOCK" ] || { echo "server did not start"; cat "$LOG"; exit 1; }
for _ in $(seq 1 100); do
  curl -fsS "http://127.0.0.1:$NET_PORT/api/help" >/dev/null 2>&1 && break
  sleep 0.05
done
for _ in $(seq 1 100); do
  curl -fsS --cacert "$TLS_CERT" "https://127.0.0.1:$TLS_PORT/api/help" >/dev/null 2>&1 && break
  sleep 0.05
done

check() {
  local name="$1"; shift
  if "$@" >/tmp/rux-check.out 2>/tmp/rux-check.err; then
    echo "PASS  $name"; PASS=$((PASS+1))
  else
    echo "FAIL  $name"; sed -n '1,3p' /tmp/rux-check.err | sed 's/^/      /'
    FAIL=$((FAIL+1))
  fi
}

check_json_output() {
  local name="$1" filter="$2" output="$3"
  if jq -e "$filter" >/dev/null 2>/tmp/rux-check.err <<<"$output"; then
    echo "PASS  $name"; PASS=$((PASS+1))
  else
    echo "FAIL  $name"; sed -n '1,3p' /tmp/rux-check.err | sed 's/^/      /'
    FAIL=$((FAIL+1))
  fi
}

check_json() {
  local name="$1" filter="$2"; shift 2
  local output
  if output=$("$@" 2>/tmp/rux-check.err); then
    check_json_output "$name" "$filter" "$output"
  else
    echo "FAIL  $name"; sed -n '1,3p' /tmp/rux-check.err | sed 's/^/      /'
    FAIL=$((FAIL+1))
  fi
}

contains() {
  local needle="$1"; shift
  # PTY startup and the shell's first prompt can race the command response.
  # Retry capture briefly rather than making this assertion timing-sensitive.
  local attempt
  for attempt in $(seq 1 10); do
    if "$@" >/tmp/rux-capture.out 2>/tmp/rux-check.err \
      && grep -q -- "$needle" /tmp/rux-capture.out; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

check "server.version"        "${R[@]}" api call server.version
check_json "remote HTTP principal" '.you.kind == "anonymous" and .you.transport == "tcp"' \
  "${NR[@]}" api call server.status
check_json "remote HTTP hosts" '.hosts|any(.label == "declared-host")' \
  "${NR[@]}" api call hosts.list
check_json "remote HTTPS principal" '.you.kind == "anonymous" and .you.transport == "tcp"' \
  "${TR[@]}" api call server.status
check "api list"              "${R[@]}" api list
check "api describe"          "${R[@]}" api describe session.new_split
check "session.create"        "${R[@]}" api call session.create \
  '{"label":"compat","initial_windows":[{"window_label":"main","layout":{"block":{"flavor":"com.superlogical.terminal.shell","label":"shell-1"}}}]}'
check "session.list"          "${R[@]}" api call session.list
check "session.view via -s"   "${R[@]}" api call -s compat session.view
check_json "Lua config keymap" \
  '(.bindings|any(.action == "probe_action")) and (.bindings|any(.action == "client.key.forward")) and (.actions|any(.name == "probe_action")) and (.modes|any(.name == "resize"))' \
  "${R[@]}" api call -s compat client.keymap
check_json "Lua custom client.action" \
  '.result.label == "compat" and .result.value == "works" and .result.origin == "api" and .result.exec == "lua-exec" and .client_actions[0].action == "pane.zoom"' \
  "${R[@]}" api call -s compat client.action \
  '{"action":"probe_action","args":{"value":"works"}}'
check_json "Lua function key binding" \
  '.result.handled == true and .result.binding_id == "key-0"' \
  "${R[@]}" api call client.action \
  '{"action":"client.key.forward","args":{"binding_id":"key-0"}}'
cat >>"$CONFIG_FILE" <<'LUA'
rex.bind("ctrl+shift+z", "probe_action", { value = "reloaded" })
LUA
check_json "server.config_reload" '.generation == 2 and .diagnostics == []' \
  "${R[@]}" api call server.config_reload
check_json "reloaded Lua keymap" \
  '(.bindings|any(.keys == ["ctrl+shift+z"]))' \
  "${R[@]}" api call -s compat client.keymap
ONBOARDING_JSON=$("${R[@]}" api call session.create \
  '{"label":"compat-onboarding","initial_windows":[{"window_label":"walkthrough","layout":{"block":{"flavor":"com.superlogical.onboarding.onboarding","label":"guide","options":{}}}}]}')
ONBOARDING_SID=$(jq -r '.session_id' <<<"$ONBOARDING_JSON")
ONBOARDING_BLOCK=$(jq -r '.initial_windows[0].block_ids[0]' <<<"$ONBOARDING_JSON")
check_json "onboarding state" '.generation == 0 and (.step // "") == ""' \
  "${R[@]}" api call -s compat-onboarding block.method \
  "$(jq -cn --arg b "$ONBOARDING_BLOCK" '{block_id:$b,method:"state",args:{}}')"
check_json "onboarding set_step" '.generation == 1 and .step == "welcome"' \
  "${R[@]}" api call -s compat-onboarding block.method \
  "$(jq -cn --arg b "$ONBOARDING_BLOCK" '{block_id:$b,method:"set_step",args:{step:"welcome"}}')"
check "onboarding session destroyed" "${R[@]}" api call -s compat-onboarding session.destroy
check_json "hosts.list includes config host" \
  '(.hosts|length == 1) and (.hosts[0].label == "declared-host")' \
  "${R[@]}" api call hosts.list
HOST_JSON=$("${R[@]}" api call hosts.put \
  '{"host":{"label":"compat-remote","endpoints":["http://127.0.0.1:45231"],"icon":"computer"}}')
check_json_output "hosts.put" '.host.id|startswith("host:")' "$HOST_JSON"
HOST_ID=$(jq -r '.host.id' <<<"$HOST_JSON")
check_json "hosts.list after put" '.hosts|length == 2' "${R[@]}" api call hosts.list
check_json "hosts.remove" '.removed == true' "${R[@]}" api call hosts.remove \
  "$(jq -cn --arg id "$HOST_ID" '{id:$id}')"
check_json "declared host remains after stored removal" \
  '(.hosts|length == 1) and (.hosts[0].label == "declared-host")' "${R[@]}" api call hosts.list
DECLARED_HOST_ID=$("${R[@]}" api call hosts.list | jq -r '.hosts[0].id')
check_json "hosts.remove hides declared host" '.removed == true' \
  "${R[@]}" api call hosts.remove "$(jq -cn --arg id "$DECLARED_HOST_ID" '{id:$id}')"
check_json "declared host is hidden" '.hosts == []' "${R[@]}" api call hosts.list
check_json "hosts.put restores declared host" \
  '.host.label == "declared-host"' "${R[@]}" api call hosts.put \
  "$(jq -cn --arg id "$DECLARED_HOST_ID" '{host:{id:$id,label:"declared-host",endpoints:["https://example.invalid"]}}')"
check_json "hosts.remove missing is safe" '.removed == false' \
  "${R[@]}" api call hosts.remove
check "client.perform/client.reply" env PYTHONDONTWRITEBYTECODE=1 REX_SOCKET="$SOCK" \
  python3 spec/tools/probe_perform.py
check "OSC 7501 program status" env PYTHONDONTWRITEBYTECODE=1 REX_SOCKET="$SOCK" \
  python3 spec/tools/probe_terminal_status.py
check "terminal data ticket" env PYTHONDONTWRITEBYTECODE=1 REX_SOCKET="$SOCK" \
  python3 spec/tools/probe_data_channel.py

# Exercise the newer layout and ownership methods through the real CLI's API
# command, using an isolated session so the basic CLI checks remain unchanged.
LAYOUT_SESSION_JSON=$("${R[@]}" api call session.create \
  '{"label":"compat-layout","initial_windows":[{"window_label":"main","layout":{"block":{"flavor":"com.superlogical.terminal.shell","label":"layout-a"}}}]}') || exit 1
LAYOUT_SID=$(jq -r '.session_id' <<<"$LAYOUT_SESSION_JSON")
LAYOUT_A=$(jq -r '.initial_windows[0].block_ids[0]' <<<"$LAYOUT_SESSION_JSON")
LAYOUT_W1=$(jq -r '.initial_windows[0].window_id' <<<"$LAYOUT_SESSION_JSON")
check "layout fixture created" test -n "$LAYOUT_SID"

NEW_SPLIT_ARGS=$(jq -cn --arg anchor "$LAYOUT_A" \
  '{anchor_id:$anchor,direction:"horizontal",side:"after",ratio:0,layout:{block:{flavor:"com.superlogical.terminal.shell",label:"layout-c"}}}')
NEW_SPLIT_JSON=$("${R[@]}" api call -s compat-layout session.new_split "$NEW_SPLIT_ARGS")
check_json_output "session.new_split (zero means half)" \
  '.block_ids|length == 1' "$NEW_SPLIT_JSON"
LAYOUT_C=$(jq -r '.block_ids[0]' <<<"$NEW_SPLIT_JSON")
check_json "new_split zero ratio geometry" \
  '.windows[0].layers[0].layout.split.ratio == 0.5' \
  "${R[@]}" api call -s compat-layout session.view
check_json "session.focus_direction" '.revision >= 1' "${R[@]}" api call -s compat-layout session.focus_direction \
  '{"direction":"right"}'
check_json "session.resize_pane" '.revision >= 1' "${R[@]}" api call -s compat-layout session.resize_pane \
  "$(jq -cn --arg a "$LAYOUT_A" --arg c "$LAYOUT_C" '{direction:"horizontal",before_block_id:$a,after_block_id:$c,ratio:0.35}')"
check_json "resize_pane geometry" '.windows[0].layers[0].layout.split.ratio == 0.35' \
  "${R[@]}" api call -s compat-layout session.view

NEW_BLOCK_JSON=$("${R[@]}" api call -s compat-layout session.new_block \
  '{"flavor":"com.superlogical.terminal.shell","label":"layout-b"}')
LAYOUT_B=$(jq -r '.block_id' <<<"$NEW_BLOCK_JSON")
check "session.new_block" test -n "$LAYOUT_B"
OUTPUT_BLOCK_JSON=$("${R[@]}" api call -s compat-layout session.new_block \
  '{"flavor":"com.superlogical.terminal.shell","label":"blob-output","options":{"command":["/bin/sh","-c","printf '"'"'RUX_BLOB_PAYLOAD'"'"'; sleep 30"]}}')
OUTPUT_BLOCK=$(jq -r '.block_id' <<<"$OUTPUT_BLOCK_JSON")
sleep 0.3
check_json "terminal list_dir" '.status == "ok" and (.entries|type == "array")' \
  "${R[@]}" api call -s compat-layout block.method \
  "$(jq -cn --arg b "$OUTPUT_BLOCK" '{block_id:$b,method:"list_dir",args:{path:"~",limit:5,files:true}}')"
check_json "terminal process snapshot" '.child.pid > 0 and .child.name != ""' \
  "${R[@]}" api call -s compat-layout block.method \
  "$(jq -cn --arg b "$OUTPUT_BLOCK" '{block_id:$b,method:"process",args:{}}')"
check_json "terminal set_theme" '. == {}' "${R[@]}" api call -s compat-layout block.method \
  "$(jq -cn --arg b "$OUTPUT_BLOCK" '{block_id:$b,method:"set_theme",args:{foreground:"#010203",background:"#040506",scheme:"dark"}}')"
check_json "terminal theme formatting" '.content|contains("color: rgb(1, 2, 3)")' \
  "${R[@]}" api call -s compat-layout block.method \
  "$(jq -cn --arg b "$OUTPUT_BLOCK" '{block_id:$b,method:"format",args:{format:"html"}}')"
FORMAT_JSON=$("${R[@]}" api call -s compat-layout block.method \
  "$(jq -cn --arg b "$OUTPUT_BLOCK" '{block_id:$b,method:"format",args:{format:"text",max_bytes:8}}')")
check_json_output "terminal format creates blob" '.id >= 1 and .eof == false' "$FORMAT_JSON"
BLOB_ID=$(jq -r '.id' <<<"$FORMAT_JSON")
check_json "terminal blob_read" '.total > 0 and (.data|type == "string")' \
  "${R[@]}" api call -s compat-layout block.method \
  "$(jq -cn --arg b "$OUTPUT_BLOCK" --argjson id "$BLOB_ID" '{block_id:$b,method:"blob_read",args:{id:$id,offset:0,max_bytes:512}}')"
check_json "session.move_block" '.created_split_id|startswith("split:")' \
  "${R[@]}" api call -s compat-layout session.move_block \
  "$(jq -cn --arg b "$LAYOUT_B" --arg a "$LAYOUT_A" '{block_id:$b,anchor_block_id:$a,direction:"horizontal",side:"before",ratio:0.25}')"
check_json "session.swap_blocks" '.revision >= 1' "${R[@]}" api call -s compat-layout session.swap_blocks \
  "$(jq -cn --arg a "$LAYOUT_B" --arg c "$LAYOUT_C" '{block_id:$a,other_block_id:$c}')"

FLOAT_JSON=$("${R[@]}" api call -s compat-layout session.float_block \
  "$(jq -cn --arg c "$LAYOUT_C" '{block_id:$c,bounds:[0.1,0.1,0.4,0.4]}')")
FLOAT_LAYER=$(jq -r '.layer_id' <<<"$FLOAT_JSON")
check "session.float_block" jq -e '.layer_id|startswith("layer:")' <<<"$FLOAT_JSON"
check_json "session.resize_layer" '.revision >= 1' "${R[@]}" api call -s compat-layout session.resize_layer \
  "$(jq -cn --arg l "$FLOAT_LAYER" '{layer_id:$l,bounds:[0.2,0.2,0.4,0.4]}')"

NEW_LAYER_JSON=$("${R[@]}" api call -s compat-layout session.new_layer \
  '{"bounds":[0.5,0.5,0.3,0.3],"layout":{"block":{"flavor":"com.superlogical.terminal.shell","label":"layout-d"}},"focus":false}')
NEW_LAYER=$(jq -r '.layer_id' <<<"$NEW_LAYER_JSON")
check_json "session.raise_layer" '.revision >= 1' "${R[@]}" api call -s compat-layout session.raise_layer \
  "$(jq -cn --arg l "$NEW_LAYER" --arg r "$FLOAT_LAYER" '{layer_id:$l,relative_layer_id:$r}')"
check_json "session.lower_layer" '.revision >= 1' "${R[@]}" api call -s compat-layout session.lower_layer \
  "$(jq -cn --arg l "$NEW_LAYER" --arg r "$FLOAT_LAYER" '{layer_id:$l,relative_layer_id:$r}')"
check_json "session.own_block" '.blocks|length == 1' "${R[@]}" api call -s compat-layout session.own_block \
  "$(jq -cn --arg b "$LAYOUT_B" '{block_ids:[$b],mode:"take"}')"
check_json "session.disown_block" '.blocks|length == 1' "${R[@]}" api call -s compat-layout session.disown_block \
  "$(jq -cn --arg b "$LAYOUT_B" '{block_ids:[$b]}')"
check_json "session.detach_block" '.revision >= 1' "${R[@]}" api call -s compat-layout session.detach_block \
  "$(jq -cn --arg b "$LAYOUT_C" '{block_id:$b}')"
NEW_WINDOW_JSON=$("${R[@]}" api call -s compat-layout session.new_window \
  '{"window_label":"layout-window-2","layout":{"block":{"flavor":"com.superlogical.terminal.shell","label":"layout-window-block"}},"focus":false}')
LAYOUT_W2=$(jq -r '.window_id' <<<"$NEW_WINDOW_JSON")
check_json "session.move_window before" '.revision >= 1' "${R[@]}" api call -s compat-layout session.move_window \
  "$(jq -cn --arg w "$LAYOUT_W2" --arg b "$LAYOUT_W1" '{window_id:$w,before_window_id:$b}')"
check_json "session.move_window to end" '.revision >= 1' "${R[@]}" api call -s compat-layout session.move_window \
  "$(jq -cn --arg w "$LAYOUT_W2" '{window_id:$w}')"
COMPAT_SID=$("${R[@]}" api call session.list | jq -r '.sessions[] | select(.label == "compat") | .session_id')
check_json "session.move before" '. == {}' "${R[@]}" api call -s compat-layout session.move \
  "$(jq -cn --arg sid "$COMPAT_SID" '{before_session_id:$sid}')"
check_json "session.move to end" '. == {}' "${R[@]}" api call -s compat-layout session.move
check "layout fixture destroyed" "${R[@]}" api call -s compat-layout session.destroy

check "rex ls"                "${R[@]}" ls
check "split"                 "${R[@]}" split -s compat -- /bin/sh -c 'echo split-ok; sleep 20'
check "run (new window)"      "${R[@]}" run -s compat -- /bin/sh -c 'echo run-ok; sleep 20'
check "send"                  "${R[@]}" send -b shell-1 'echo compat-$((40+2))'
check "send-key enter"        "${R[@]}" send-key -b shell-1 enter
sleep 0.8
check "capture sees output"   contains "compat-42" "${R[@]}" capture -b shell-1
check "session.destroy"       "${R[@]}" kill compat

if "${R[@]}" api call session.list 2>/dev/null | grep -q '"label":"compat"'; then
  echo "FAIL  session gone after kill"; FAIL=$((FAIL+1))
else
  echo "PASS  session gone after kill"; PASS=$((PASS+1))
fi

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]

#!/bin/bash
# Confirm rux-server is reachable on a Tailscale address and not on any
# public or non-tailnet address. Run on the host after install.sh.
set -euo pipefail

PORT="${RUX_PORT:-7297}"
# install.sh records the Serve port it chose (7443 when 443 is taken).
if [[ "${1:-}" != "--self-test" && -z "${RUX_HTTPS_PORT:-}" && -r /etc/rux/server.env ]]; then
  saved="$(grep -E '^RUX_HTTPS_PORT=[0-9]+$' /etc/rux/server.env | tail -n 1 | cut -d= -f2- || true)"
  if [[ -n "$saved" ]]; then
    RUX_HTTPS_PORT="$saved"
  fi
fi
HTTPS_PORT="${RUX_HTTPS_PORT:-443}"
IFACE="${RUX_TAILSCALE_IF:-tailscale0}"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
ok() { printf 'ok: %s\n' "$*"; }

is_tailscale_ip() {
  local ip="${1,,}"
  ip="${ip#[}"
  ip="${ip%]}"
  if [[ "$ip" == *:* ]]; then
    [[ "$ip" == fd7a:115c:a1e0:* ]]
    return
  fi
  local a b
  IFS=. read -r a b _ _ <<<"$ip"
  [[ "${a:-}" == "100" && "${b:-0}" -ge 64 && "${b:-0}" -le 127 ]]
}

# `ip route get <own tailnet ip>` on the node itself uses lo. The tailnet
# REJECT matches that packet unless install.sh allowed `-i lo -d <that ip>`.
arrives_on_loopback() {
  local route="$1"
  [[ "$route" == *" dev lo "* || "$route" == *" dev lo" ]]
}

if [[ "${1:-}" == "--self-test" ]]; then
  is_tailscale_ip 100.64.0.1
  is_tailscale_ip 100.127.255.255
  is_tailscale_ip fd7a:115c:a1e0::1
  is_tailscale_ip FD7A:115C:A1E0::abcd
  if is_tailscale_ip 100.63.255.255; then fail "100.63 was treated as tailscale"; fi
  if is_tailscale_ip 100.128.0.1; then fail "100.128 was treated as tailscale"; fi
  if is_tailscale_ip 0.0.0.0; then fail "0.0.0.0 was treated as tailscale"; fi
  if is_tailscale_ip 10.0.0.5; then fail "rfc1918 was treated as tailscale"; fi
  if is_tailscale_ip 127.0.0.1; then fail "loopback was treated as tailscale"; fi
  if is_tailscale_ip fd7a:115c:a1e1::1; then fail "wrong ula prefix"; fi
  arrives_on_loopback "local 100.64.1.2 dev lo src 100.64.1.2 uid 0"
  arrives_on_loopback "local 100.64.1.2 dev lo"
  if arrives_on_loopback "100.64.1.2 dev tailscale0 src 100.64.1.2"; then
    fail "tailscale0 route was treated as loopback"
  fi
  ok "address classification"
  exit 0
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
  command -v curl >/dev/null || fail "curl is required"
  command -v lsof >/dev/null || fail "lsof is required"
  pid="$(pgrep -x rux-server || true)"
  [[ -n "$pid" ]] || fail "rux-server is not running"
  cmdline="$(ps -p "${pid%% *}" -o args= || true)"
  [[ "$cmdline" == *"--tailnet-only"* ]] || fail "rux-server was not started with --tailnet-only: $cmdline"
  [[ "$cmdline" == *"tailnet://"* ]] || fail "rux-server has no tailnet:// listener: $cmdline"
  if [[ "$cmdline" == *"0.0.0.0"* || "$cmdline" == *"[::]"* || "$cmdline" == *"http://"* || "$cmdline" == *"https://"* ]]; then
    fail "rux-server command line exposes a public listener: $cmdline"
  fi
  ok "process command line is tailnet-only"
  found_port=0
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    found_port=1
    case "$line" in
      *":${PORT}"*"*:"*|*"*:${PORT}"*|*"0.0.0.0:${PORT}"*|*"[::]:${PORT}")
        fail "tcp/${PORT} is listening on ${line}"
        ;;
    esac
    ok "tcp/${PORT} listens on ${line}"
  done < <(lsof -nP -iTCP:"${PORT}" -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $9}')
  [[ "$found_port" == "1" ]] || fail "nothing is listening on tcp/${PORT}"
  if [[ -f /etc/pf.anchors/com.rux ]]; then
    ok "pf anchor com.rux is installed"
  else
    ok "no pf anchor; --tailnet-only is the lockdown because pf was not already enabled"
  fi
  ok "the application firewall is not used; it cannot limit a port to the Tailscale interface"
  cat <<EOF

Rux is bound to the tailnet. Also confirm the network firewall in front of
this Mac does not allow tcp/${PORT} from the public internet. A cloud
security list is one example: an Oracle Cloud VCN often allows only tcp/22.

EOF
  exit 0
fi

command -v ss >/dev/null || fail "ss is required (iproute2)"
command -v curl >/dev/null || fail "curl is required"

pid="$(pidof rux-server || true)"
[[ -n "$pid" ]] || fail "rux-server is not running"
cmdline="$(tr '\0' ' ' <"/proc/${pid%% *}/cmdline")"
[[ "$cmdline" == *"--tailnet-only"* ]] || fail "rux-server was not started with --tailnet-only: $cmdline"
[[ "$cmdline" == *"tailnet://"* ]] || fail "rux-server has no tailnet:// listener: $cmdline"
if [[ "$cmdline" == *"0.0.0.0"* || "$cmdline" == *"[::]"* || "$cmdline" == *"http://"* || "$cmdline" == *"https://"* ]]; then
  fail "rux-server command line exposes a public listener: $cmdline"
fi
ok "process command line is tailnet-only"

mapfile -t listeners < <(ss -H -lnt | awk '{print $4}')
found_port=0
for local_addr in "${listeners[@]}"; do
  case "$local_addr" in
    *":${PORT}") ;;
    *) continue ;;
  esac
  found_port=1
  host="${local_addr%:*}"
  if [[ "$local_addr" == \[*\]:* ]]; then
    host="${local_addr#\[}"
    host="${host%%\]*}"
  fi
  case "$host" in
    0.0.0.0|\*|::|"") fail "tcp/${PORT} is listening on ${local_addr}" ;;
  esac
  if ! is_tailscale_ip "$host"; then
    fail "tcp/${PORT} is listening on non-tailscale address ${local_addr}"
  fi
  ok "tcp/${PORT} listens on ${local_addr}"
done
[[ "$found_port" == "1" ]] || fail "nothing is listening on tcp/${PORT}"

# tcp/443 may belong to a public web server. That is fine: the installer
# leaves it alone. rux-server itself must not bind a public address.
if [[ "$HTTPS_PORT" != "$PORT" ]]; then
  https_seen=0
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    local_addr="$(awk '{print $4}' <<<"$line")"
    case "$local_addr" in
      *":${HTTPS_PORT}") ;;
      *) continue ;;
    esac
    https_seen=1
    host="${local_addr%:*}"
    if [[ "$local_addr" == \[*\]:* ]]; then
      host="${local_addr#\[}"
      host="${host%%\]*}"
    fi
    public=0
    case "$host" in
      0.0.0.0|\*|::|"") public=1 ;;
      *)
        if ! is_tailscale_ip "$host"; then
          public=1
        fi
        ;;
    esac
    if [[ "$public" == "1" && "$line" == *'"rux-server"'* ]]; then
      fail "rux-server is listening on public tcp/${HTTPS_PORT} (${local_addr})"
    fi
    if [[ "$public" == "1" ]]; then
      ok "tcp/${HTTPS_PORT} on ${local_addr} is not rux-server; the installer leaves that port alone"
    else
      ok "tcp/${HTTPS_PORT} listens on ${local_addr}"
    fi
  done < <(ss -H -lntp 2>/dev/null || true)
  if [[ "$https_seen" == "0" ]]; then
    ok "tcp/${HTTPS_PORT} has no listener (tailscale serve was not required)"
  fi
fi

if timeout 3 bash -c "echo >/dev/tcp/127.0.0.1/${PORT}" 2>/dev/null; then
  fail "tcp/${PORT} accepted a connection on 127.0.0.1"
fi
ok "tcp/${PORT} is closed on 127.0.0.1"

while read -r ip; do
  [[ -n "$ip" ]] || continue
  if is_tailscale_ip "$ip"; then
    continue
  fi
  if timeout 3 bash -c "echo >/dev/tcp/${ip}/${PORT}" 2>/dev/null; then
    fail "tcp/${PORT} accepted a connection on non-tailscale address ${ip}"
  fi
  ok "tcp/${PORT} is closed on ${ip}"
done < <(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1)

ts_ip="$(tailscale ip -4 2>/dev/null | head -n 1 || true)"
[[ -n "$ts_ip" ]] || fail "tailscale ip -4 returned nothing"
route="$(ip route get "$ts_ip" 2>/dev/null || true)"
help_body="$(mktemp)"
code="$(curl -sS -m 8 -o "$help_body" -w '%{http_code}' "http://${ts_ip}:${PORT}/api/help" || true)"
if [[ "$code" == "200" ]] && grep -q '"methods"' "$help_body"; then
  ok "http://${ts_ip}:${PORT}/api/help answered over the tailnet address"
elif arrives_on_loopback "$route"; then
  ok "skipped http://${ts_ip}:${PORT}/api/help on this machine: packets to its own tailnet address arrive on lo, not ${IFACE}. Re-run install.sh so it allows -i lo -d ${ts_ip}, or check from another tailnet device: curl -fsS http://${ts_ip}:${PORT}/api/help"
else
  fail "http://${ts_ip}:${PORT}/api/help returned ${code:-no response}: $(head -c 200 "$help_body")"
fi
rm -f "$help_body"

ok "local non-tailscale addresses were checked; this script does not query a cloud metadata service"

if iptables -S INPUT 2>/dev/null | grep -q rux-tailnet; then
  iptables -S INPUT | grep -q -- "-dport ${PORT}.*rux-tailnet.*REJECT" \
    || iptables -S INPUT | grep rux-tailnet | grep -q REJECT \
    || fail "iptables has rux-tailnet rules but no REJECT for the rux port"
  ok "iptables rejects the rux port off ${IFACE}"
elif command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw status verbose | grep -q rux-tailnet || fail "ufw is active but has no rux-tailnet rules"
  ok "ufw has rux-tailnet rules"
elif command -v nft >/dev/null && nft list table inet rux_tailnet >/dev/null 2>&1; then
  nft list table inet rux_tailnet | grep -q rux-tailnet \
    || fail "nftables table rux_tailnet has no rux-tailnet rules"
  ok "nftables rejects the rux ports off ${IFACE}"
elif systemctl is-active --quiet firewalld; then
  ok "firewalld is active; confirm rich rules reject ${PORT} except on ${IFACE}"
else
  fail "no iptables, nftables, ufw, or firewalld lockdown found"
fi

if command -v tailscale >/dev/null; then
  # `funnel status` with no config returns immediately. Bound it anyway so a
  # stuck tailscaled prompt cannot hang this check. `funnel off` is not run here.
  funnel="$(timeout 10 tailscale funnel status </dev/null 2>&1 || true)"
  if printf '%s' "$funnel" | grep -Eiq 'Funnel on|Available on the internet'; then
    fail "Tailscale Funnel looks enabled; turn it off with: sudo timeout 10 tailscale funnel off </dev/null"
  fi
  ok "Tailscale Funnel is not advertising a public URL"
fi

cat <<EOF

Rux is bound to the tailnet and closed on the addresses checked from this host.
Also confirm the cloud or edge firewall does not allow tcp/${PORT} from
0.0.0.0/0. A public website may keep tcp/443 open. For example, an Oracle
Cloud VCN security list often allows only tcp/22, and this script cannot
probe that list from outside the network.

EOF

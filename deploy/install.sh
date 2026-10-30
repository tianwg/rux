#!/bin/bash
# Install a personal rux-server so a Rex client can reach it only over Tailscale.
#
# Linux (systemd: Debian, Ubuntu, Fedora, RHEL, Arch, openSUSE) and macOS.
# The server runs as the invoking login account. Official Rex starts that
# personal server with `rex server start`; this kit keeps it running with a
# systemd user unit (Linux) or a launchd LaunchAgent (macOS).
#
#   sudo TS_AUTHKEY='tskey-auth-...' ./install.sh
#
# TS_AUTHKEY is read from the environment and is never written into the repo,
# the unit file, or /etc/rux. Do not run this script under `bash -x`.
set +x
set -euo pipefail
umask 077

PORT="${RUX_PORT:-7297}"
HTTPS_PORT="${RUX_HTTPS_PORT:-443}"
IFACE="${RUX_TAILSCALE_IF:-tailscale0}"
HOSTNAME_WANTED="${RUX_HOSTNAME:-}"
SKIP_FIREWALL="${RUX_SKIP_FIREWALL:-0}"
SKIP_SERVE="${RUX_SKIP_SERVE:-0}"
SKIP_HTTPS="${RUX_SKIP_HTTPS:-0}"
# Set by decide_https when tcp/$HTTPS_PORT must stay untouched.
SKIP_HTTPS_LOCK=0

log() { printf 'rux-install: %s\n' "$*"; }
die() { printf 'rux-install: %s\n' "$*" >&2; exit 1; }

# Official personal server runs as the invoking login account, not as a
# dedicated system user. RUX_USER wins. Otherwise this is SUDO_USER, which
# sudo sets to the account that ran sudo. Root is not that account.
select_login_user() {
  local user="${RUX_USER:-}"
  if [[ -z "$user" ]]; then
    user="${SUDO_USER:-}"
  fi
  if [[ -z "$user" || "$user" == "root" ]]; then
    return 1
  fi
  printf '%s\n' "$user"
}

# Ports that are accepted on the tailscale interface and rejected elsewhere.
# Equal ports produce one pair. A skipped HTTPS port is omitted, but the
# tailnet HTTP port is always included.
lock_ports() {
  printf '%s\n' "$PORT"
  if [[ "$HTTPS_PORT" != "$PORT" && "$SKIP_HTTPS_LOCK" != "1" ]]; then
    printf '%s\n' "$HTTPS_PORT"
  fi
}

# This node's own tailnet addresses. A curl to one of them from the host
# itself arrives on lo, not on the tailscale interface, so the public REJECT
# would fail that check. RUX_LOOPBACK_DESTS, when set (even empty), replaces
# the tailscale lookup. Pass 4 or 6 to select an address family.
loopback_dests() {
  local want="$1" line dest
  if [[ -z "${RUX_LOOPBACK_DESTS+x}" ]]; then
    command -v tailscale >/dev/null || return 0
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      if [[ "$want" == "6" && "$line" == *:* ]]; then
        printf '%s\n' "$line"
      elif [[ "$want" == "4" && "$line" != *:* ]]; then
        printf '%s\n' "$line"
      fi
    done < <({ tailscale ip -4 2>/dev/null || true; tailscale ip -6 2>/dev/null || true; })
    return 0
  fi
  # Intentional split: RUX_LOOPBACK_DESTS is a space-separated address list.
  # shellcheck disable=SC2086
  for dest in $RUX_LOOPBACK_DESTS; do
    if [[ "$want" == "6" && "$dest" == *:* ]]; then
      printf '%s\n' "$dest"
    elif [[ "$want" == "4" && "$dest" != *:* ]]; then
      printf '%s\n' "$dest"
    fi
  done
}

comma_dests() {
  local family="$1" dest joined=""
  while IFS= read -r dest; do
    [[ -n "$dest" ]] || continue
    if [[ -n "$joined" ]]; then
      joined+=","
    fi
    joined+="$dest"
  done < <(loopback_dests "$family")
  printf '%s' "$joined"
}

# Reads `ss -H -lntp` text in $2 and prints foreign, ours, or clear.
# foreign: a process other than rux-server/tailscaled owns the port, or a
# public bind has no process name (Caddy on *:443 with ss hiding the user).
classify_https_listeners() {
  python3 - "$1" "$2" <<'PY'
import re, sys
port, text = sys.argv[1], sys.argv[2]

def is_tailscale(host):
    host = host.strip("[]").lower()
    if host.startswith("fd7a:115c:a1e0:"):
        return True
    parts = host.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        a, b = int(parts[0]), int(parts[1])
        return a == 100 and 64 <= b <= 127
    return False

foreign = False
seen = False
for line in text.splitlines():
    parts = line.split()
    if len(parts) < 4:
        continue
    local = parts[3]
    if local.startswith("["):
        host, sep, listen_port = local[1:].rpartition("]:")
    else:
        host, sep, listen_port = local.rpartition(":")
    if sep == "" or listen_port != port:
        continue
    seen = True
    names = re.findall(r'\("([^"]+)"', line)
    bases = [name.rsplit("/", 1)[-1] for name in names]
    if not bases:
        if host in ("*", "0.0.0.0", "::", "") or not is_tailscale(host):
            foreign = True
        continue
    if any(base not in ("rux-server", "tailscaled") for base in bases):
        foreign = True
if foreign:
    print("foreign")
elif seen:
    print("ours")
else:
    print("clear")
PY
}

# Prints the port Tailscale Serve should use, or "skip".
# $1 requested HTTPS port, $2 the rux HTTP port, $3 `ss -H -lntp` text.
# A foreign listener (Caddy on :443) is left alone. Rex for Mac refuses plain
# HTTP, so Serve moves to the first free port in 7443, 8443, 9443.
choose_serve_port() {
  local requested="$1" http_port="$2" text="$3" kind alt
  kind="$(classify_https_listeners "$requested" "$text")"
  if [[ "$kind" != "foreign" ]]; then
    printf '%s\n' "$requested"
    return 0
  fi
  for alt in 7443 8443 9443; do
    [[ "$alt" == "$http_port" || "$alt" == "$requested" ]] && continue
    kind="$(classify_https_listeners "$alt" "$text")"
    if [[ "$kind" != "foreign" ]]; then
      printf '%s\n' "$alt"
      return 0
    fi
  done
  printf 'skip\n'
}

# True when `tailscale funnel status` shows a config. An empty reply or
# "No serve config" is not a config: `funnel off` then blocks on tailscale 1.102.
funnel_is_configured() {
  printf '%s\n' "$1" | grep -Eiq 'Funnel on|Available on the internet|https://'
}

https_url() {
  local dns="$1"
  if [[ "$HTTPS_PORT" == "443" ]]; then
    printf 'https://%s' "$dns"
  else
    printf 'https://%s:%s' "$dns" "$HTTPS_PORT"
  fi
}

# Bound a command. Linux has timeout(1). macOS does not, unless coreutils
# installed gtimeout.
run_timeout() {
  local secs="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$secs" "$@"
    return
  fi
  if command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$secs" "$@"
    return
  fi
  perl -e 'alarm shift @ARGV; exec @ARGV or die $!' "$secs" "$@"
}

# `tailscale funnel off` with no serve config waits forever on tailscale 1.102.4.
# Status is bounded, and the off commands run only when a config is present,
# each with a 10s cap and a closed stdin.
turn_funnel_off() {
  local status bin="${TAILSCALE_BIN:-tailscale}"
  status="$(run_timeout 10 "$bin" funnel status </dev/null 2>&1 || true)"
  if ! funnel_is_configured "$status"; then
    log "Tailscale Funnel has no config; skipping tailscale funnel off"
    return 0
  fi
  run_timeout 10 "$bin" funnel off </dev/null >/dev/null 2>&1 || true
  run_timeout 10 "$bin" funnel --https="${HTTPS_PORT}" off </dev/null >/dev/null 2>&1 || true
}

# debian, fedora, arch, suse, linux, or darwin. Pass an os-release path and
# a uname -s value to test it; the defaults are this machine.
os_family() {
  local release="${1:-/etc/os-release}" uname_s="${2:-$(uname -s)}"
  if [[ "$uname_s" == "Darwin" ]]; then
    printf 'darwin\n'
    return 0
  fi
  if [[ ! -r "$release" ]]; then
    printf 'linux\n'
    return 0
  fi
  local id id_like
  id="$(awk -F= '$1=="ID"{gsub(/"/,"",$2); print tolower($2)}' "$release")"
  id_like="$(awk -F= '$1=="ID_LIKE"{gsub(/"/,"",$2); print tolower($2)}' "$release")"
  case " $id $id_like " in
    *" debian "*|*" ubuntu "*|*" linuxmint "*|*" pop "*) printf 'debian\n' ;;
    *" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*) printf 'fedora\n' ;;
    *" arch "*|*" manjaro "*) printf 'arch\n' ;;
    *" suse "*|*" sles "*) printf 'suse\n' ;;
    *) printf 'linux\n' ;;
  esac
}

# ss(8) text, or the same shape built from lsof on macOS.
listener_text() {
  if command -v ss >/dev/null 2>&1; then
    ss -H -lntp 2>/dev/null || true
    return 0
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {
      cmd=$1; pid=$2; name=$9;
      if (name == "") next;
      printf "LISTEN 0 128 %s *:* users:((\"%s\",pid=%s,fd=3))\n", name, cmd, pid
    }'
    return 0
  fi
  return 0
}

# 443 stays untouched when another program owns it. Serve then uses the next
# free port so Rex for Mac still has an https:// URL. RUX_SKIP_HTTPS=1 skips
# both the lockdown and Serve even when 443 is free. RUX_PORT is still locked
# down when the two ports are the same number.
decide_https() {
  SKIP_HTTPS_LOCK=0
  if [[ "$HTTPS_PORT" == "$PORT" ]]; then
    return 0
  fi
  if [[ "$SKIP_HTTPS" == "1" ]]; then
    SKIP_HTTPS_LOCK=1
    SKIP_SERVE=1
    log "RUX_SKIP_HTTPS=1: not locking tcp/${HTTPS_PORT} and not running tailscale serve"
    return 0
  fi
  local text chosen requested
  requested="$HTTPS_PORT"
  text="$(listener_text)"
  chosen="$(choose_serve_port "$HTTPS_PORT" "$PORT" "$text")"
  if [[ "$chosen" == "skip" ]]; then
    SKIP_HTTPS_LOCK=1
    SKIP_SERVE=1
    log "WARNING: tcp/${requested} is in use, and 7443, 8443, and 9443 are in use too."
    log "Leaving tcp/${requested} unchanged and skipping tailscale serve."
    log "Rex for Mac refuses http:// hosts. Set RUX_HTTPS_PORT to a free port and rerun, or RUX_SKIP_HTTPS=1 to keep this skip."
    return 0
  fi
  if [[ "$chosen" != "$requested" ]]; then
    HTTPS_PORT="$chosen"
    log "WARNING: something other than rux already listens on tcp/${requested}."
    log "Leaving tcp/${requested} unchanged. Tailscale Serve will use tcp/${HTTPS_PORT}."
    log "Rex for Mac refuses plain HTTP. After Serve is healthy the app URL is https://<magicdns>:${HTTPS_PORT}"
  fi
}

apply_firewall() {
  local ports=() shown p
  while IFS= read -r p; do
    [[ -n "$p" ]] && ports+=("$p")
  done < <(lock_ports)
  shown="$(IFS=,; printf '%s' "${ports[*]}")"
  log "locking down tcp/${shown} to interface ${IFACE}"
  # Use the firewall that is already active: firewalld, ufw, nftables, or
  # iptables. Some images, including Oracle Cloud Ubuntu, restore
  # /etc/iptables/rules.v4 at boot, so that file is updated when it exists
  # even if another firewall is also active. A host with nftables.service
  # and no rules.v4 gets an inet table instead.
  local live=iptables
  if systemctl is-active --quiet firewalld; then
    apply_firewalld
    live=firewalld
  elif command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    apply_ufw
    live=ufw
  elif nftables_is_primary; then
    apply_nftables
    live=nft
  else
    apply_iptables
  fi
  # A saved rules.v4 wins at boot on images that restore it, even when ufw
  # or firewalld is also running.
  if [[ -f /etc/iptables/rules.v4 || -f /etc/iptables/rules.v6 ]]; then
    persist_iptables_file /etc/iptables/rules.v4 iptables
    persist_iptables_file /etc/iptables/rules.v6 ip6tables
    if systemctl list-unit-files netfilter-persistent.service >/dev/null 2>&1; then
      systemctl enable netfilter-persistent.service >/dev/null 2>&1 || true
    fi
  elif [[ "$live" == iptables ]]; then
    ensure_iptables_persistent
  fi
}

nftables_is_primary() {
  [[ ! -f /etc/iptables/rules.v4 && ! -f /etc/iptables/rules.v6 ]] || return 1
  command -v nft >/dev/null || return 1
  systemctl is-active --quiet nftables || systemctl is-enabled --quiet nftables
}

apply_iptables() {
  local bin port
  local ports=()
  while IFS= read -r port; do
    [[ -n "$port" ]] && ports+=("$port")
  done < <(lock_ports)
  for bin in iptables ip6tables; do
    command -v "$bin" >/dev/null || continue
    while "$bin" -S INPUT 2>/dev/null | grep -q -- '--comment rux-tailnet'; do
      local line
      line="$("$bin" -S INPUT | grep -F -- '--comment rux-tailnet' | head -n 1)"
      # shellcheck disable=SC2086
      "$bin" -D ${line#-A } || break
    done
    local family=4
    [[ "$bin" == "ip6tables" ]] && family=6
    local dests=() dest
    while IFS= read -r dest; do
      [[ -n "$dest" ]] && dests+=("$dest")
    done < <(loopback_dests "$family")
    for port in "${ports[@]}"; do
      "$bin" -I INPUT 1 -p tcp --dport "$port" ! -i "$IFACE" -m comment --comment rux-tailnet -j REJECT
      "$bin" -I INPUT 1 -p tcp --dport "$port" -i "$IFACE" -m comment --comment rux-tailnet -j ACCEPT
      for dest in "${dests[@]}"; do
        "$bin" -I INPUT 1 -p tcp --dport "$port" -i lo -d "$dest" -m comment --comment rux-tailnet -j ACCEPT
      done
    done
  done
}

ensure_iptables_persistent() {
  if ! command -v iptables >/dev/null; then
    log "iptables is not installed; skipping rules.v4 persistence"
    return 0
  fi
  if [[ "$(os_family)" != "debian" ]]; then
    log "this distribution does not use iptables-persistent. Live rules are installed; persist them with firewalld, nftables, or the host's iptables service."
    return 0
  fi
  if ! dpkg -s iptables-persistent >/dev/null 2>&1; then
    log "installing iptables-persistent so /etc/iptables/rules.v4 survives reboot"
    echo 'iptables-persistent iptables-persistent/autosave_v4 boolean false' | debconf-set-selections
    echo 'iptables-persistent iptables-persistent/autosave_v6 boolean false' | debconf-set-selections
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent
  fi
  install -d -m 0755 /etc/iptables
  if [[ ! -f /etc/iptables/rules.v4 ]]; then
    cat >/etc/iptables/rules.v4 <<'EOF'
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
EOF
  fi
  if [[ ! -f /etc/iptables/rules.v6 ]]; then
    cat >/etc/iptables/rules.v6 <<'EOF'
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
EOF
  fi
  persist_iptables_file /etc/iptables/rules.v4 iptables
  persist_iptables_file /etc/iptables/rules.v6 ip6tables
  systemctl enable netfilter-persistent.service >/dev/null 2>&1 || true
}

nft_dport_expr() {
  local ports=() port
  while IFS= read -r port; do
    [[ -n "$port" ]] && ports+=("$port")
  done < <(lock_ports)
  if [[ "${#ports[@]}" -eq 1 ]]; then
    printf '%s' "${ports[0]}"
    return 0
  fi
  local joined="${ports[0]}" port
  for port in "${ports[@]:1}"; do
    joined+=", ${port}"
  done
  printf '{ %s }' "$joined"
}

apply_nftables() {
  command -v nft >/dev/null || die "nftables is the firewall but nft is not installed"
  local dport
  dport="$(nft_dport_expr)"
  nft delete table inet rux_tailnet >/dev/null 2>&1 || true
  nft add table inet rux_tailnet
  nft add chain inet rux_tailnet input '{ type filter hook input priority -50; policy accept; }'
  local dest lo_rules=""
  while IFS= read -r dest; do
    [[ -n "$dest" ]] || continue
    if [[ "$dest" == *:* ]]; then
      # shellcheck disable=SC2086
      nft add rule inet rux_tailnet input iifname "lo" ip6 daddr "$dest" tcp dport ${dport} accept comment "rux-tailnet"
      lo_rules+="        iifname \"lo\" ip6 daddr ${dest} tcp dport ${dport} accept comment \"rux-tailnet\"
"
    else
      # shellcheck disable=SC2086
      nft add rule inet rux_tailnet input iifname "lo" ip daddr "$dest" tcp dport ${dport} accept comment "rux-tailnet"
      lo_rules+="        iifname \"lo\" ip daddr ${dest} tcp dport ${dport} accept comment \"rux-tailnet\"
"
    fi
  done < <(loopback_dests 4; loopback_dests 6)
  # shellcheck disable=SC2086
  nft add rule inet rux_tailnet input iifname "$IFACE" tcp dport ${dport} accept comment "rux-tailnet"
  # shellcheck disable=SC2086
  nft add rule inet rux_tailnet input tcp dport ${dport} reject comment "rux-tailnet"
  install -d -m 0755 /etc/nftables.d
  cat >/etc/nftables.d/rux-tailnet.nft <<EOF
table inet rux_tailnet {
    chain input {
        type filter hook input priority -50; policy accept;
${lo_rules}        iifname "${IFACE}" tcp dport ${dport} accept comment "rux-tailnet"
        tcp dport ${dport} reject comment "rux-tailnet"
    }
}
EOF
  chmod 0644 /etc/nftables.d/rux-tailnet.nft
  if [[ -f /etc/nftables.conf ]] && ! grep -q 'rux-tailnet.nft' /etc/nftables.conf; then
    printf '\ninclude "/etc/nftables.d/rux-tailnet.nft"\n' >>/etc/nftables.conf
  fi
  log "nftables table inet rux_tailnet installed (no /etc/iptables/rules.v4 on this host)"
}

persist_iptables_file() {
  local path="$1" bin="$2"
  [[ -f "$path" ]] || return 0
  if ! command -v "$bin" >/dev/null; then
    log "not persisting ${path}; ${bin} is not installed"
    return 0
  fi
  local list="" port
  while IFS= read -r port; do
    [[ -n "$port" ]] || continue
    if [[ -n "$list" ]]; then
      list+=","
    fi
    list+="$port"
  done < <(lock_ports)
  local family=4
  if [[ "$bin" == "ip6tables" || "$path" == *.v6 ]]; then
    family=6
  fi
  local dests
  dests="$(comma_dests "$family")"
  python3 - "$path" "$list" "$IFACE" "$dests" <<'PY'
import pathlib, sys
path, ports_text, iface, dests_text = sys.argv[1:]
file = pathlib.Path(path)
text = file.read_text()
kept = [line for line in text.splitlines() if "rux-tailnet" not in line]
ports = []
for port in ports_text.split(","):
    port = port.strip()
    if port and port not in ports:
        ports.append(port)
dests = []
for dest in dests_text.split(","):
    dest = dest.strip()
    if dest and dest not in dests and dest != "0.0.0.0" and dest != "::":
        dests.append(dest)
rules = []
for port in ports:
    for dest in dests:
        rules.append(
            f"-A INPUT -d {dest} -i lo -p tcp -m tcp --dport {port} -m comment --comment rux-tailnet -j ACCEPT"
        )
for port in ports:
    rules.append(
        f"-A INPUT -i {iface} -p tcp -m tcp --dport {port} -m comment --comment rux-tailnet -j ACCEPT"
    )
for port in ports:
    rules.append(
        f"-A INPUT ! -i {iface} -p tcp -m tcp --dport {port} -m comment --comment rux-tailnet -j REJECT"
    )
out = []
inserted = False
in_filter = False
for line in kept:
    if line.strip() == "*filter":
        in_filter = True
    elif line.strip().startswith("*"):
        in_filter = False
    if in_filter and not inserted and (
        line.startswith("-A INPUT -j REJECT")
        or line.startswith("-A INPUT -j DROP")
        or line.strip() == "COMMIT"
    ):
        out.extend(rules)
        inserted = True
    out.append(line)
if not inserted:
    out.extend(rules)
file.write_text("\n".join(out) + "\n")
PY
  chmod 0644 "$path"
  if [[ "$path" == /etc/iptables/* ]]; then
    log "updated $path so a boot-time restore keeps the tailnet lockdown"
  fi
}

apply_ufw() {
  while ufw status numbered | grep -q rux-tailnet; do
    local num
    num="$(ufw status numbered | grep rux-tailnet | head -n 1 | sed -n 's/^\[ *\([0-9][0-9]*\)\].*/\1/p')"
    [[ -n "$num" ]] || break
    ufw --force delete "$num"
  done
  local ports=() port index=1 dest
  while IFS= read -r port; do
    [[ -n "$port" ]] && ports+=("$port")
  done < <(lock_ports)
  local dests=()
  while IFS= read -r dest; do
    [[ -n "$dest" ]] && dests+=("$dest")
  done < <(loopback_dests 4; loopback_dests 6)
  for port in "${ports[@]}"; do
    for dest in "${dests[@]}"; do
      ufw --force insert "$index" allow in on lo to "$dest" port "$port" proto tcp comment rux-tailnet
      index=$((index + 1))
    done
  done
  for port in "${ports[@]}"; do
    ufw --force insert "$index" allow in on "$IFACE" to any port "$port" proto tcp comment rux-tailnet
    index=$((index + 1))
  done
  for port in "${ports[@]}"; do
    ufw --force insert "$index" reject to any port "$port" proto tcp comment rux-tailnet-public
    index=$((index + 1))
  done
  log "ufw rules installed. If this host also restores /etc/iptables/rules.v4 at boot, those rules are updated too."
}

apply_firewalld() {
  local ports=() port spec
  while IFS= read -r port; do
    [[ -n "$port" ]] && ports+=("$port")
  done < <(lock_ports)
  local dests4=() dests6=() dest
  while IFS= read -r dest; do
    [[ -n "$dest" ]] && dests4+=("$dest")
  done < <(loopback_dests 4)
  while IFS= read -r dest; do
    [[ -n "$dest" ]] && dests6+=("$dest")
  done < <(loopback_dests 6)
  for port in "${ports[@]}"; do
    for dest in "${dests4[@]}"; do
      firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" interface name=\"lo\" destination address=\"${dest}\" port port=\"${port}\" protocol=\"tcp\" accept" >/dev/null || true
    done
    for dest in "${dests6[@]}"; do
      firewall-cmd --permanent --add-rich-rule="rule family=\"ipv6\" interface name=\"lo\" destination address=\"${dest}\" port port=\"${port}\" protocol=\"tcp\" accept" >/dev/null || true
    done
    for spec in \
      "rule family=\"ipv4\" interface name=\"${IFACE}\" port port=\"${port}\" protocol=\"tcp\" accept" \
      "rule family=\"ipv6\" interface name=\"${IFACE}\" port port=\"${port}\" protocol=\"tcp\" accept"
    do
      firewall-cmd --permanent --add-rich-rule="$spec" >/dev/null || true
    done
  done
  for port in "${ports[@]}"; do
    for spec in \
      "rule family=\"ipv4\" port port=\"${port}\" protocol=\"tcp\" reject" \
      "rule family=\"ipv6\" port port=\"${port}\" protocol=\"tcp\" reject"
    do
      firewall-cmd --permanent --add-rich-rule="$spec" >/dev/null || true
    done
  done
  firewall-cmd --reload
  log "firewalld rich rules added for ${IFACE}"
}


if [[ "${1:-}" == "--self-test" ]]; then
  RUX_LOOPBACK_DESTS=""
  tmp="$(mktemp)"
  cat >"$tmp" <<'EOF'
*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
COMMIT
EOF
  persist_iptables_file "$tmp" iptables
  python3 - "$tmp" <<'PY'
import sys
lines = open(sys.argv[1]).read().splitlines()
reject = next(i for i, line in enumerate(lines) if line.startswith("-A INPUT -j REJECT"))
marks = [i for i, line in enumerate(lines) if "rux-tailnet" in line]
assert marks and max(marks) < reject, lines
assert any("dport 7297" in line and "-i tailscale0" in line and "ACCEPT" in line for line in lines)
assert any("! -i tailscale0" in line and "dport 7297" in line and "REJECT" in line for line in lines)
assert "0.0.0.0" not in "\n".join(lines)
PY
  persist_iptables_file "$tmp" iptables
  count="$(grep -c rux-tailnet "$tmp")"
  [[ "$count" == "4" ]]
  # Same port twice must stay one ACCEPT and one REJECT, including a second run.
  HTTPS_PORT="$PORT" persist_iptables_file "$tmp" iptables
  count="$(grep -c rux-tailnet "$tmp")"
  [[ "$count" == "2" ]]
  HTTPS_PORT="$PORT" persist_iptables_file "$tmp" iptables
  count="$(grep -c rux-tailnet "$tmp")"
  [[ "$count" == "2" ]]
  python3 - "$tmp" <<'PY'
import sys
lines = open(sys.argv[1]).read().splitlines()
marks = [line for line in lines if "rux-tailnet" in line]
assert len(marks) == 2, marks
assert sum("dport 7297" in line and "ACCEPT" in line for line in marks) == 1
assert sum("dport 7297" in line and "REJECT" in line for line in marks) == 1
assert not any("dport 443" in line for line in marks)
PY
  HTTPS_PORT=443 SKIP_HTTPS_LOCK=1 persist_iptables_file "$tmp" iptables
  count="$(grep -c rux-tailnet "$tmp")"
  [[ "$count" == "2" ]]
  caddy=$'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("caddy",pid=1,fd=3))'
  [[ "$(classify_https_listeners 443 "$caddy")" == "foreign" ]]
  bare=$'LISTEN 0 511 *:443 *:*'
  [[ "$(classify_https_listeners 443 "$bare")" == "foreign" ]]
  ours=$'LISTEN 0 128 100.64.1.2:443 0.0.0.0:* users:(("tailscaled",pid=2,fd=8))'
  [[ "$(classify_https_listeners 443 "$ours")" == "ours" ]]
  both=$'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("caddy",pid=1,fd=3))\nLISTEN 0 128 100.64.1.2:443 0.0.0.0:* users:(("tailscaled",pid=2,fd=8))'
  [[ "$(classify_https_listeners 443 "$both")" == "foreign" ]]
  [[ "$(classify_https_listeners 443 "")" == "clear" ]]
  [[ "$(nft_dport_expr)" == "{ 7297, 443 }" ]]
  HTTPS_PORT="$PORT"
  [[ "$(nft_dport_expr)" == "7297" ]]
  HTTPS_PORT=443
  SKIP_HTTPS_LOCK=0
  RUX_LOOPBACK_DESTS="100.64.1.2 fd7a:115c:a1e0::2"
  persist_iptables_file "$tmp" iptables
  count="$(grep -c rux-tailnet "$tmp")"
  [[ "$count" == "6" ]]
  python3 - "$tmp" <<'PY'
import sys
lines = [line for line in open(sys.argv[1]).read().splitlines() if "rux-tailnet" in line]
assert sum("-i lo" in line and "-d 100.64.1.2" in line and "ACCEPT" in line for line in lines) == 2, lines
assert not any("fd7a" in line for line in lines)
assert not any("0.0.0.0" in line for line in lines)
assert sum("! -i tailscale0" in line and "REJECT" in line for line in lines) == 2
PY
  HTTPS_PORT="$PORT"
  persist_iptables_file "$tmp" iptables
  count="$(grep -c rux-tailnet "$tmp")"
  [[ "$count" == "3" ]]
  python3 - "$tmp" <<'PY'
import sys
lines = [line for line in open(sys.argv[1]).read().splitlines() if "rux-tailnet" in line]
assert len(lines) == 3, lines
assert sum("-i lo" in line and "-d 100.64.1.2" in line and "dport 7297" in line for line in lines) == 1
assert sum("-i tailscale0" in line and "ACCEPT" in line for line in lines) == 1
assert sum("REJECT" in line for line in lines) == 1
PY
  RUX_LOOPBACK_DESTS=""
  caddy443=$'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("caddy",pid=1,fd=3))'
  [[ "$(choose_serve_port 443 7297 "$caddy443")" == "7443" ]]
  [[ "$(choose_serve_port 443 7297 "")" == "443" ]]
  ours443=$'LISTEN 0 128 100.64.1.2:443 0.0.0.0:* users:(("tailscaled",pid=2,fd=8))'
  [[ "$(choose_serve_port 443 7297 "$ours443")" == "443" ]]
  [[ "$(choose_serve_port 7443 7297 "$caddy443")" == "7443" ]]
  busy=$'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("caddy",pid=1,fd=3))\nLISTEN 0 4096 *:7443 *:*\nLISTEN 0 4096 *:8443 *:*'
  [[ "$(choose_serve_port 443 7297 "$busy")" == "9443" ]]
  taken7443=$'LISTEN 0 4096 *:7443 *:*'
  [[ "$(choose_serve_port 7443 7297 "$taken7443")" == "8443" ]]
  all_taken=$'LISTEN 0 4096 *:443 *:*\nLISTEN 0 4096 *:7443 *:*\nLISTEN 0 4096 *:8443 *:*\nLISTEN 0 4096 *:9443 *:*'
  [[ "$(choose_serve_port 443 7297 "$all_taken")" == "skip" ]]
  funnel_is_configured "" && exit 1
  funnel_is_configured "No serve config" && exit 1
  funnel_is_configured "Funnel is off" && exit 1
  funnel_is_configured $'# Funnel on:\nhttps://host.example.ts.net:7443'
  [[ "$(HTTPS_PORT=7443 https_url host.example.ts.net)" == "https://host.example.ts.net:7443" ]]
  [[ "$(HTTPS_PORT=443 https_url host.example.ts.net)" == "https://host.example.ts.net" ]]
  [[ "$(RUX_USER=alice SUDO_USER=ubuntu select_login_user)" == "alice" ]]
  [[ "$(RUX_USER= SUDO_USER=ubuntu select_login_user)" == "ubuntu" ]]
  if RUX_USER= SUDO_USER=root select_login_user >/dev/null; then
    echo "root was accepted as the personal account" >&2
    exit 1
  fi
  if RUX_USER= SUDO_USER= select_login_user >/dev/null; then
    echo "an empty account was accepted" >&2
    exit 1
  fi
  if RUX_USER=root select_login_user >/dev/null; then
    echo "RUX_USER=root was accepted" >&2
    exit 1
  fi
  osrel="$(mktemp)"
  printf 'ID=ubuntu\nID_LIKE=debian\n' >"$osrel"
  [[ "$(os_family "$osrel" Linux)" == "debian" ]]
  printf 'ID=fedora\n' >"$osrel"
  [[ "$(os_family "$osrel" Linux)" == "fedora" ]]
  printf 'ID=rhel\nID_LIKE="fedora"\n' >"$osrel"
  [[ "$(os_family "$osrel" Linux)" == "fedora" ]]
  printf 'ID=arch\n' >"$osrel"
  [[ "$(os_family "$osrel" Linux)" == "arch" ]]
  printf 'ID=opensuse-tumbleweed\nID_LIKE="opensuse suse"\n' >"$osrel"
  [[ "$(os_family "$osrel" Linux)" == "suse" ]]
  [[ "$(os_family "$osrel" Darwin)" == "darwin" ]]
  rm -f "$tmp" "$osrel"
  log "self-test ok"
  exit 0
fi

check_server_binary() {
  python3 - "$1" "$(uname -m)" <<'PY'
import struct, sys
path, want = sys.argv[1], sys.argv[2]
norm = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64", "amd64": "x86_64"}
def same(got):
    if norm.get(got, got) != norm.get(want, want):
        sys.exit(f"binary is {got} but this machine is {want}")
with open(path, "rb") as fh:
    data = fh.read(32)
if data[:4] == b"\x7fELF":
    machine = struct.unpack_from("<H", data, 18)[0]
    same({183: "aarch64", 62: "x86_64"}.get(machine, f"e_machine={machine}"))
elif data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
    endian = "<" if data[:4] == b"\xcf\xfa\xed\xfe" else ">"
    cputype = struct.unpack_from(endian + "I", data, 4)[0] & 0xFFFFFFFF
    same({0x01000007: "x86_64", 0x0100000C: "aarch64"}.get(cputype, f"cputype={cputype:#x}"))
elif data[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
    sys.exit(0)
else:
    sys.exit("rux-server is not an ELF or Mach-O binary")
PY
}

install_linux_packages() {
  local missing=0
  command -v python3 >/dev/null || missing=1
  command -v curl >/dev/null || missing=1
  if ! command -v iptables >/dev/null && ! command -v nft >/dev/null && ! command -v firewall-cmd >/dev/null; then
    missing=1
  fi
  [[ "$missing" == "0" ]] && return 0
  local family
  family="$(os_family)"
  log "installing python3, curl, and a firewall tool for ${family}"
  case "$family" in
    debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq python3 curl ca-certificates iptables iproute2
      ;;
    fedora)
      if command -v dnf >/dev/null; then
        dnf install -y python3 curl ca-certificates iptables iproute
      else
        yum install -y python3 curl ca-certificates iptables iproute
      fi
      ;;
    arch)
      pacman -Sy --noconfirm python curl ca-certificates iptables iproute2
      ;;
    suse)
      zypper --non-interactive install python3 curl ca-certificates iptables iproute2
      ;;
    *)
      die "install python3, curl, and iptables or nftables, then rerun"
      ;;
  esac
}

user_home() {
  local user="$1" home=""
  if command -v getent >/dev/null; then
    home="$(getent passwd "$user" | cut -d: -f6)"
  fi
  if [[ -z "$home" ]] && command -v dscl >/dev/null; then
    home="$(dscl . -read "/Users/${user}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
  fi
  printf '%s\n' "$home"
}

find_darwin_tailscale() {
  local candidate
  if command -v tailscale >/dev/null 2>&1; then
    command -v tailscale
    return 0
  fi
  for candidate in \
    /Applications/Tailscale.app/Contents/MacOS/Tailscale \
    /opt/homebrew/bin/tailscale \
    /usr/local/bin/tailscale
  do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

use_tailscale_bin() {
  TAILSCALE_BIN="$1"
  tailscale() { "$TAILSCALE_BIN" "$@"; }
}

sanitize_hostname() {
  local raw="${1:-rux}"
  python3 - "$raw" <<'PY'
import re, sys
text = sys.argv[1].strip().lower()
text = re.sub(r"[^a-z0-9-]+", "-", text).strip("-")[:63].strip("-")
print(text or "rux")
PY
}

ensure_tailscale_login() {
  if [[ -z "$HOSTNAME_WANTED" ]]; then
    HOSTNAME_WANTED="$(hostname -s 2>/dev/null || hostname)"
  fi
  HOSTNAME_WANTED="$(sanitize_hostname "$HOSTNAME_WANTED")"
  local state
  state="$(tailscale status --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("BackendState",""))' || true)"
  if [[ "$state" == "Running" ]]; then
    log "Tailscale is already running; leaving the existing login in place"
    return 0
  fi
  [[ -n "${TS_AUTHKEY:-}" ]] || die "Tailscale is not up. Export TS_AUTHKEY (an auth key from the Tailscale admin console) and rerun. The key is not stored in this repo."
  case "$TS_AUTHKEY" in
    *[[:space:]]*) die "TS_AUTHKEY must be a single token with no whitespace" ;;
  esac
  local keyfile
  keyfile="$(mktemp "${TMPDIR:-/tmp}/rux-authkey.XXXXXX")"
  trap 'rm -f "$keyfile"' EXIT
  printf '%s' "$TS_AUTHKEY" >"$keyfile"
  chmod 0600 "$keyfile"
  log "bringing Tailscale up as ${HOSTNAME_WANTED} (auth key is not logged)"
  if tailscale up --help 2>&1 | grep -q -- '--auth-key-file'; then
    tailscale up --ssh=false --accept-dns=true --hostname="$HOSTNAME_WANTED" --auth-key-file="$keyfile"
  else
    tailscale up --ssh=false --accept-dns=true --hostname="$HOSTNAME_WANTED" --auth-key="$TS_AUTHKEY"
  fi
  rm -f "$keyfile"
  trap - EXIT
  unset TS_AUTHKEY
  state="$(tailscale status --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("BackendState",""))' || true)"
  [[ "$state" == "Running" ]] || die "tailscale did not reach Running (state=${state:-unknown}). Finish login with 'sudo tailscale up' and rerun."
}

read_tailscale_identity() {
  {
    IFS= read -r ts_dns
    IFS= read -r ts_tags
  } < <(tailscale status --json | python3 -c '
import json, sys
st = json.load(sys.stdin)
self = st.get("Self") or {}
dns = (self.get("DNSName") or "").rstrip(".")
tags = self.get("Tags") or []
print(dns)
print(",".join(tags))
')
  allow_identified="${RUX_TAILNET_ALLOW_IDENTIFIED:-}"
  if [[ -z "$allow_identified" ]]; then
    if [[ -n "$ts_tags" ]]; then
      allow_identified=true
      log "node is tagged (${ts_tags}); tagged nodes have no owner, so peers tailscaled can identify are admitted. Restrict them with tailnet ACLs."
    else
      allow_identified=false
      log "node is user-owned; only that Tailscale user can connect"
    fi
  fi
}

apply_pf() {
  if [[ "$SKIP_FIREWALL" == "1" ]]; then
    log "RUX_SKIP_FIREWALL=1: not changing pf"
    return 0
  fi
  if ! command -v pfctl >/dev/null; then
    log "pfctl is absent. --tailnet-only is the lockdown. The application firewall is unchanged."
    return 0
  fi
  if ! pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
    log "pf is not enabled. Not turning it on, and not changing the application firewall. --tailnet-only refuses public binds."
    return 0
  fi
  local ts_ip iface="" port list=""
  ts_ip="$(tailscale ip -4 2>/dev/null | head -n 1 || true)"
  if [[ -n "$ts_ip" ]]; then
    iface="$(route -n get "$ts_ip" 2>/dev/null | awk '/interface:/{print $2}')"
  fi
  if [[ -z "$iface" ]]; then
    log "could not find the Tailscale interface; not changing pf"
    return 0
  fi
  while IFS= read -r port; do
    [[ -n "$port" ]] || continue
    if [[ -n "$list" ]]; then
      list+=", "
    fi
    list+="$port"
  done < <(lock_ports)
  install -d -m 0755 /etc/pf.anchors
  cat >/etc/pf.anchors/com.rux <<EOF
# Personal rux-server: the tailnet interface may connect. Other interfaces may not.
pass in quick on ${iface} proto tcp to any port { ${list} }
block in quick proto tcp to any port { ${list} }
EOF
  chmod 0644 /etc/pf.anchors/com.rux
  if [[ -f /etc/pf.conf ]] && ! grep -q 'anchor "com.rux"' /etc/pf.conf; then
    cp /etc/pf.conf /etc/pf.conf.rux-orig
    printf '\n# rux-tailnet\nanchor "com.rux"\nload anchor "com.rux" from "/etc/pf.anchors/com.rux"\n' >>/etc/pf.conf
  fi
  if pfctl -f /etc/pf.conf; then
    log "pf anchor com.rux loaded on ${iface}"
  else
    log "pfctl rejected the ruleset; restoring /etc/pf.conf"
    if [[ -f /etc/pf.conf.rux-orig ]]; then
      cp /etc/pf.conf.rux-orig /etc/pf.conf
      pfctl -f /etc/pf.conf || true
    fi
  fi
}

install_darwin() {
  command -v python3 >/dev/null || die "python3 is required. Install it from python.org or Homebrew, then rerun."
  check_server_binary "$bin_src"
  local tsbin
  tsbin="$(find_darwin_tailscale)" || die "Install Tailscale.app (https://tailscale.com/download) or Homebrew tailscale (brew install tailscale), then rerun. The Linux Tailscale installer is not used on macOS."
  use_tailscale_bin "$tsbin"
  log "using Tailscale CLI ${TAILSCALE_BIN}"
  ensure_tailscale_login
  read_tailscale_identity
  RUX_LOGIN_USER="$(select_login_user)" || die "refusing to install the personal server as root. Run sudo ./install.sh from the login account (sudo sets SUDO_USER), or set RUX_USER to that account."
  id "$RUX_LOGIN_USER" >/dev/null 2>&1 || die "login user ${RUX_LOGIN_USER} does not exist"
  RUX_LOGIN_UID="$(id -u "$RUX_LOGIN_USER")"
  RUX_LOGIN_GID="$(id -g "$RUX_LOGIN_USER")"
  RUX_LOGIN_HOME="$(user_home "$RUX_LOGIN_USER")"
  [[ -n "$RUX_LOGIN_HOME" && -d "$RUX_LOGIN_HOME" ]] || die "login user ${RUX_LOGIN_USER} has no home directory"
  log "personal server account is ${RUX_LOGIN_USER}; terminals run as that user"
  install -d -o root -g wheel -m 0755 /usr/local/bin /usr/local/share/doc/rux /etc/rux || install -d -m 0755 /usr/local/bin /usr/local/share/doc/rux /etc/rux
  install -m 0755 "$bin_src" /usr/local/bin/rux-server
  install -m 0644 "$here/README.md" /usr/local/share/doc/rux/README.md
  local runtime="${RUX_LOGIN_HOME}/Library/Application Support/rux/run"
  local state="${RUX_LOGIN_HOME}/.local/state/rex"
  install -d -o "$RUX_LOGIN_USER" -g "$RUX_LOGIN_GID" -m 0750 \
    "${RUX_LOGIN_HOME}/Library/Application Support/rux" \
    "$runtime" \
    "${RUX_LOGIN_HOME}/Library/LaunchAgents" \
    "${RUX_LOGIN_HOME}/Library/Logs" \
    "${RUX_LOGIN_HOME}/.local" \
    "${RUX_LOGIN_HOME}/.local/state" \
    "$state"
  decide_https
  umask 022
  {
    if [[ "$allow_identified" == "1" || "$allow_identified" == "true" ]]; then
      printf 'RUX_TAILNET_ALLOW_IDENTIFIED=true\n'
    else
      printf 'RUX_TAILNET_ALLOW_IDENTIFIED=false\n'
    fi
    if [[ "$SKIP_SERVE" != "1" ]]; then
      printf 'RUX_HTTPS_PORT=%s\n' "$HTTPS_PORT"
    fi
    printf 'RUX_USER=%s\n' "$RUX_LOGIN_USER"
  } >/etc/rux/server.env
  chmod 0644 /etc/rux/server.env
  umask 077
  local plist="${RUX_LOGIN_HOME}/Library/LaunchAgents/com.rux.server.plist"
  local serve="${runtime}/rex/serve.sock"
  local identified="false" login_shell
  [[ "$allow_identified" == "1" || "$allow_identified" == "true" ]] && identified="true"
  login_shell="$(dscl . -read "/Users/${RUX_LOGIN_USER}" UserShell 2>/dev/null | awk '{print $2}')"
  [[ -n "$login_shell" ]] || login_shell="/bin/zsh"
  cat >"$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.rux.server</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/rux-server</string>
    <string>--personal</string>
    <string>--extra-listen</string>
    <string>tailnet://:${PORT}</string>
    <string>--extra-listen</string>
    <string>tailnet-serve://${serve}</string>
    <string>--tailnet-only</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>${RUX_LOGIN_HOME}</string>
    <key>USER</key>
    <string>${RUX_LOGIN_USER}</string>
    <key>SHELL</key>
    <string>${login_shell}</string>
    <key>XDG_RUNTIME_DIR</key>
    <string>${runtime}</string>
    <key>XDG_STATE_HOME</key>
    <string>${RUX_LOGIN_HOME}/.local/state</string>
    <key>RUX_TAILNET_ALLOW_IDENTIFIED</key>
    <string>${identified}</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${RUX_LOGIN_HOME}/Library/Logs/rux-server.log</string>
  <key>StandardErrorPath</key>
  <string>${RUX_LOGIN_HOME}/Library/Logs/rux-server.log</string>
</dict>
</plist>
EOF
  chown "$RUX_LOGIN_USER:$RUX_LOGIN_GID" "$plist"
  chmod 0644 "$plist"
  local domain="gui/${RUX_LOGIN_UID}"
  launchctl bootout "${domain}/com.rux.server" >/dev/null 2>&1 || true
  launchctl bootstrap "$domain" "$plist" || launchctl load -w "$plist"
  launchctl enable "${domain}/com.rux.server" >/dev/null 2>&1 || true
  launchctl kickstart -k "${domain}/com.rux.server" >/dev/null 2>&1 || true
  apply_pf
  if [[ "$SKIP_SERVE" != "1" ]]; then
    local ready=0
    for _ in $(seq 1 40); do
      if [[ -S "$serve" ]]; then
        ready=1
        break
      fi
      sleep 1
    done
    if [[ "$ready" == "1" ]]; then
      turn_funnel_off
      if ! tailscale serve --bg --https="${HTTPS_PORT}" "unix:${serve}"; then
        tailscale serve --bg --https="${HTTPS_PORT}" "unix://${serve}" \
          || log "tailscale serve did not start; use the http:// tailnet URL below."
      fi
    else
      log "serve socket did not appear; the tailnet HTTP listener is still the supported path"
    fi
  fi
  local ts_ip app_url
  ts_ip="$(tailscale ip -4 | head -n 1 || true)"
  log "installed. rux-server runs as ${RUX_LOGIN_USER} and listens on Tailscale addresses only."
  log "terminals open as ${RUX_LOGIN_USER}. socket ${runtime}/rex/server.sock, state ${state}"
  if [[ -n "$ts_dns" && "$SKIP_SERVE" != "1" ]]; then
    app_url="$(https_url "$ts_dns")"
    log "Rex for Mac: ${app_url}"
    log "rex CLI (HTTPS, after Serve is healthy): rex -S ${app_url}"
    log "save the host: rex hosts add remote '${app_url}'"
  fi
  if [[ -n "$ts_dns" ]]; then
    log "rex CLI (tailnet HTTP): rex -S http://${ts_dns}:${PORT}"
  fi
  if [[ -n "$ts_ip" ]]; then
    log "rex CLI (tailnet IP, no MagicDNS): rex -S http://${ts_ip}:${PORT}"
  fi
  log "LaunchAgent: launchctl print ${domain}/com.rux.server"
  log "Run ./verify-tailnet.sh before relying on it."
}

if [[ "$(id -u)" -ne 0 ]]; then
  exec sudo --preserve-env=TS_AUTHKEY,RUX_PORT,RUX_HTTPS_PORT,RUX_TAILSCALE_IF,RUX_HOSTNAME,RUX_BIN,RUX_SKIP_FIREWALL,RUX_SKIP_SERVE,RUX_SKIP_HTTPS,RUX_TAILNET_ALLOW_IDENTIFIED,RUX_USER \
    "$0" "$@"
fi

here="$(cd "$(dirname "$0")" && pwd)"
bin_src="${RUX_BIN:-$here/rux-server}"
[[ -f "$bin_src" ]] || die "missing rux-server binary (set RUX_BIN or place it next to install.sh)"

if [[ "$(uname -s)" == "Darwin" ]]; then
  install_darwin
  exit 0
fi

if [[ ! -d /run/systemd/system ]]; then
  die "this Linux install needs systemd (Debian, Ubuntu, Fedora, RHEL, Arch, openSUSE). Official Rex also documents OpenRC on Alpine; this kit does not install OpenRC scripts."
fi
install_linux_packages
check_server_binary "$bin_src"

if ! command -v tailscale >/dev/null || ! systemctl cat tailscaled.service >/dev/null 2>&1; then
  log "installing Tailscale from the official installer"
  curl -fsSL https://tailscale.com/install.sh | sh
fi
systemctl enable --now tailscaled
use_tailscale_bin "$(command -v tailscale)"

ensure_tailscale_login
read_tailscale_identity

RUX_LOGIN_USER="$(select_login_user)" || die "refusing to install the personal server as root. Run sudo ./install.sh from the login account (sudo sets SUDO_USER), or set RUX_USER to that account."
id "$RUX_LOGIN_USER" >/dev/null 2>&1 || die "login user ${RUX_LOGIN_USER} does not exist"
RUX_LOGIN_UID="$(id -u "$RUX_LOGIN_USER")"
RUX_LOGIN_GID="$(id -g "$RUX_LOGIN_USER")"
RUX_LOGIN_HOME="$(user_home "$RUX_LOGIN_USER")"
[[ -n "$RUX_LOGIN_HOME" && -d "$RUX_LOGIN_HOME" ]] || die "login user ${RUX_LOGIN_USER} has no home directory"
log "personal server account is ${RUX_LOGIN_USER} (uid ${RUX_LOGIN_UID}); terminals run as that user"

# A previous kit ran a system unit as the dedicated user rux. Stop it and
# leave /var/lib/rux in place. host-id is copied below when the personal
# state directory does not already have one.
if [[ -f /etc/systemd/system/rux-server.service ]] || systemctl cat rux-server.service >/dev/null 2>&1; then
  systemctl disable --now rux-server.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/rux-server.service
  rm -rf /etc/systemd/system/rux-server.service.d
  systemctl daemon-reload || true
  log "stopped the old system rux-server unit"
fi
if id rux >/dev/null 2>&1; then
  log "the rux system account is no longer used by the personal server; it was not removed"
fi

install -d -o root -g root -m 0755 /etc/rux /usr/local/share/doc/rux /usr/lib/systemd/user
install -m 0755 "$bin_src" /usr/local/bin/rux-server
install -m 0644 "$here/README.md" /usr/local/share/doc/rux/README.md
install -m 0644 "$here/rux-server.service" /usr/lib/systemd/user/rux-server.service
# Optional modes. They are not enabled. rex.service and
# rex-login-server.service conflict because both want /run/rex.
install -m 0644 "$here/rex.service" /etc/systemd/system/rex.service
install -m 0644 "$here/rex-login-server.service" /etc/systemd/system/rex-login-server.service
if ! id rex >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/rex --create-home --shell /usr/sbin/nologin --user-group rex \
    || log "could not create the rex user for the optional shared server"
  log "optional shared server user rex has a nologin shell. Before enabling rex.service, run: usermod --shell /bin/bash rex"
fi
if [[ ! -e /etc/pam.d/rex-login-server && -f "$here/rex-login-server.pam" ]]; then
  install -m 0644 "$here/rex-login-server.pam" /etc/pam.d/rex-login-server
fi
if [[ ! -e /etc/rex/accounts.jsonc ]]; then
  install -d -m 0755 /etc/rex
  printf '%s\n' '{' '  "version": 1,' '  "accounts": {}' '}' >/etc/rex/accounts.jsonc
  chmod 0644 /etc/rex/accounts.jsonc
fi
if [[ -x "$here/rux-tsnet" ]]; then
  install -m 0755 "$here/rux-tsnet" /usr/local/bin/rux-tsnet
fi
if [[ "$PORT" != "7297" ]]; then
  sed -i "s#tailnet://:7297#tailnet://:${PORT}#" /usr/lib/systemd/user/rux-server.service
fi
RUX_STATE_DIR="${RUX_LOGIN_HOME}/.local/state/rex"
if [[ ! -d "${RUX_LOGIN_HOME}/.local" ]]; then
  install -d -o "$RUX_LOGIN_USER" -g "$RUX_LOGIN_GID" -m 0755 "${RUX_LOGIN_HOME}/.local"
fi
if [[ ! -d "${RUX_LOGIN_HOME}/.local/state" ]]; then
  install -d -o "$RUX_LOGIN_USER" -g "$RUX_LOGIN_GID" -m 0755 "${RUX_LOGIN_HOME}/.local/state"
fi
install -d -o "$RUX_LOGIN_USER" -g "$RUX_LOGIN_GID" -m 0750 "$RUX_STATE_DIR"
if [[ -d /var/lib/rux ]]; then
  for name in host-id hosts.json; do
    if [[ -f "/var/lib/rux/${name}" && ! -e "${RUX_STATE_DIR}/${name}" ]]; then
      install -o "$RUX_LOGIN_USER" -g "$RUX_LOGIN_GID" -m 0600 "/var/lib/rux/${name}" "${RUX_STATE_DIR}/${name}"
      log "copied ${name} from /var/lib/rux to ${RUX_STATE_DIR}"
    fi
  done
  log "previous state remains at /var/lib/rux and is not the personal server state directory"
fi

OLD_RUX_USER=""
if [[ -f /etc/rux/server.env ]]; then
  OLD_RUX_USER="$(grep -E '^RUX_USER=' /etc/rux/server.env | tail -n 1 | cut -d= -f2- || true)"
fi

decide_https
umask 022
{
  if [[ "$allow_identified" == "1" || "$allow_identified" == "true" ]]; then
    printf 'RUX_TAILNET_ALLOW_IDENTIFIED=true\n'
  else
    printf 'RUX_TAILNET_ALLOW_IDENTIFIED=false\n'
  fi
  if [[ "$SKIP_SERVE" != "1" ]]; then
    printf 'RUX_HTTPS_PORT=%s\n' "$HTTPS_PORT"
  fi
  printf 'RUX_USER=%s\n' "$RUX_LOGIN_USER"
} >/etc/rux/server.env
chmod 0644 /etc/rux/server.env
umask 077

added_tailscale_group=0
if getent group tailscale >/dev/null; then
  if ! id -nG "$RUX_LOGIN_USER" | tr ' ' '\n' | grep -qx tailscale; then
    usermod -aG tailscale "$RUX_LOGIN_USER" && added_tailscale_group=1 || true
  fi
fi
tailscale set --operator="$RUX_LOGIN_USER" >/dev/null 2>&1 \
  || log "could not set tailscale operator to ${RUX_LOGIN_USER}; LocalAPI whois still works when the socket is accessible"

if [[ "$SKIP_FIREWALL" != "1" ]]; then
  # shellcheck source=firewall.sh
  # The lockdown lives in this file so a partial copy of the kit still applies it.
  apply_firewall
fi

# Linger so the user manager, and this personal server, come back at boot
# without an interactive login. A system unit with User= would not get
# XDG_RUNTIME_DIR or the login environment.
loginctl enable-linger "$RUX_LOGIN_USER"
systemctl start "user@${RUX_LOGIN_UID}.service"
if [[ "$added_tailscale_group" == "1" ]]; then
  # The user manager reads groups at start. Restart it once so the new
  # tailscale group is visible to rux-server.
  systemctl restart "user@${RUX_LOGIN_UID}.service" || true
fi
runtime="/run/user/${RUX_LOGIN_UID}"
for _ in $(seq 1 50); do
  [[ -d "$runtime" ]] && break
  sleep 0.1
done
[[ -d "$runtime" ]] || die "linger did not create ${runtime}"
SERVE_SOCK="${runtime}/rex/serve.sock"
run_user_systemctl() {
  if systemctl --user --machine="${RUX_LOGIN_USER}@" "$@"; then
    return 0
  fi
  sudo -u "$RUX_LOGIN_USER" env \
    XDG_RUNTIME_DIR="$runtime" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=${runtime}/bus" \
    systemctl --user "$@"
}
systemctl daemon-reload
run_user_systemctl daemon-reload
run_user_systemctl enable rux-server
# enable --now does not restart a unit that is already running, so an upgrade
# would keep the previous rux-server process and the old binary.
run_user_systemctl restart rux-server
if [[ -n "${OLD_RUX_USER}" && "${OLD_RUX_USER}" != "${RUX_LOGIN_USER}" ]]; then
  systemctl --user --machine="${OLD_RUX_USER}@" disable --now rux-server >/dev/null 2>&1 \
    || log "could not disable the personal server previously enabled for ${OLD_RUX_USER}"
fi

if [[ "$SKIP_SERVE" != "1" ]]; then
  ready=0
  for _ in $(seq 1 40); do
    if [[ -S "$SERVE_SOCK" ]]; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "$ready" == "1" ]]; then
    # Serve is tailnet-only. Turn Funnel off so the HTTPS port cannot become public.
    # The socket is mode 0600 under the login user's runtime dir. tailscaled
    # runs as root and can connect; the server accepts only uid 0.
    turn_funnel_off
    if ! tailscale serve --bg --https="${HTTPS_PORT}" "unix:${SERVE_SOCK}"; then
      tailscale serve --bg --https="${HTTPS_PORT}" "unix://${SERVE_SOCK}" \
        || log "tailscale serve did not start; use the http:// tailnet URL below. Enable HTTPS certificates in the tailnet admin console and rerun."
    fi
  else
    log "serve socket did not appear; the tailnet HTTP listener is still the supported path"
  fi
fi

ts_ip="$(tailscale ip -4 | head -n 1 || true)"
log "installed. rux-server runs as ${RUX_LOGIN_USER} and listens on Tailscale addresses only."
log "terminals open as ${RUX_LOGIN_USER}. socket ${runtime}/rex/server.sock, state ${RUX_STATE_DIR}"
if [[ -n "$ts_dns" && "$SKIP_SERVE" != "1" ]]; then
  app_url="$(https_url "$ts_dns")"
  log "Rex for Mac: ${app_url}"
  log "rex CLI (HTTPS, after Serve is healthy): rex -S ${app_url}"
  log "save the host: rex hosts add remote '${app_url}'"
  log "In Rex for Mac: Add Remote Host… and paste ${app_url}"
fi
if [[ -n "$ts_dns" ]]; then
  log "rex CLI (tailnet HTTP): rex -S http://${ts_dns}:${PORT}"
fi
if [[ -n "$ts_ip" ]]; then
  log "rex CLI (tailnet IP, no MagicDNS): rex -S http://${ts_ip}:${PORT}"
fi
if [[ "$SKIP_SERVE" == "1" ]]; then
  log "Tailscale Serve was not configured. Rex for Mac refuses plain http:// hosts."
  log "Set RUX_HTTPS_PORT to a free port and rerun install.sh to get an https:// URL."
fi
log "Run ./verify-tailnet.sh before relying on it."
log "Cloud firewall: keep tcp/${PORT} closed from 0.0.0.0/0. A public website may keep tcp/443 open; this install does not require it. For example, an Oracle Cloud VCN security list often allows only tcp/22."

# Install rux-server on Linux or macOS

This kit installs `rux-server` so a real Rex client can use it as a remote
host, and so the server is reachable only over Tailscale.

The default service uses the machine's `tailscaled`, which is what the stock
Rex server does for its `tailnet://` and `tailnet-serve://` listeners. An
optional `rux-tsnet` sidecar (built-in Tailscale) is a second device. The
default service does not pass `--tailscale`, and `rux-server` does not spawn
the sidecar in that mode. Re-running `install.sh` restarts `rux-server`
so the new binary replaces the running process.

Official Rex publishes `.deb`, `.rpm`, and Alpine packages, plus a tarball
for other distributions, and runs the personal server as the login account.
This kit is that personal server: a systemd user unit on Linux, or a
launchd LaunchAgent on macOS. Shared (`rex.service`) and login
(`rex-login-server.service`) units are installed on Linux and not enabled.
The install path is a systemd host. Cloud images that restore iptables at boot need the rules saved, which the installer does.

## How the Rex client connects

On the host the server listens in two tailnet-only ways:

| Listener | Bind | Identity | Client URL |
|---|---|---|---|
| `tailnet://:7297` | This node's Tailscale IPs only (`100.64.0.0/10` and `fd7a:115c:a1e0::/48`). `0.0.0.0` and `::` are refused. | tailscaled LocalAPI `whois` on the TCP peer | `http://<dns>:7297` |
| `tailnet-serve://$XDG_RUNTIME_DIR/rex/serve.sock` | Unix socket mode `0600` in the login user's runtime directory. Only root (`tailscaled`) is accepted. | `X-Forwarded-For` plus whois, or `Tailscale-User-Login`. `Tailscale-Funnel-Request` is refused. | `https://<dns>` after `tailscale serve` |

`<dns>` is the node's MagicDNS name, such as `host.tail1234.ts.net`.
Tailscale encrypts the path. The HTTP listener is plain HTTP on purpose:
that is the Rex tailnet-address mode. Do not publish that port on a public
address.

From a Mac or another machine on the same tailnet:

```sh
rex -S http://host.tail1234.ts.net:7297 ls
rex hosts add remote http://host.tail1234.ts.net:7297
rex -S remote new demo
```

When `tailscale serve` is healthy and the tailnet has HTTPS certificates
turned on, the client can use the shorter URL. When another program such
as Caddy is already listening on tcp/443, the installer leaves that port
alone and moves Serve to 7443, then 8443, then 9443. A bare hostname tries
HTTPS on port 443, then HTTPS on 7297, then HTTP on 7297:

```sh
rex -S https://host.tail1234.ts.net ls
rex -S host.tail1234.ts.net ls
```

In Rex for Mac, choose **Add Remote Host…** and paste one of those URLs.
`rex hosts` is CLI-only today and does not sync to the GUI.

If MagicDNS is off, use the tailnet IPv4 address from `tailscale ip -4`:

```sh
rex -S http://100.x.y.z:7297 ls
```

Who may connect:

- Default: only the Tailscale user who owns this node (the same user id `whois` reports for the node).
- A tagged node has no owner. The installer turns on `--tailnet-allow-identified`, which admits any peer Tailscale can identify. Lock that down with tailnet ACLs. Tagged clients get no Serve identity headers; they use `http://<dns>:7297`, where whois still works.
- Tailscale Funnel is refused. Do not enable it.

The stock `rex` CLI has no bearer-token flag. Whois replaces that header.

## Install

Pick the tarball for the machine. A dynamically linked Linux build needs
the glibc it was linked against and `libpam.so.0` for the login server.
A static musl binary cannot open the distro's PAM library. macOS builds
are LaunchAgents for the login account and are produced on a Mac: build
`rux-server`, place it next to `install.sh`, and use the macOS commands below.

Debian or Ubuntu (the linux-aarch64 tarball is the usual ARM64 image; use
`rux-linux-x86_64.tar.gz` on x86_64):

```sh
sudo apt-get update
sudo apt-get install -y curl ca-certificates python3
tar -xzf rux-linux-aarch64.tar.gz
cd rux-linux-aarch64
sudo TS_AUTHKEY='tskey-auth-...' ./install.sh
sudo ./verify-tailnet.sh
```

Fedora, RHEL, CentOS, Rocky, or Alma:

```sh
sudo dnf install -y curl ca-certificates python3
tar -xzf rux-linux-x86_64.tar.gz
cd rux-linux-x86_64
sudo TS_AUTHKEY='tskey-auth-...' ./install.sh
sudo ./verify-tailnet.sh
```

Arch or Manjaro (`python` is the package name; the command is `python3`):

```sh
sudo pacman -Sy --noconfirm curl ca-certificates python
tar -xzf rux-linux-x86_64.tar.gz
cd rux-linux-x86_64
sudo TS_AUTHKEY='tskey-auth-...' ./install.sh
sudo ./verify-tailnet.sh
```

macOS (Tailscale.app or Homebrew `tailscale` already installed; python3 from
python.org or Homebrew). The personal server is a LaunchAgent for the login
account, not a system daemon:

```sh
tar -xzf rux-macos-aarch64.tar.gz
cd rux-macos-aarch64
sudo TS_AUTHKEY='tskey-auth-...' ./install.sh
./verify-tailnet.sh
```

On an Intel Mac use `rux-macos-x86_64.tar.gz` the same way. openSUSE uses
`sudo zypper install curl ca-certificates python3` and the matching Linux
tarball. The installer detects the distro and the firewall that is already
active (iptables, nftables, ufw, or firewalld).

Create the auth key in the Tailscale admin console (Settings → Keys). It is
read from `TS_AUTHKEY` and is not written to the git repo, the systemd unit,
or `/etc/rux`. Do not run the installer under `bash -x`.

Optional environment variables:

| Variable | Meaning |
|---|---|
| `RUX_HOSTNAME` | Tailscale device name. Default: this host's short name. |
| `RUX_PORT` | Tailnet HTTP port. Default `7297`, which is what `rex` probes. |
| `RUX_HTTPS_PORT` | Port for `tailscale serve`. Default `443`. When that port is already taken, Serve moves to 7443, then 8443, then 9443, and the Rex app URL includes the port. When this equals `RUX_PORT`, the firewall installs one rule pair. |
| `RUX_TAILNET_ALLOW_IDENTIFIED` | `true` or `false`. Default: `true` only when the node is tagged. |
| `RUX_SKIP_SERVE` | `1` skips `tailscale serve`. The `rex` CLI can still use HTTP on 7297. Rex for Mac refuses that URL. |
| `RUX_SKIP_HTTPS` | `1` skips both the HTTPS lockdown and `tailscale serve`, even when 443 is free. |
| `RUX_SKIP_FIREWALL` | `1` skips the host firewall. Not recommended. |
| `RUX_USER` | Login account the personal server runs as. Default: `SUDO_USER`. Root is refused. |

Re-running `install.sh` is safe. If Tailscale is already logged in, the auth
key is not required.

Useful checks after install:

```sh
systemctl --user --machine="$(id -un)@" status rux-server
tailscale ip -4
journalctl --user --machine="$(id -un)@" -u rux-server -n 50 --no-pager
```

`id -un` above is the account that ran `sudo ./install.sh`. The user
manager is that account's, not root's. On macOS, the same account is the
LaunchAgent: `launchctl print gui/$(id -u)/com.rux.server`.

The journal prints the exact `rex -S` commands once the tailnet addresses
are bound.

## Firewall

`rux-server --tailnet-only` will not bind `0.0.0.0`, `::`, or any address
outside the Tailscale ranges. The host firewall is a second lock:

- **iptables / ip6tables**: accept tcp/7297 on `tailscale0`
  and reject it on every other interface. A curl from this machine to its
  own tailnet address arrives on `lo`, so the installer also accepts
  `-i lo -d <that address>` for the locked ports. It does not accept
  `0.0.0.0/0` or `127.0.0.1`. tcp/443 gets the same pair only
  when nothing else is already listening there. A public Caddy or nginx on
  `*:443` is left alone. Tailscale Serve then uses the next free port
  (7443, then 8443, then 9443), that port is locked down, and the installer
  prints `https://<magicdns>:7443` for Rex for Mac, which refuses plain HTTP.
  `RUX_SKIP_HTTPS=1` skips Serve even when 443 is free. Setting
  `RUX_HTTPS_PORT` equal to `RUX_PORT` installs one ACCEPT and one REJECT,
  not two copies. Rules are marked `rux-tailnet`. On current Ubuntu the
  `iptables` command is iptables-nft; the saved text format is still
  `/etc/iptables/rules.v4`.
- Some images restore `/etc/iptables/rules.v4` (and `rules.v6`) at
  boot. Oracle Cloud Ubuntu is one example (iptables-persistent or
  netfilter-persistent). The installer inserts
  the same rules into those files, ahead of the image's
  `-A INPUT -j REJECT` line, and does not dump Tailscale's live chains over
  the file. It still updates the file when ufw or firewalld is the live
  firewall, because the image loads `rules.v4` again at boot.
- If that file is missing and nftables is not the firewall, the installer
  installs `iptables-persistent` (without saving the current live ruleset)
  and writes a minimal `rules.v4` / `rules.v6` that only adds the rux rules.
- **ufw**, if it is already active, gets matching allow/reject rules.
  `ufw status verbose` shows the `rux-tailnet` comment.
- **firewalld**, if it is active, gets rich rules for the same policy.
- **nftables.service**, only when it is enabled and `/etc/iptables/rules.v4`
  does not exist: table `inet rux_tailnet` plus
  `/etc/nftables.d/rux-tailnet.nft`. A host that already has
  `/etc/iptables/rules.v4` is not this case.

Outbound HTTPS (package installs, Tailscale coordination) is not blocked.
SSH on tcp/22 is not modified.

### Cloud firewall

Binding to `100.x` and rejecting the port on the public NIC does not change
the cloud network. Leave the security group closed for tcp/7297 from
`0.0.0.0/0`. A public website may keep tcp/443 open. For example, an Oracle
Cloud VCN security list often allows only tcp/22; do not add tcp/7297 there.
`verify-tailnet.sh` checks from inside the host. If the on-host curl to the
node's own tailnet address is rejected
because it arrives on `lo`, the script says so and asks for a check from
another tailnet device instead of reporting a false failure. It cannot see
a security list that would allow the port from the internet if the process
were later bound to a public address.

## What the service runs

The default is a personal server, the official "just you" mode. It is a
systemd **user** unit (`/usr/lib/systemd/user/rux-server.service`) enabled
for the login account that invoked `sudo` (`SUDO_USER`, or `RUX_USER`).
`loginctl enable-linger` brings that user manager back at boot. Official
`rex` starts this mode with `rex server start` rather than a unit; the
unit is how this kit keeps that same account running after reboot. It does
not pass `--exit-empty`.

An upgrade stops and disables a previous system `rux-server.service` (the
old dedicated `rux` user). It copies `host-id` and `hosts.json` from
`/var/lib/rux` into `~/.local/state/rex` when those files are missing
there, and leaves the rest of `/var/lib/rux` in place. The `rux` account
is not deleted and nothing starts as it.

```text
rux-server \
  --personal \
  --extra-listen tailnet://:7297 \
  --extra-listen tailnet-serve://%t/rex/serve.sock \
  --tailnet-only
```

`%t` is the login account's runtime directory, usually
`/run/user/<uid>`. The server socket is `$XDG_RUNTIME_DIR/rex/server.sock`.
State is `~/.local/state/rex`. Terminals run as that user, with that
user's shell (`$SHELL`, otherwise the passwd shell). The Serve socket is
mode `0600`. `tailscaled` runs as root and can connect; any other uid is
dropped. The login account is set as the Tailscale operator so LocalAPI
whois works. Who may connect is still the tailnet node owner, not the OS
user name.

`/etc/rux/server.env` may set `RUX_TAILNET_ALLOW_IDENTIFIED=true` and
records `RUX_USER`. It does not contain an auth key. Remote Rex clients
use the tailnet URLs above.

`server.tailscale.enable` runs only when `rux-tsnet` is installed beside
`rux-server`. The default unit does not call it. Sign the machine in with
`tailscale up`. Do not put a Tailscale auth key in the unit or `/etc/rux`.

## Optional modes

`install.sh` also installs, and does not enable:

- `rex.service` — shared server as user and group `rex`, socket
  `/run/rex/server.sock` mode `0660`, state `/var/lib/rex`. The unit is
  not sandboxed. The `rex` account is created with a nologin shell; set a
  real shell (`usermod --shell /bin/bash rex`) before enabling it, or its
  terminals exit immediately.
- `rex-login-server.service` — root login server. It reads
  `/etc/rex/accounts.jsonc`, opens a PAM login session for the chosen
  account, and proxies each connection to a server running as that
  account. On a machine with systemd-logind that server is the account's
  personal server. `--pam=false` checks `/etc/shadow` and opens no
  session. The two units conflict because both use `/run/rex`.

Leave both disabled. The tailnet-only personal user unit (Linux) or
LaunchAgent (macOS) is what `install.sh` enables. On macOS the runtime
directory is `~/Library/Application Support/rux/run`, because there is no
`/run/user/<uid>`. The socket is still `$XDG_RUNTIME_DIR/rex/server.sock`
and state is still `~/.local/state/rex`. Tailscale.app and Homebrew
`tailscaled` are both accepted; the server searches their LocalAPI sockets.

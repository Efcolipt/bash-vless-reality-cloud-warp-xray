# VPN on 3x-ui

## Install

As root on a fresh Debian 12/13 or Ubuntu 24.04 server.

**Node**, a VPN server. Point the domain's A record at the server first:

```bash
apt-get update && apt-get install -y git && git clone --depth 1 https://github.com/Efcolipt/bash-vless-reality-cloud-warp-xray.git /opt/vpn && /opt/vpn/install.sh node vpn.example.com "ssh-ed25519 AAAA... you@laptop"
```

**Bridge**, a node in Russia in front of a node abroad (see [Bridge](#bridge-in-russia)). The exit link is a
VLESS REALITY (TCP) link of a client on the exit node:

```bash
apt-get update && apt-get install -y git && git clone --depth 1 https://github.com/Efcolipt/bash-vless-reality-cloud-warp-xray.git /opt/vpn && /opt/vpn/install.sh bridge ru.example.com "vless://…@exit-ip:443?security=reality&…" "ssh-ed25519 AAAA... you@laptop"
```

**Head**, one subscription for several nodes (optional, on its own small server):

```bash
apt-get update && apt-get install -y git && git clone --depth 1 https://github.com/Efcolipt/bash-vless-reality-cloud-warp-xray.git /opt/vpn && /opt/vpn/install.sh head "ssh-ed25519 AAAA... you@laptop"
```

**After a server's IP changes**, on the node and against the head:

```bash
sudo /opt/vpn/install.sh share-address <old ip> <new ip>
XUI_API_TOKEN=<head token> /opt/vpn/install.sh share-address <old ip> <new ip> <head panel url>
```

The SSH key is optional. With it the server gets a new sudo user on a random port, and root and password logins
stop working; the new access line is printed at once and kept in `/root/vpn-ssh.txt`. Without it SSH stays as it is.

The install runs as a systemd unit and the terminal only follows `/root/vpn-install.log`, so a dropped SSH session
does not stop it: read the log from the hoster's console or after logging in again.

Optional variables, set before the command (`HYSTERIA_BANDWIDTH=12500000 /opt/vpn/install.sh node …`):

| Variable | Default | Meaning |
|---|---|---|
| `HYSTERIA_BANDWIDTH` | `125000000` (1 Gbit/s) | Hysteria2 brutal sends at exactly this rate in bytes per second: set the server's real bandwidth. |
| `XRAY_VERSION` | `v26.11.9` | Xray core the panel runs. |
| `XUI_ACME_EMAIL` | none | Email for Let's Encrypt notices. |
| `SSH_USER`, `SSH_PORT` | random | The new SSH user and port, so you know them before the session that started the install drops. |

## What a node gets

| Port | What |
|---|---|
| 443/tcp | VLESS + REALITY + Vision, the fastest profile. |
| 11849/tcp | VLESS + XHTTP + REALITY, for networks that cut long TCP sessions. |
| 11274/udp, 20000–50000/udp | Hysteria2 with salamander obfuscation; clients hop over the range. |
| random/tcp | 3x-ui panel, HTTPS. |
| 2096/tcp | Subscription, HTTPS. |
| 80/tcp | Let's Encrypt renewals. |

- **Self-steal REALITY.** REALITY borrows the TLS handshake of the server's own site: Caddy serves a decoy page on
  127.0.0.1 with the domain's certificate, for any SNI. Clients send the server's domain as SNI, it resolves to this
  server, and a prober that is not a client gets the decoy site.
- **One client, three profiles.** All inbounds share the client `admin` and one subscription; the subscription
  hands out the server's IP, not its domain.
- **Client auto-setup.** The subscription carries split routing from
  [RoscomVPN](https://github.com/hydraponique/roscomvpn-routing), which the panel refreshes in the background:
  Russian sites go direct from the user's device, YouTube, Telegram and GitHub through the VPN, ads are blocked.
  Happ gets it as a header (plus autoconnect to the fastest server, local networks and Apple push outside the
  tunnel), Incy as an autorouting profile, Clash/Mihomo inside the YAML, JSON subscriptions embedded.
- **Routing on the server**, in order: private addresses and BitTorrent blocked; `anthropic.com`, `claude.ai`,
  `statsig.com`, `sentry.io`, `githubusercontent.com` direct (before the ad filter, which contains
  `statsig.anthropic.com`); ads blocked; OpenAI through Cloudflare WARP, because it refuses many hosting
  addresses; sites blocked in Russia direct; Russian sites through WARP, because many of them refuse foreign
  hosting addresses. Spotify, Reddit, NVIDIA and others stay direct: through WARP they time out or stall.
  WARP dials Cloudflare's IPv4 endpoint: by name the core can pick the AAAA, which never answers.
- **System.** BBR with fq and buffers sized for QUIC, an nftables firewall that drops everything but SSH and the
  ports above, fail2ban on SSH, Xray pinned to `XRAY_VERSION`, Russian geodata refreshed every night at 04:00
  Moscow time (a refresh restarts the core, so it runs when nobody is online).

## Several nodes behind a head

1. Install the head with the command above.
2. On the head: **Nodes → Add**, with the node's panel address `XUI_ACCESS_URL` and its API token
   `XUI_API_TOKEN`, both from `/etc/x-ui/install-result.env` on the node.
3. Manage clients and the nodes' inbounds on the head from then on: the head keeps its own copy of each inbound,
   and an edit made on the node never reaches the subscription.

The head's address is in every user's subscription link, so keep it off the servers that carry traffic.

## Bridge in Russia

Some providers block the address of a foreign server for their subscribers within days. A bridge is a node on a
Russian server: users connect to its domestic address, Russian sites leave from it directly (and see a Russian
address), and everything else, sites blocked in Russia included, goes on to the exit node over VLESS REALITY.
The exit keeps its own routing (WARP, exceptions); only the bridge's address is in user subscriptions.

1. On the exit node, add a client for the bridge on the VLESS REALITY (TCP) inbound and copy its link.
2. Install the bridge with that link (see [Install](#install)) and attach it to the head like any node.
3. Attach the users to the bridge's inbounds. Keep their exit profiles too: where the exit is not blocked,
   clients that pick the fastest server use it directly.

Check from the bridge that the exit answers before moving users: some Russian data centers filter foreign
addresses too.

## Clients

Since Xray 26.9.8, REALITY refuses a ClientHello without an X25519MLKEM768 key share
([XTLS/Xray-core#7259](https://github.com/XTLS/Xray-core/issues/7259)): clients need a current core and the
`chrome` fingerprint. The failure looks like `reality verification failed` or `received real certificate` on the
client, and the server logs nothing.

- **Happ**, **v2rayNG**: current versions work with all three profiles.
- **Throne**: 1.4.5 or newer — 1.4.2 and older run a sing-box fork that strips X25519MLKEM768 whatever the
  fingerprint. In **Preset Settings → TLS → Default Fingerprint** choose `chrome` (Throne's own fingerprint
  overrides the subscription); turn the DNS cache on (optimistic, persistent); MTU 1400; mux off; log level warn.
  Throne updates have reset these settings before.
- **Hiddify, NekoBox, Karing, sing-box**: sing-box 1.14.5 / 1.15.0-alpha.14 or newer (sing-box stripped the key
  share until 14.11.2026). Until then they keep Hysteria2, which is not REALITY.
- **mihomo**: `support-x25519mlkem768: true` under `reality-opts`.

## When users cannot connect

**Check the Xray version first.** A panel update replaces the core with the newest one. Set it back in the
panel: **Overview → Xray → change version**.

**Then check whether the IP is blocked.** In Russia blocks hit addresses, not protocols: a blocked IP does not
answer even the TCP handshake from the affected provider, so changing SNI, protocol or port does not help. Signs:
the node answers from abroad and other users stay connected, while every connection from the affected network
times out. Then:

1. Get a new IP from the hoster, from another /24: whole subnets get blocked.
2. Point the domain's A record at it.
3. Run `share-address` on the node and against the head (see [Install](#install)).
4. Users refresh their subscription; clients with auto-update do it themselves.

A Cloudflare CDN in front of the node does not help in Russia: since June 2025 the large providers cut
connections to Cloudflare addresses after about 16 KB.

## Pitfalls

- **Domain in the subscription.** TUN clients resolve it through the tunnel they are building, hang for
  10 seconds and drop connections at random. The subscription hands out the IP.
- **DNS over HTTPS by name.** Xray resolves the DoH server's name through itself and loops. The template pins
  `dns.adguard-dns.com` in `dns.hosts`; `https://<ip>/dns-query` fails the certificate check.
- **Policy timeouts.** The default `uplinkOnly: 2` and `downlinkOnly: 5` cut downloads, streaming and XHTTP. The
  template sets both to 0.
- **`domainStrategy: IPIfNonMatch`** resolves every domain for the rules and pins a single CPU. The template uses
  `AsIs`.
- **Mux** breaks Vision. XHTTP's `xmux` is a different thing and needs `hKeepAlivePeriod` above 0.
- **Restarting x-ui** drops every connection.

To remove the panel: `x-ui uninstall`.

## Layout

| Path | What |
|---|---|
| `install.sh` | Entry point: `node`, `bridge`, `head`, `share-address`, `update-geodata`. |
| `lib/system.sh` | Packages, kernel tuning, SSH, firewall, fail2ban. |
| `lib/panel.sh` | 3x-ui install and API: Xray core, WARP or bridge routing, inbounds, subscription, geodata, share address. |
| `lib/decoy.sh` | Caddy decoy site for self-steal REALITY. |
| `config/xray-template.json` | Routing, DNS, policy and outbounds; the WARP outbound is added at install. |
| `config/sysctl.conf` | Kernel network settings. |
| `config/caddy/Caddyfile` | Decoy site on 127.0.0.1. |
| `config/decoy/index.html` | Decoy page. |
| `config/sub-theme/index.html` | Subscription page: status, usage, one-tap import into Happ, v2rayNG, Hiddify and Clash, the link with a copy button; Russian or English by the browser. Title, announcement and support link come from the panel settings. |

# VPN node on 3x-ui

Scripts that set up a VPN server the way ours runs: a [3x-ui](https://github.com/MHSanaei/3x-ui) panel on
PostgreSQL, a pinned Xray core, Russian sites through Cloudflare WARP, and three protocols per server, so a
client can switch when one of them is blocked. Several servers (nodes) can sit behind one head panel that hands
out a single subscription.

Tested on Debian 13 with 1 vCPU and 2 GB RAM, 3x-ui v3.11.0, Xray v26.6.27.

## What a node runs

| Port | Protocol | Notes |
|---|---|---|
| 443/tcp | VLESS + REALITY + Vision | The fastest one. REALITY borrows the TLS handshake of `www.nvidia.com`. |
| 11849/tcp | VLESS + XHTTP + REALITY | Survives where plain TCP sessions are cut after a few seconds. |
| 11274/udp | Hysteria2 | QUIC with salamander obfuscation and brutal congestion control. |
| random | 3x-ui panel | HTTPS with a Let's Encrypt certificate for the node's domain. |
| 2096/tcp | Subscription | HTTPS with the same certificate. |

All three inbounds share one client, so one subscription link gives all three profiles.

Routing on the server, in this order:

1. Private addresses and BitTorrent are blocked.
2. `anthropic.com`, `claude.ai`, `statsig.com`, `sentry.io` and `githubusercontent.com` go direct. They must come
   before the ad filter: `geosite:category-ads-all` contains `statsig.anthropic.com` and breaks Claude Code.
3. Ads are blocked.
4. Sites blocked in Russia go direct from the server.
5. Russian sites (`geosite:category-ru`, `geoip:ru`) go through Cloudflare WARP, because many Russian sites refuse
   foreign hosting addresses.

## Before you start

- A VPS outside Russia with an unlimited channel; our node runs on 1 vCPU and 2 GB RAM.
- A domain (or subdomain) whose A record points at the server. The panel, the subscription and Hysteria2 need a
  certificate for it, and Let's Encrypt checks it over port 80.
- An SSH key on your machine (`ssh-keygen -t ed25519`).

## Set up a node

1. Log in as root and fetch the scripts into `/opt/vpn`, where the user created in the next step can reach them:

   ```bash
   apt-get update && apt-get install -y git
   git clone https://github.com/Efcolipt/bash-vless-reality-cloud-warp-xray.git /opt/vpn && cd /opt/vpn
   ```

2. Lock down SSH in two steps, so a typo cannot cut you off:

   ```bash
   ./harden-ssh.sh "ssh-ed25519 AAAA... you@laptop"   # your public key, the content of ~/.ssh/id_ed25519.pub
   ```

   It prints a new user, a random port and a password for the hoster's console. Keep the root session open and
   check `ssh -p <port> <user>@<server ip>` from another terminal. When that works:

   ```bash
   sudo ./harden-ssh.sh --lock <port>
   ```

   From now on log in as the new user and run the scripts with `sudo`.

3. Install the node:

   ```bash
   cd /opt/vpn && sudo ./install-node.sh vpn1.example.com you@example.com
   ```

   It tunes the kernel (BBR, fq, buffers sized for QUIC), installs 3x-ui with PostgreSQL and a certificate,
   switches the core to the pinned Xray, registers WARP, writes the routing template and creates the three
   inbounds with a first client, `admin`. At the end it prints the panel address, the login and the
   subscription link. The login, the password and the API token stay in `/etc/x-ui/install-result.env`.

   Optional variables:

   | Variable | Default | Meaning |
   |---|---|---|
   | `NODE_NAME` | first label of the domain | Prefix of the profile names in clients. |
   | `REALITY_TARGET` | `www.nvidia.com` | Site whose TLS handshake REALITY borrows. |
   | `HYSTERIA_BANDWIDTH` | `125000000` (1 Gbit/s) | Brutal sends at exactly this rate in bytes per second: set the server's real bandwidth. |
   | `XRAY_VERSION` | `v26.6.27` | See [Xray version](#xray-version) before changing it. |
   | `XUI_VERSION` | `v3.11.0` | 3x-ui release. |

4. Add users in the panel: **Clients → Add**, attach each client to all three inbounds and give it one
   subscription ID. Send each user their subscription link.

## Several servers behind one head panel

A head panel serves one subscription for all nodes, so users never edit anything when a server is added or
replaced. It can be a small VPS of its own:

1. Install plain 3x-ui on it with a certificate for its IP:

   ```bash
   curl -fsSL -o install.sh https://raw.githubusercontent.com/MHSanaei/3x-ui/v3.11.0/install.sh
   XUI_NONINTERACTIVE=1 XUI_SSL_MODE=ip XUI_DB_TYPE=postgres bash install.sh v3.11.0
   ```

2. On the head: **Nodes → Add**, with the node's panel address (`XUI_ACCESS_URL`) and its API token
   (`XUI_API_TOKEN`), both from `/etc/x-ui/install-result.env` on the node. The head copies the node's inbounds.
3. Manage clients on the head from then on. Edit the node's inbounds on the head too: the head keeps its own copy,
   and an edit made on the node does not reach the subscription.

The head's address is in every user's subscription link, so keep it off the server that carries the traffic.

## Clients

- **Happ** and **v2rayNG** run the Xray core and work with all three profiles.
- **Throne** (desktop) runs sing-box for VLESS and Xray for XHTTP. Set in its settings:

  | Setting | Value | Why |
  |---|---|---|
  | Preset Settings → TLS → Default Fingerprint | `firefox` | Throne's own fingerprint overrides the subscription; `edge` breaks REALITY. |
  | DNS cache | on, optimistic, persistent | Otherwise every DNS query goes through the tunnel again. |
  | MTU | 1400 | 1500 fragments inside the tunnel. |
  | Mux | off | Mux breaks Vision. |
  | Log level | warn | `debug` writes 4 MB logs every couple of hours. |

  Throne updates have reset these settings before: check them after an update.

## When users cannot connect

**Check the Xray version first.** A panel update replaces the core with the newest one, and newer cores reject
some clients (see below). Pin it back in the panel (**Overview → Xray → change version**) or on the node:

```bash
sudo bash -c '. /etc/x-ui/install-result.env && curl -fsS -X POST -H "Authorization: Bearer $XUI_API_TOKEN" \
  "$XUI_ACCESS_URL/panel/api/server/installXray/v26.6.27"'
```

**Then check whether the server's IP is blocked.** In Russia the blocks hit addresses, not protocols: a blocked IP
does not even answer the TCP handshake from the affected provider, so changing SNI, protocol or port does not help.
Signs: the node answers from abroad and other users stay connected, while from the affected network every
connection to the IP times out. When that happens:

1. Get a new IP from the hoster, preferably from another /24: whole subnets get blocked.
2. Point the domain's A record at it.
3. On the node, and on the head if there is one:

   ```bash
   sudo ./set-share-address.sh <old ip> <new ip>                                          # on the node
   XUI_API_TOKEN=<head token> ./set-share-address.sh <old ip> <new ip> <head panel url>   # against the head
   ```

4. Users refresh their subscription; clients with auto-update pick up the new address themselves.

Cloudflare as a CDN in front of the node does not help in Russia: since June 2025 the large providers cut
connections to Cloudflare addresses after about 16 KB.

## Xray version

Xray 26.9.8 and later make REALITY refuse a ClientHello without an X25519MLKEM768 key share
([XTLS/Xray-core#7259](https://github.com/XTLS/Xray-core/issues/7259)). Clients using the `edge`, `ios` or
`random` fingerprints and older sing-box and mihomo builds then get `reality verification failed` or
`received real certificate`, and the server logs nothing. Xray clients (Happ, v2rayNG) are not affected. That is
why the core is pinned to v26.6.27. Before raising `XRAY_VERSION`, check that every client you support connects
with the `chrome` fingerprint.

## Pitfalls

- **Subscription address.** The subscription hands out the server's IP, not its domain
  (`shareAddrStrategy: custom`). With a domain there, TUN clients resolve it through the tunnel they are building,
  hang for 10 seconds and drop connections at random.
- **DNS over HTTPS by domain.** Xray resolves the DoH server's own name through itself and loops
  (`tries to resolve itself`). The template pins `dns.adguard-dns.com` in `dns.hosts`; replacing it with
  `https://<ip>/dns-query` fails the TLS check, because the certificate is issued for the name.
- **Policy timeouts.** The default `uplinkOnly: 2` and `downlinkOnly: 5` kill a connection seconds after one side
  closes, which breaks downloads, streaming and XHTTP. The template sets both to 0.
- **`domainStrategy: IPIfNonMatch`** resolves every domain to match the rules and pins a single CPU. The template
  uses `AsIs`: Russian domains match `geosite:category-ru`, and `geoip:ru` catches direct IP connections.
- **Mux** is not compatible with Vision. XHTTP's `xmux` is a different thing and is needed; its
  `hKeepAlivePeriod` must not be 0.
- **Restarting x-ui** drops every user's connection. Do not restart it without a reason.

## Files

| File | What it is |
|---|---|
| `harden-ssh.sh` | SSH user, port and key-only login in two phases. |
| `install-node.sh` | The node setup described above. |
| `set-share-address.sh` | Moves subscriptions to a new IP after an IP change. |
| `panel-api.sh` | The 3x-ui API call both scripts above use. |
| `xray-template.json` | Routing, DNS, policy and outbounds; `install-node.sh` adds the WARP outbound. |
| `99-vpn-node.conf` | Kernel network settings. |

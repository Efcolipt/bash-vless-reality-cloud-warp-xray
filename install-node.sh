#!/usr/bin/env bash
# Sets up a VPN node: 3x-ui on PostgreSQL with a certificate for the domain, a pinned Xray core,
# Cloudflare WARP for Russian sites, and three inbounds that share one client.
#   sudo ./install-node.sh <domain whose A record points at this server> [acme email]
set -euo pipefail

domain="${1:?usage: sudo ./install-node.sh <domain whose A record points at this server> [acme email]}"
acme_email="${2:-}"
xui_version="${XUI_VERSION:-v3.11.0}"
# Xray 26.9.8 and later drop REALITY clients without an X25519MLKEM768 key share (XTLS/Xray-core#7259).
xray_version="${XRAY_VERSION:-v26.6.27}"
reality_target="${REALITY_TARGET:-www.nvidia.com}"
# Hysteria2 brutal sends at this fixed rate (bytes per second): set it to the server's real bandwidth.
hysteria_bandwidth="${HYSTERIA_BANDWIDTH:-125000000}"
name="${NODE_NAME:-${domain%%.*}}"
here="$(cd "$(dirname "$0")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
share_address="$(getent ahostsv4 "$domain" | awk 'NR == 1 { print $1 }')"
[[ -n "$share_address" ]] || { echo "$domain does not resolve: create its A record first." >&2; exit 1; }

echo "==> Kernel tuning"
install -m 644 "$here/99-vpn-node.conf" /etc/sysctl.d/99-vpn-node.conf
sysctl -q --system
interface="$(ip -o -4 route show default | awk '{ print $5; exit }')"
cat >/etc/systemd/system/qdisc-fq.service <<UNIT
[Unit]
Description=fq qdisc on $interface
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/tc qdisc replace dev $interface root fq
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now -q qdisc-fq.service

echo "==> 3x-ui $xui_version"
apt-get update -q
apt-get install -y -q curl jq openssl
curl -fsSL -o /tmp/x-ui-install.sh "https://raw.githubusercontent.com/MHSanaei/3x-ui/$xui_version/install.sh"
XUI_NONINTERACTIVE=1 XUI_SSL_MODE=domain XUI_DOMAIN="$domain" XUI_ACME_EMAIL="$acme_email" XUI_DB_TYPE=postgres \
  bash /tmp/x-ui-install.sh "$xui_version" </dev/null
certificate="/root/cert/$domain/fullchain.pem"
certificate_key="/root/cert/$domain/privkey.pem"
[[ -s "$certificate" ]] || { echo "No certificate for $domain: check its A record and that port 80 is open." >&2; exit 1; }

# shellcheck source=/dev/null
source /etc/x-ui/install-result.env
panel="${XUI_ACCESS_URL%/}"
source "$here/panel-api.sh"

wait_for_panel() {
  for _ in {1..30}; do
    api GET server/status >/dev/null 2>&1 && return
    sleep 2
  done
  api GET server/status >/dev/null
}

wait_for_panel

echo "==> Xray $xray_version"
api POST "server/installXray/$xray_version" >/dev/null
xray_binary=(/usr/local/x-ui/bin/xray-linux-*)

echo "==> Cloudflare WARP"
keys="$("${xray_binary[0]}" wg)"
warp="$(api POST xray/warp/reg \
  --data-urlencode "privateKey=$(awk -F': ' '/^PrivateKey/ { print $2 }' <<<"$keys")" \
  --data-urlencode "publicKey=$(awk -F': ' '/PublicKey/ { print $2 }' <<<"$keys")" | jq -r .)"
# reserved is the three raw bytes of client_id; jq's @base64d would mangle bytes above 127.
reserved="$(jq -r '.config.config.client_id // .data.client_id' <<<"$warp" | base64 -d | od -An -tu1 | jq -sc .)"
warp_outbound="$(jq -c --argjson reserved "$reserved" '.config.config as $device | {
  tag: "warp",
  protocol: "wireguard",
  streamSettings: { sockopt: { domainStrategy: "ForceIPv4v6" } },
  targetStrategy: "ForceIPv4v6",
  settings: {
    mtu: 1280,
    workers: 2,
    noKernelTun: true,
    secretKey: .data.private_key,
    address: [($device.interface.addresses.v4 + "/32"), ($device.interface.addresses.v6 + "/128")],
    reserved: $reserved,
    peers: [{ publicKey: $device.peers[0].public_key, endpoint: $device.peers[0].endpoint.host }]
  }
}' <<<"$warp")"

echo "==> Routing, DNS and policy"
xray_config="$(jq -c --argjson warp "$warp_outbound" '.outbounds += [$warp]' "$here/xray-template.json")"
api POST xray/update --data-urlencode "xraySetting=$xray_config" >/dev/null

echo "==> Inbounds"
uuid="$(api GET server/getNewUUID | jq -r .uuid)"
sub_id="$(openssl rand -hex 8)"
hysteria_auth="$(openssl rand -hex 16)"

client() {
  jq -nc --arg flow "$1" --arg id "$uuid" --arg auth "$hysteria_auth" --arg sub_id "$sub_id" '{
    email: "admin", id: $id, auth: $auth, flow: $flow, subId: $sub_id,
    enable: true, limitIp: 0, totalGB: 0, expiryTime: 0, tgId: 0, comment: "", reset: 0
  }'
}

reality() {
  api GET server/getNewX25519Cert | jq -c --arg target "$reality_target" --arg short_id "$(openssl rand -hex 8)" '{
    show: false,
    xver: 0,
    target: ($target + ":443"),
    serverNames: [$target],
    privateKey: .privateKey,
    shortIds: [$short_id],
    settings: { publicKey: .publicKey, fingerprint: "firefox", serverName: "", spiderX: "/" }
  }'
}

add_inbound() {
  jq -c --arg name "$name" --arg share_address "$share_address" '. + {
    remark: ($name + " | " + .remark),
    enable: true,
    listen: "",
    expiryTime: 0,
    total: 0,
    shareAddrStrategy: "custom",
    shareAddr: $share_address,
    sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], routeOnly: true }
  }' | api POST inbounds/add -H 'Content-Type: application/json' --data @- >/dev/null
}

jq -nc --argjson client "$(client xtls-rprx-vision)" --argjson reality "$(reality)" '{
  remark: "VLESS Reality",
  port: 443,
  protocol: "vless",
  settings: { clients: [$client], decryption: "none", encryption: "none" },
  streamSettings: {
    network: "tcp",
    tcpSettings: { acceptProxyProtocol: false, header: { type: "none" } },
    security: "reality",
    realitySettings: $reality
  }
}' | add_inbound

jq -nc --argjson client "$(client "")" --argjson reality "$(reality)" '{
  remark: "XHTTP Reality",
  port: 11849,
  protocol: "vless",
  settings: { clients: [$client], decryption: "none", encryption: "none" },
  streamSettings: {
    network: "xhttp",
    xhttpSettings: {
      path: "/api/v1/updates",
      host: "",
      mode: "stream-one",
      xPaddingBytes: "100-1000",
      xmux: {
        maxConcurrency: "16-32",
        maxConnections: 0,
        cMaxReuseTimes: 0,
        hMaxRequestTimes: "600-900",
        hMaxReusableSecs: "1800-3000",
        hKeepAlivePeriod: 45
      }
    },
    security: "reality",
    realitySettings: $reality
  }
}' | add_inbound

jq -nc --argjson client "$(client "")" --arg domain "$domain" --arg certificate "$certificate" \
  --arg certificate_key "$certificate_key" --arg bandwidth "$hysteria_bandwidth" --arg obfs "$(openssl rand -hex 16)" '{
  remark: "HY2",
  port: 11274,
  protocol: "hysteria",
  settings: { clients: [$client], version: 2 },
  streamSettings: {
    network: "hysteria",
    hysteriaSettings: { version: 2, udpIdleTimeout: 60 },
    security: "tls",
    tlsSettings: {
      serverName: $domain,
      minVersion: "1.2",
      maxVersion: "1.3",
      alpn: ["h3"],
      certificates: [{
        certificateFile: $certificate,
        keyFile: $certificate_key,
        ocspStapling: 3600,
        oneTimeLoading: false,
        usage: "encipherment",
        buildChain: false
      }],
      settings: { fingerprint: "firefox" }
    },
    finalmask: {
      udp: [{ type: "salamander", settings: { password: $obfs } }],
      quicParams: {
        congestion: "brutal",
        brutalUp: $bandwidth,
        brutalDown: $bandwidth,
        initStreamReceiveWindow: 8388608,
        maxStreamReceiveWindow: 8388608,
        initConnectionReceiveWindow: 20971520,
        maxConnectionReceiveWindow: 20971520,
        maxIdleTimeout: 30,
        keepAlivePeriod: 10,
        disablePathMTUDiscovery: false,
        maxIncomingStreams: 1024
      }
    }
  }
}' | add_inbound

echo "==> Subscription over HTTPS"
# Without its own certificate the subscription server answers plain HTTP and leaks every client key.
settings="$(api POST setting/all | jq -c --arg certificate "$certificate" --arg certificate_key "$certificate_key" \
  '.subCertFile = $certificate | .subKeyFile = $certificate_key')"
api POST setting/update -H 'Content-Type: application/json' --data "$settings" >/dev/null

mkdir -p /etc/systemd/system/x-ui.service.d
printf '[Service]\nLimitNOFILE=1048576\nLimitNPROC=infinity\n' >/etc/systemd/system/x-ui.service.d/limits.conf
systemctl daemon-reload
systemctl restart x-ui
wait_for_panel

settings="$(api POST setting/all)"
cat <<DONE

Node is ready.
  Panel:        $XUI_ACCESS_URL
  Login:        $XUI_USERNAME / $XUI_PASSWORD
  Xray:         $(api GET server/status | jq -r '.xray.version')
  Subscription: https://$domain:$(jq -r .subPort <<<"$settings")$(jq -r .subPath <<<"$settings")$sub_id
  Share address: $share_address

Panel login, password and the API token (XUI_API_TOKEN, needed to attach this node to a head panel)
are kept in /etc/x-ui/install-result.env.
DONE

#!/usr/bin/env bash
set -euo pipefail

INFO="[INFO]"
WARN="[WARN]"
ERROR="[ERROR]"

XRAY_PATH_CONFIG="/usr/local/etc/xray/config.json"
MASK_DOMAIN="yahoo.com"

# --- helpers ---------------------------------------------------------------

die() { echo "$ERROR $*" >&2; exit 1; }
log() { echo "$INFO $*"; }
warn() { echo "$WARN $*" >&2; }

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Please run this script with root privilege"
}

default_iface() {
  ip route show default 2>/dev/null | awk '{print $5; exit}'
}

resolve_ipv4() {
  getent ahostsv4 "$1" 2>/dev/null | awk '{print $1; exit}'
}

restart_firewall_service_if_any() {
  if systemctl list-unit-files | grep -q '^netfilter-persistent\.service'; then
    systemctl restart netfilter-persistent || true
  elif systemctl list-unit-files | grep -q '^iptables\.service'; then
    systemctl restart iptables || true
  elif command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent reload || true
  fi
}

iptables_add_once() {
  local table="$1"; shift
  local chain="$1"; shift
  iptables -t "$table" -C "$chain" "$@" 2>/dev/null || \
  iptables -t "$table" -A "$chain" "$@"
}

# --- sysctl ----------------------------------------------------------------

apply_sysctl() {
  log "Applying sysctl"

  cat >/etc/sysctl.d/99-xray.conf <<'EOF'
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 10000
net.core.somaxconn = 4096

net.ipv4.ip_forward = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30

net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 30

net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000

net.ipv4.tcp_fastopen = 3

net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864

net.ipv4.udp_mem = 4096 51200 102400

net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0

net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

  sysctl --system >/dev/null
}

# --- xray config ------------------------------------------------------------

set_xray_config() {
  local keys_file="/usr/local/etc/xray/.keys"
  [[ -f "$keys_file" ]] || die "Keys file not found: $keys_file"

  local UUID XRAY_PRIV XRAY_SHORT_IDS
  UUID="$(awk -F': ' '/uuid/ {print $2; exit}' "$keys_file")"
  XRAY_PRIV="$(awk -F': ' '/PrivateKey/ {print $2; exit}' "$keys_file")"
  XRAY_SHORT_IDS="$(awk -F': ' '/shortsid/ {print $2; exit}' "$keys_file")"

  [[ -n "$UUID" && -n "$XRAY_PRIV" && -n "$XRAY_SHORT_IDS" ]] || die "Failed to read keys"

  log "Registering WARP"
  local WARP_INFO
  WARP_INFO="$(bash -c "$(curl -fsSL warp-reg.vercel.app)")"

  local WARP_PRIV WARP_PUB WARP_V6 WARP_RESERVED
  WARP_PRIV="$(jq -r '.private_key' <<<"$WARP_INFO")"
  WARP_PUB="$(jq -r '.public_key'  <<<"$WARP_INFO")"
  WARP_V6="$(jq -r '.v6' <<<"$WARP_INFO")"
  WARP_RESERVED="$(jq -r '.reserved_str' <<<"$WARP_INFO")"

  local LISTEN_IP
  LISTEN_IP="$(hostname -I | awk '{print $1}')"

  cat >"$XRAY_PATH_CONFIG" <<EOF
{
  "log": { "loglevel": "info" },

  "api": {
    "services": ["HandlerService", "LoggerService", "StatsService"],
    "tag": "api"
  },
  "stats": {},

  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" },
      "tag": "api"
    },
    {
      "listen": "$LISTEN_IP",
      "port": 443,
      "protocol": "vless",
      "tag": "reality-in",
      "settings": {
        "decryption": "none",
        "encryption": "none",
        "clients": [
          { "id": "$UUID", "email": "main", "flow": "xtls-rprx-vision" }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$MASK_DOMAIN:443",
          "serverNames": ["$MASK_DOMAIN"],
          "privateKey": "$XRAY_PRIV",
          "minClientVer": "",
          "maxClientVer": "",
          "maxTimeDiff": 0,
          "shortIds": ["$XRAY_SHORT_IDS"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
    },
    {
      "tag": "Shadowsocks TCP",
      "listen": "0.0.0.0",
      "port": 1080,
      "protocol": "shadowsocks",
      "settings": {
        "clients": [],
        "network": "tcp,udp"
      }
    }
  ],

  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" },
    {
      "protocol": "wireguard",
      "tag": "warp",
      "settings": {
        "secretKey": "$WARP_PRIV",
        "address": ["172.16.0.2/32", "$WARP_V6/128"],
        "peers": [
          {
            "endpoint" : "engage.cloudflareclient.com:2408",
            "allowedIPs": ["0.0.0.0/0", "::/0"],
            "publicKey": "$WARP_PUB"
          }
        ],
        "mtu": 1280,
        "reserved": "$WARP_RESERVED",
        "workers": 2,
        "domainStrategy": "ForceIP"
      }
    }
  ],

  "routing": {
    "rules": [
      {"type": "field", "protocol": "bittorrent", "outboundTag": "block"},
      {
        "domain": ["geosite:category-ads-all", "geosite:win-spy"],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "domain": [
          "geosite:openai",      "geosite:category-ru", "geosite:private",
          "domain:ru",           "domain:su",           "domain:by",
          "domain:xn--p1ai"
        ],
        "outboundTag": "warp"
      },
      {
        "type": "field",
        "ip": ["geoip:ru", "geoip:private"],
        "outboundTag": "warp"
      }
    ]
  }
}
EOF
}

set_protocols_forwarding() {
  log "Set protocols forwarding"

  local ip face
  ip="$(resolve_ipv4 "$MASK_DOMAIN")"
  face="$(default_iface)"

  iptables_add_once nat PREROUTING -i "$face" -p udp --dport 443 -j DNAT --to "$ip:443"
  iptables_add_once nat POSTROUTING -o "$face" -j MASQUERADE

  netfilter-persistent save || true
  restart_firewall_service_if_any
}

install_xray() {
  log "Installing Xray"
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

  local keys_file="/usr/local/etc/xray/.keys"
  {
    echo "shortsid: $(openssl rand -hex 8)"
    echo "uuid: $(xray uuid)"
    xray x25519
  } > "$keys_file"
}

export DOMAIN=$(hostname)

# --- main ------------------------------------------------------------------

main() {
  require_root

  apt update
  apt install -y iptables iptables-persistent curl jq openssl


  read -r -p "PORT: " XUI_PORT
  read -r -p "USER: " XUI_USER
  read -r -p "PATH: " XUI_PATH
  read -r -s -p "PASSWORD: " XUI_PASSWORD
  echo

  JAR="$(mktemp)"
  trap 'rm -f "$JAR"' EXIT


  curl -sSk -L \
    -c "$JAR" \
    -H "Content-Type: application/json" \
    -X POST "https://localhost:$XUI_PORT/$XUI_PATH/login" \
    --data "{\"username\":\"$XUI_USER\",\"password\":\"$XUI_PASSWORD\",\"twoFactorCode\":\"\"}"


    echo "Cookie jar: $JAR"
    cat "$JAR"



  log "DONE"
}

main

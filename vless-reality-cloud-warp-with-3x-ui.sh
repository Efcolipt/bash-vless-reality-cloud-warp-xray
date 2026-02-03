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


gen_random_string() {
    local length="$1"
    local random_string=$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w "$length" | head -n 1)
    echo "$random_string"
}


main() {
  require_root

  apt update
  apt install -y iptables iptables-persistent curl jq openssl

  ARCH=$(uname -m)
  case "${ARCH}" in
    x86_64 | x64 | amd64) XUI_ARCH="amd64" ;;
    i*86 | x86) XUI_ARCH="386" ;;
    armv8* | armv8 | arm64 | aarch64) XUI_ARCH="arm64" ;;
    armv7* | armv7) XUI_ARCH="armv7" ;;
    armv6* | armv6) XUI_ARCH="armv6" ;;
    armv5* | armv5) XUI_ARCH="armv5" ;;
    s390x) XUI_ARCH="s390x" ;;
    *) XUI_ARCH="amd64" ;;
  esac

  wget https://github.com/MHSanaei/3x-ui/releases/latest/download/x-ui-linux-${XUI_ARCH}.tar.gz

  # Detect OS release
  if [[ -f /etc/os-release ]]; then
      source /etc/os-release
      release=$ID
  elif [[ -f /usr/lib/os-release ]]; then
      source /usr/lib/os-release
      release=$ID
  else
      echo "Failed to detect OS"
      exit 1
  fi

  cd /root/
  rm -rf x-ui/ /usr/local/x-ui/ /usr/bin/x-ui
  tar zxvf x-ui-linux-${XUI_ARCH}.tar.gz
  chmod +x x-ui/x-ui x-ui/bin/xray-linux-* x-ui/x-ui.sh
  cp x-ui/x-ui.sh /usr/bin/x-ui



# Copy appropriate service file based on OS
if [ -f "x-ui/x-ui.service" ]; then
    cp -f x-ui/x-ui.service /etc/systemd/system/
elif [[ "$release" == "ubuntu" || "$release" == "debian" || "$release" == "armbian" ]]; then
    if [ -f "x-ui/x-ui.service.debian" ]; then
        cp -f x-ui/x-ui.service.debian /etc/systemd/system/x-ui.service
    else
        echo "Service file not found in archive, downloading..."
        curl -fLo /etc/systemd/system/x-ui.service https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.service.debian
    fi
else
    if [ -f "x-ui/x-ui.service.rhel" ]; then
        cp -f x-ui/x-ui.service.rhel /etc/systemd/system/x-ui.service
    else
        echo "Service file not found in archive, downloading..."
        curl -fLo /etc/systemd/system/x-ui.service https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.service.rhel
    fi
fi

mv x-ui/ /usr/local/

cat >"/usr/local/x-ui/bin/config.json" <<'JSON'
{
  "api": {
    "services": [
      "HandlerService",
      "LoggerService",
      "StatsService"
    ],
    "tag": "api"
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 62789,
      "protocol": "tunnel",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    }
  ],
  "log": {
    "dnsLog": true,
    "error": "",
    "loglevel": "info",
    "maskAddress": ""
  },
  "metrics": {
    "listen": "127.0.0.1:11111",
    "tag": "metrics_out"
  },
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundDownlink": true,
      "statsInboundUplink": true,
      "statsOutboundDownlink": false,
      "statsOutboundUplink": false
    }
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ],
        "domain": [
          "geosite:category-ads-all",
          "geosite:win-spy"
        ]
      },
      {
        "type": "field",
        "outboundTag": "warp",
        "ip": [
          "ext:geoip_RU.dat:ru",
          "geoip:private"
        ],
        "domain": [
          "regexp:.*\\.su$",
          "regexp:.*\\.ru$",
          "regexp:.*\\.by$",
          "ext:geosite_RU.dat:ru-available-only-inside",
          "regexp:.*\\.xn--p1ai$"
        ]
      }
    ]
  },
  "stats": {}
}
JSON

  systemctl daemon-reload
  systemctl enable x-ui
  systemctl restart x-ui

  local XUI_FOLDER="${XUI_MAIN_FOLDER:=/usr/local/x-ui}"
  local XUI_USER=$(gen_random_string 10)
  local XUI_PASSWORD=$(gen_random_string 18)
  local XUI_PATH=$(gen_random_string 18)
  local XUI_PORT=$(shuf -i 1024-62000 -n 1)
  local IS_EXIST_CERT=$("$XUI_FOLDER/x-ui" setting -getCert true | grep 'cert:' | awk -F': ' '{print $2}' | tr -d '[:space:]')

  "$XUI_FOLDER/x-ui" setting -port "$XUI_PORT" -username "$XUI_USER" -password "$XUI_PASSWORD" -resetTwoFactor false -webBasePath "$XUI_PATH"

  echo -e "Panel login username: ${XUI_USER}"
  echo -e "Panel login password: ${config_XUI_PASSWORDpassword}"
  echo -e "Web Base port: ${XUI_PORT}"
  echo -e "Web base path: ${XUI_PATH}"

  if [[ -z "$IS_EXIST_CERT" ]]; then
    x-ui settings
  fi

  
  JAR="$(mktemp)"
  trap 'rm -f "$JAR"' EXIT

  curl -sSk -L \
    -c "$JAR" \
    -H "Content-Type: application/json" \
    -X POST "https://localhost:$XUI_PORT/$XUI_PATH/login" \
    --data "{\"username\":\"$XUI_USER\",\"password\":\"$XUI_PASSWORD\",\"twoFactorCode\":\"\"}"


  local LISTEN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "$LISTEN_IP" ]] || LISTEN_IP="0.0.0.0"

  local SHORD_IDS="$(openssl rand -hex 8)"

  local BODY="$(jq -n \ 
    --arg mask_domain "$MASK_DOMAIN" \
    --arg xray_priv "$XRAY_PRIV" \
    --arg listen_ip "$LISTEN_IP" \
    --arg short_ids "$SHORD_IDS" \
      '{
        up: 0,
        down: 0,
        total: 0,
        remark: "",
        enable: true,
        expiryTime: 0,
        listen: "$listen_ip",
        port: 443,
        protocol: "vless",
        settings: {},
        streamSettings: {
          network: "tcp",
          security: "reality",
          realitySettings: {
            show: false,
            dest: ($mask_domain + ":443"),
            serverNames: [$mask_domain],
            privateKey: $xray_priv,
            shortIds: [$short_ids]
          }
        },
        sniffing: {
          enabled: true,
          destOverride: ["http","tls","quic"]
        }
      }'
  
  )"

  curl -sSk -L "https://localhost:$XUI_PORT/$XUI_PATH/api/inbounds/add" \
    -c "$JAR" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data "$BODY"
  

  log "DONE"
}

main

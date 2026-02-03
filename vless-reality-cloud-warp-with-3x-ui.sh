#!/usr/bin/env bash
set -euo pipefail

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || {
    echo "Please run this script with root privilege" >&2
    exit 1
  }
}

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


gen_random_string() {
    local length="$1"
    local random_string=$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w "$length" | head -n 1)
    echo "$random_string"
}


main() {
  require_root

  apt update
  apt install -y jq openssl

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
  echo -e "Panel login password: ${XUI_PASSWORD}"
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

  local SHORT_ID="$(openssl rand -hex 8)"

  local MASK_DOMAIN="yahoo.com"
  local PRIVATE_KEY="$(
    curl -sSk -L \
      -b "$JAR" -c "$JAR" \
      -H 'Accept: application/json' \
      -H 'Content-Type: application/json' \
      -X GET "https://localhost:$XUI_PORT/$XUI_PATH/api/server/getNewX25519Cert" \
    | jq -r '.obj.privateKey'
  )"
  

  local BODY="$(jq -n \
    --arg mask_domain "$MASK_DOMAIN" \
    --arg xray_priv "$PRIVATE_KEY" \
    --arg listen_ip "$LISTEN_IP" \
    --arg short_id "$SHORT_ID" \
    '{
      up: 0,
      down: 0,
      total: 0,
      remark: "",
      enable: true,
      expiryTime: 0,
      listen: $listen_ip,
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
          shortIds: [$short_id]
        }
      },
      sniffing: {
        enabled: true,
        destOverride: ["http","tls","quic"]
      }
    }'
  )"
  
  curl -sSk -L -X POST "https://localhost:$XUI_PORT/$XUI_PATH/api/inbounds/add" \
    -b "$JAR" -c "$JAR" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data "$BODY"
}

main

#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

#######################################
# Helpers
#######################################
require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || {
    echo "Please run this script with root privilege" >&2
    exit 1
  }
}

log() { echo "[LOG] $*"; }

gen_random_string() {
  local length="$1"
  local random_string
  random_string="$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w "$length" | head -n 1)"
  echo "$random_string"
}

wait_for_port() {
  local port="$1"
  for _ in {1..30}; do
    if ss -lnt | awk '{print $4}' | grep -q ":$port$"; then
      return 0
    fi
    sleep 1
  done
  echo "❌ x-ui did not open port $port" >&2
  systemctl status x-ui --no-pager >&2 || true
  exit 1
}

#######################################
# Sysctl (original unchanged)
#######################################
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

  sysctl --system
}

#######################################
# Install / Detect
#######################################
install_deps() {
  apt update
  apt install -y jq openssl
}

detect_xui_arch() {
  local ARCH
  ARCH="$(uname -m)"
  case "${ARCH}" in
    x86_64 | x64 | amd64) echo "amd64" ;;
    i*86 | x86) echo "386" ;;
    armv8* | armv8 | arm64 | aarch64) echo "arm64" ;;
    armv7* | armv7) echo "armv7" ;;
    armv6* | armv6) echo "armv6" ;;
    armv5* | armv5) echo "armv5" ;;
    s390x) echo "s390x" ;;
    *) echo "amd64" ;;
  esac
}

detect_os_release() {
  local release
  if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release="$ID"
  elif [[ -f /usr/lib/os-release ]]; then
    source /usr/lib/os-release
    release="$ID"
  else
    echo "Failed to detect OS" >&2
    exit 1
  fi
  echo "$release"
}

download_xui() {
  local arch="$1"
  wget "https://github.com/MHSanaei/3x-ui/releases/latest/download/x-ui-linux-${arch}.tar.gz"
}

install_xui_files() {
  local arch="$1"

  cd /root/
  rm -rf x-ui/ /usr/local/x-ui/ /usr/bin/x-ui
  tar zxvf "x-ui-linux-${arch}.tar.gz"
  chmod +x x-ui/x-ui x-ui/bin/xray-linux-* x-ui/x-ui.sh
  cp x-ui/x-ui.sh /usr/bin/x-ui
}

setup_systemd_service() {
  local release="$1"

  # Copy appropriate service file based on OS (original logic preserved)
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

  systemctl daemon-reload
  systemctl enable x-ui
  systemctl restart x-ui
}

#######################################
# Panel setup / auth
#######################################
setup_panel_credentials() {
  local XUI_FOLDER="${XUI_MAIN_FOLDER:=/usr/local/x-ui}"

  XUI_USER="$(gen_random_string 10)"
  XUI_PASSWORD="$(gen_random_string 18)"
  XUI_PORT="$(shuf -i 1024-62000 -n 1)"

  "$XUI_FOLDER/x-ui" setting -port "$XUI_PORT" -username "$XUI_USER" -password "$XUI_PASSWORD" -resetTwoFactor false

  systemctl restart x-ui
  wait_for_port "$XUI_PORT"
}

panel_login_cookiejar() {
  JAR="$(mktemp)"
  trap 'rm -f "$JAR"' EXIT

  curl -sSk -L \
    -c "$JAR" \
    -H "Content-Type: application/json" \
    -X POST "http://localhost:$XUI_PORT/login" \
    --data "{\"username\":\"$XUI_USER\",\"password\":\"$XUI_PASSWORD\",\"twoFactorCode\":\"\"}"
}

get_listen_ip() {
  LISTEN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "$LISTEN_IP" ]] || LISTEN_IP="0.0.0.0"
}

#######################################
# Xray / Warp / Reality config (original content preserved)
#######################################
fetch_x25519_keys() {
  X25519_KEYS="$(
    curl -sSk -L \
      -b "$JAR" -c "$JAR" \
      -H 'Accept: application/json' \
      -H 'Content-Type: application/json' \
      -X GET "http://localhost:$XUI_PORT/panel/api/server/getNewX25519Cert"
  )"
}

register_warp() {
  WARP_INFO="$(bash -c "$(curl -L warp-reg.vercel.app)")"

  WARP_PRIV="$(jq -r '.private_key' <<<"$WARP_INFO")"
  WARP_PUB="$(jq -r '.public_key'  <<<"$WARP_INFO")"
  WARP_V6="$(jq -r '.v6' <<<"$WARP_INFO")"
  WARP_RESERVED="$(jq -r '.reserved_str' <<<"$WARP_INFO")"
}

update_xray_config() {
  INIT_CONFIG="$(
    jq -cn \
      --arg warp_priv "$WARP_PRIV" \
      --arg warp_v6 "$WARP_V6" \
      --arg warp_pub "$WARP_PUB" \
      --arg warp_res "$WARP_RESERVED" \
      '{
          "api": {
            "services": ["HandlerService", "LoggerService", "StatsService"],
            "tag": "api"
          },
          "dns": {
            "servers": [
              "https+local://8.8.4.4/dns-query",
              "https+local://8.8.8.8/dns-query",
              "https+local://1.1.1.1/dns-query",
              "localhost"
            ],
            "queryStrategy": "UseIPv4"
          },
          "inbounds": [
            {
              "listen": "127.0.0.1",
              "port": 62789,
              "protocol": "tunnel",
              "settings": {"address": "127.0.0.1"},
              "tag": "api"
            }
          ],
          "log": {"dnsLog": false, "error": "", "loglevel": "error", "maskAddress": ""},
          "metrics": {"listen": "127.0.0.1:11111", "tag": "metrics_out"},
          "outbounds": [
            {"protocol": "freedom",   "tag": "direct"                 },
            {"protocol": "blackhole", "tag": "blocked", "settings": {}},
            {
              "protocol": "wireguard",
              "tag": "warp",
              "settings": {
                "secretKey": $warp_priv,
                "address": ["172.16.0.2/32", ($warp_v6 + "/128")],
                "peers": [
                  {
                    "endpoint" : "engage.cloudflareclient.com:2408",
                    "allowedIPs": ["0.0.0.0/0", "::/0"],
                    "publicKey": $warp_pub
                  }
                ],
                "mtu": 1280,
                "reserved": $warp_res,
                "workers": 2,
                "domainStrategy": "ForceIP"
              }
            }
          ],
          "policy": {
            "levels": { "0": {"statsUserDownlink": true, "statsUserUplink": true} },
            "system": {
              "statsInboundDownlink" : true,
              "statsInboundUplink"   : true,
              "statsOutboundDownlink": false,
              "statsOutboundUplink"  : false
            }
          },
          "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
              { "inboundTag": ["api"], "outboundTag": "api", "type": "field" },
              {
                "type": "field",
                "outboundTag": "blocked",
                "protocol": ["bittorrent"],
                "domain": ["geosite:category-ads-all", "geosite:win-spy"]
              },
              {
                "type": "field",
                "outboundTag": "warp",
                "ip": ["ext:geoip_RU.dat:ru", "geoip:private"],
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
        }'
  )"

  curl -sSk -L \
    -b "$JAR" -c "$JAR" \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "xraySetting=$INIT_CONFIG" \
    -X POST "http://localhost:$XUI_PORT/panel/xray/update"
}

add_vless_reality_inbound() {
  SNIFFING="$(jq -cn \
    '{
      enabled: true,
      destOverride: ["http","tls","quic"]
    }'
  )"

  PRIVATE_KEY="$(jq -r '.obj.privateKey' <<<"$X25519_KEYS")"
  PUBLIC_KEY="$(jq -r '.obj.publicKey'  <<<"$X25519_KEYS")"

  SHORT_ID="$(openssl rand -hex 8)"
  MASK_DOMAIN="yahoo.com"

  STREAM_SETTINGS="$(jq -cn \
    --arg mask_domain "$MASK_DOMAIN" \
    --arg xray_priv "$PRIVATE_KEY" \
    --arg xray_pub "$PUBLIC_KEY" \
    --arg short_id "$SHORT_ID" \
    '{
      network: "tcp",
      security: "reality",
      realitySettings: {
        show: false,
        target: ($mask_domain + ":443"),
        serverNames: [$mask_domain],
        privateKey: $xray_priv,
        shortIds: [$short_id],
        "settings": {
          "publicKey"    : $xray_pub,
          "fingerprint"  : "chrome",
          "serverName"   : "",
          "spiderX"      : "/",
          "mldsa65Verify": ""
        }
      }
    }'
  )"

  UUID="$(
    curl -sSk -L \
      -b "$JAR" -c "$JAR" \
      -H 'Accept: application/json' \
      -H 'Content-Type: application/json' \
      -X GET "http://localhost:$XUI_PORT/panel/api/server/getNewUUID" \
      | jq -r '.obj.uuid'
  )"

  SETTINGS="$(jq -cn \
    --arg uuid "$UUID" \
    --arg email "$(gen_random_string 10)" \
    --arg sub_id "$(gen_random_string 18)" \
    '{
      decryption: "none",
      encryption: "none",
      "clients":[
        {
          id: $uuid,
          flow: "xtls-rprx-vision",
          email: $email,
          limitIp: 0,
          totalGB: 0,
          expiryTime: 0,
          enable: true,
          tgId: "",
          subId: $sub_id,
          comment: "",
          reset: 0
        }
      ]
    }'
  )"

  BODY="$(jq -n \
    --arg listen_ip "$LISTEN_IP" \
    --arg streamSettings "$STREAM_SETTINGS" \
    --arg sniffing "$SNIFFING" \
    --arg settings "$SETTINGS" \
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
      settings: $settings,
      streamSettings: $streamSettings,
      sniffing: $sniffing
    }'
  )"

  curl -sSk -L -X POST "http://localhost:$XUI_PORT/panel/api/inbounds/add" \
    -b "$JAR" -c "$JAR" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data "$BODY"
}

#######################################
# Main
#######################################
main() {
  require_root
  install_deps

  XUI_ARCH="$(detect_xui_arch)"
  download_xui "$XUI_ARCH"

  RELEASE="$(detect_os_release)"
  install_xui_files "$XUI_ARCH"
  setup_systemd_service "$RELEASE"

  setup_panel_credentials
  panel_login_cookiejar

  get_listen_ip
  fetch_x25519_keys
  register_warp
  update_xray_config
  add_vless_reality_inbound

  apply_sysctl
  x-ui settings

  echo -e "Panel login username: ${XUI_USER}"
  echo -e "Panel login password: ${XUI_PASSWORD}"
  echo -e "Web Base port: ${XUI_PORT}"
  echo -e "http://$LISTEN_IP:$XUI_PORT"
}

main

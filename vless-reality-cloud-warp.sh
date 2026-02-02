#!/usr/bin/env bash
set -euo pipefail

INFO="[INFO]"
WARN="[WARN]"
ERROR="[ERROR]"

XRAY_PATH_CONFIG="/usr/local/etc/xray/config.json"
MASK_DOMAIN="yahoo.com"
KEYS_FILE="/usr/local/etc/xray/.keys"

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
  # More reliable than dig tail/head, avoids multiple IP random pick patterns
  # Returns first IPv4 from NSS
  getent ahostsv4 "$1" 2>/dev/null | awk '{print $1; exit}'
}

restart_firewall_service_if_any() {
  # Different distros name this differently
  if systemctl list-unit-files | grep -q '^netfilter-persistent\.service'; then
    systemctl restart netfilter-persistent || true
  elif systemctl list-unit-files | grep -q '^iptables\.service'; then
    systemctl restart iptables || true
  elif command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent reload || true
  else
    # no service; do nothing
    true
  fi
}

iptables_add_once() {
  # Usage: iptables_add_once -t nat PREROUTING ...rule...
  local table="$1"; shift
  local chain="$1"; shift
  # check (-C) same rule exists; if not then add (-A)
  iptables -t "$table" -C "$chain" "$@" 2>/dev/null || iptables -t "$table" -A "$chain" "$@"
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

set_xray_config() {
  [[ -f "$KEYS_FILE" ]] || die "Keys file not found: $KEYS_FILE"

  local UUID XRAY_PRIV XRAY_SHORT_IDS
  UUID="$(awk -F': ' '/uuid/ {print $2; exit}' "$KEYS_FILE")"
  XRAY_PRIV="$(awk -F': ' '/PrivateKey/ {print $2; exit}' "$KEYS_FILE")"
  XRAY_SHORT_IDS="$(awk -F': ' '/shortsid/ {print $2; exit}' "$KEYS_FILE")"

  [[ -n "$UUID" && -n "$XRAY_PRIV" && -n "$XRAY_SHORT_IDS" ]] || die "Failed to read uuid/x25519/shortsid"

  log "Registering WARP"
  # Keep as-is, but make curl safer
  local WARP_INFO
  WARP_INFO="$(bash -c "$(curl -fsSL warp-reg.vercel.app)")"

  local WARP_PRIV WARP_PUB WARP_V6 WARP_RESERVED
  WARP_PRIV="$(jq -r '.private_key' <<<"$WARP_INFO")"
  WARP_PUB="$(jq -r '.public_key'  <<<"$WARP_INFO")"
  WARP_V6="$(jq -r '.v6' <<<"$WARP_INFO")"
  WARP_RESERVED="$(jq -r '.reserved_str' <<<"$WARP_INFO")"

  [[ -n "$WARP_PRIV" && -n "$WARP_PUB" && -n "$WARP_V6" && -n "$WARP_RESERVED" ]] || die "Failed to parse warp-reg output"

  # Note: you used hostname -I first IP. Keep semantics, but safer fallback.
  local LISTEN_IP
  LISTEN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "$LISTEN_IP" ]] || LISTEN_IP="0.0.0.0"

  cat >"$XRAY_PATH_CONFIG" <<EOF
{
  "log": {"loglevel": "info"},
  "inbounds": [
    {
      "listen": "$LISTEN_IP",
      "port": 443,
      "protocol": "vless",
      "tag": "reality-in",
      "settings": {
        "decryption": "none",
        "encryption": "none",
        "clients": [
          {"id": "$UUID", "email": "main", "flow": "xtls-rprx-vision"}
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
    }
  ],
  "outbounds": [
    {"protocol": "freedom", "tag": "direct"},
    {"protocol": "blackhole", "tag": "block"},
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
    "domainStrategy": "IPIfNonMatch",
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

  local domain="${1:-$MASK_DOMAIN}"
  local ip face

  ip="$(resolve_ipv4 "$domain")"
  face="$(default_iface)"

  [[ -n "$ip" ]] || die "Failed to resolve IPv4 for domain: $domain"
  [[ -n "$face" ]] || die "Failed to detect default network interface"

  log "Mask domain: $domain IP: $ip  IFACE: $face"

  # DNAT rules (idempotent)
  iptables_add_once nat PREROUTING -i "$face" -p udp --dport 443 -j DNAT --to-destination "$ip:443"
  iptables_add_once nat PREROUTING -i "$face" -p tcp --dport 80  -j DNAT --to-destination "$ip:80"

  # MASQUERADE is essential for DNAT to external host to work reliably
  iptables_add_once nat POSTROUTING -o "$face" -j MASQUERADE

  # Persist if available
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
  elif command -v iptables-save >/dev/null 2>&1 && [[ -d /etc/iptables ]]; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
  fi

  restart_firewall_service_if_any
}

install_xray() {
  log "Installing Xray"
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

  rm -f "$KEYS_FILE"
  install -m 0600 /dev/null "$KEYS_FILE"

  {
    echo "shortsid: $(openssl rand -hex 8)"
    echo "uuid: $(xray uuid)"
  } >> "$KEYS_FILE"

  xray x25519 >> "$KEYS_FILE"
}



add_commands() {
  # xraynewuser
  install -m 0755 /dev/null /usr/local/bin/xraynewuser
  cat <<'EOF' > /usr/local/bin/xraynewuser
#!/usr/bin/env bash
set -euo pipefail

read -r -p "Введите имя пользователя: " email

if [[ -z "$email" || "$email" == *" "* ]]; then
  echo "Имя пользователя не может быть пустым или содержать пробелы. Попробуйте снова."
  exit 1
fi

KEYS_FILE="/usr/local/etc/xray/.keys"
PATH_CONFIG="/usr/local/etc/xray/config.json"
user_json="$(jq --arg email "$email" '.inbounds[0].settings.clients[] | select(.email == $email)' "$PATH_CONFIG" || true)"

if [[ -z "$user_json" ]]; then
  uuid="$(xray uuid)"
  jq --arg email "$email" --arg uuid "$uuid" \
     '.inbounds[0].settings.clients += [{"email": $email, "id": $uuid, "flow": "xtls-rprx-vision"}]' \
     "$PATH_CONFIG" > /tmp/xray.tmp.json && mv /tmp/xray.tmp.json "$PATH_CONFIG"

  systemctl restart xray

  index="$(jq --arg email "$email" '.inbounds[0].settings.clients | to_entries[] | select(.value.email == $email) | .key' "$PATH_CONFIG")"
  protocol="$(jq -r '.inbounds[0].protocol' "$PATH_CONFIG")"
  uuid="$(jq --argjson index "$index" -r '.inbounds[0].settings.clients[$index].id' "$PATH_CONFIG")"
  pbk="$(awk -F': ' '/Password/ {print $2; exit}' $KEYS_FILE)"
  sid="$(awk -F': ' '/shortsid/ {print $2; exit}' $KEYS_FILE)"
  username="$(jq --argjson index "$index" -r '.inbounds[0].settings.clients[$index].email' "$PATH_CONFIG")"
  sni="$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$PATH_CONFIG")"
  ip="$(hostname -I | awk '{print $1}')"

  link="$protocol://$uuid@$ip?security=reality&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid&alpn=h2&type=tcp&flow=xtls-rprx-vision&encryption=none&packetEncoding=xudp#vless-reality-cloud-warp-$username"
  echo ""
  echo "Ссылка для подключения:"
  echo "$link"
else
  echo "Пользователь с таким именем уже существует. Попробуйте снова."
fi
EOF

  # xrayrmuser
  install -m 0755 /dev/null /usr/local/bin/xrayrmuser
  cat <<'EOF' > /usr/local/bin/xrayrmuser
#!/usr/bin/env bash
set -euo pipefail

PATH_CONFIG="/usr/local/etc/xray/config.json"
mapfile -t emails < <(jq -r '.inbounds[0].settings.clients[].email' "$PATH_CONFIG")

if [[ ${#emails[@]} -eq 0 ]]; then
  echo "Нет клиентов для удаления."
  exit 1
fi

echo "Список клиентов:"
for i in "${!emails[@]}"; do
  echo "$((i+1)). ${emails[$i]}"
done

read -r -p "Введите номер клиента для удаления: " choice

if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#emails[@]} )); then
  echo "Ошибка: номер должен быть от 1 до ${#emails[@]}"
  exit 1
fi

selected_email="${emails[$((choice - 1))]}"

jq --arg email "$selected_email" \
  '(.inbounds[0].settings.clients) |= map(select(.email != $email))' \
  "$PATH_CONFIG" > /tmp/xray.tmp && mv /tmp/xray.tmp "$PATH_CONFIG"

systemctl restart xray

echo "Клиент $selected_email удалён."
EOF

  # xraymainuser
  install -m 0755 /dev/null /usr/local/bin/xraymainuser
  cat <<'EOF' > /usr/local/bin/xraymainuser
#!/usr/bin/env bash
set -euo pipefail

KEYS_FILE="/usr/local/etc/xray/.keys"
PATH_CONFIG="/usr/local/etc/xray/config.json"
protocol="$(jq -r '.inbounds[0].protocol' "$PATH_CONFIG")"
uuid="$(awk -F': ' '/uuid/ {print $2; exit}' $KEYS_FILE)"
pbk="$(awk -F': ' '/Password/ {print $2; exit}' $KEYS_FILE)"
sid="$(awk -F': ' '/shortsid/ {print $2; exit}' $KEYS_FILE)"
sni="$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$PATH_CONFIG")"
ip="$(hostname -I | awk '{print $1}')"

link="$protocol://$uuid@$ip?security=reality&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid&alpn=h2&type=tcp&flow=xtls-rprx-vision&packetEncoding=xudp&encryption=none#vless-reality-cloud-warp-main"
echo ""
echo "Ссылка для подключения:"
echo "$link"
EOF

  # xraysharelink
  install -m 0755 /dev/null /usr/local/bin/xraysharelink
  cat <<'EOF' > /usr/local/bin/xraysharelink
#!/usr/bin/env bash
set -euo pipefail

KEYS_FILE="/usr/local/etc/xray/.keys"
PATH_CONFIG="/usr/local/etc/xray/config.json"
mapfile -t emails < <(jq -r '.inbounds[0].settings.clients[].email' "$PATH_CONFIG")

for i in "${!emails[@]}"; do
  echo "$((i + 1)). ${emails[$i]}"
done

read -r -p "Выберите клиента: " client

if ! [[ "$client" =~ ^[0-9]+$ ]] || (( client < 1 || client > ${#emails[@]} )); then
  echo "Ошибка: номер должен быть от 1 до ${#emails[@]}"
  exit 1
fi

selected_email="${emails[$((client - 1))]}"

index="$(jq --arg email "$selected_email" '.inbounds[0].settings.clients | to_entries[] | select(.value.email == $email) | .key' "$PATH_CONFIG")"
protocol="$(jq -r '.inbounds[0].protocol' "$PATH_CONFIG")"
uuid="$(jq --argjson index "$index" -r '.inbounds[0].settings.clients[$index].id' "$PATH_CONFIG")"
pbk="$(awk -F': ' '/Password/ {print $2; exit}' $KEYS_FILE)"
sid="$(awk -F': ' '/shortsid/ {print $2; exit}' $KEYS_FILE)"
username="$(jq --argjson index "$index" -r '.inbounds[0].settings.clients[$index].email' "$PATH_CONFIG")"
sni="$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$PATH_CONFIG")"
ip="$(curl -4 -fsS icanhazip.com || hostname -I | awk '{print $1}')"

link="$protocol://$uuid@$ip?security=reality&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid&alpn=h2&type=tcp&flow=xtls-rprx-vision&packetEncoding=xudp&encryption=none##vless-reality-cloud-warp-$username"
echo ""
echo "Ссылка для подключения:"
echo "$link"
EOF
}

main() {
  require_root

  apt update
  apt install -y dnsutils iptables fail2ban iptables-persistent curl jq openssl

  install_xray
  set_xray_config
  apply_sysctl
  set_protocols_forwarding "$MASK_DOMAIN"
  add_commands

  systemctl restart xray

  /usr/local/bin/xraymainuser || true

  echo "
    Команды для управления пользователями Xray:

        xraymainuser - выводит ссылку для подключения основного пользователя
        xraynewuser - создает нового пользователя
        xrayrmuser - удаление пользователей
        xraysharelink - выводит список пользователей и позволяет создать для них ссылки для подключения
  "
}

main

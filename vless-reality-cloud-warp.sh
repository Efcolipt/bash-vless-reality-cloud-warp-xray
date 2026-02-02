#!/usr/bin/bash
set -e

INFO="[INFO]"
WARN="[WARN]"
ERROR="[ERROR]"

XRAY_PATH_CONFIG="/usr/local/etc/xray/config.json"
MASK_DOMAIN="images.apple.com"

export XRAY_PATH_CONFIG

[[ $EUID -ne 0 ]] && echo -e "${red}Fatal error: ${plain} Please run this script with root privilege \n " && exit 1

apply_sysctl() {
  echo "$INFO Applying sysctl"
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


set_xray_config() {
    local UUID=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/uuid/ {print $2}')
    local XRAY_PRIV=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/PrivateKey/ {print $2}')
    local XRAY_SHORT_IDS=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/shortsid/ {print $2}')

    if [[ -z "$UUID" || -z "$XRAY_PRIV" || -z "$XRAY_SHORT_IDS" ]]; then
      echo "$ERROR Failed to generate UUID/x25519"
      exit 1
    fi

    echo "$INFO Registering WARP"
    local WARP_INFO="$(bash -c "$(curl -L warp-reg.vercel.app)")"
    local WARP_PRIV="$(sed -nE 's/.*"private_key"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' <<<"$WARP_INFO")"
    local WARP_PUB="$(sed -nE 's/.*"public_key"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' <<<"$WARP_INFO")"

    local WARP_V6="$(
      printf '%s\n' "$WARP_INFO" |
      sed -E '/"endpoint"[[:space:]]*:/,/\}/d' |
      sed -nE 's/.*"v6"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p'
    )"

    local WARP_RESERVED="$(sed -nE 's/.*"reserved_str"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' <<<"$WARP_INFO")"

    if [[ -z "${WARP_PRIV}" || -z "${WARP_PUB}" || -z "${WARP_V6}" || -z "${WARP_RESERVED}" ]]; then
      echo "$ERROR Failed to parse warp-reg output"
      exit 1
    fi

 cat >"$XRAY_PATH_CONFIG" <<EOF
{
  "log": {"loglevel": "info"},
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
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "tag": "reality-in",
      "settings": {
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
  },
  "policy": {
    "levels": { "0": {"handshake": 3, "connIdle": 180} }
  }
}
EOF
}

set_protocols_forwarding() {  
  echo "$INFO Set protocols forwarding"
  local ip=$(dig +short A "$MASK_DOMAIN" | tail -n1)
  local face="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
  echo "$INFO Mask domain IP:$ip FACE:$face"

  iptables -t nat -A PREROUTING -i $face -p udp --dport 443 -j DNAT --to-destination $ip:443
  iptables -t nat -A PREROUTING -i $face -p tcp --dport 80 -j DNAT --to-destination $ip:80

  systemctl restart iptables
}

add_commands() {
# Исполняемый файл для создания новых клиентов
touch /usr/local/bin/xraynewuser
cat << 'EOF' > /usr/local/bin/xraynewuser
#!/bin/bash
read -p "Введите имя пользователя: " email

    if [[ -z "$email" || "$email" == *" "* ]]; then
    echo "Имя пользователя не может быть пустым или содержать пробелы. Попробуйте снова."
    exit 1
    fi
user_json=$(jq --arg email "$email" '.inbounds[0].settings.clients[] | select(.email == $email)' $XRAY_PATH_CONFIG)

if [[ -z "$user_json" ]]; then
uuid=$(xray uuid)
jq --arg email "$email" --arg uuid "$uuid" '.inbounds[0].settings.clients += [{"email": $email, "id": $uuid, "flow": "xtls-rprx-vision"}]' $XRAY_PATH_CONFIG > tmp.json && mv tmp.json $XRAY_PATH_CONFIG
systemctl restart xray
index=$(jq --arg email "$email" '.inbounds[0].settings.clients | to_entries[] | select(.value.email == $email) | .key'  $XRAY_PATH_CONFIG)
protocol=$(jq -r '.inbounds[0].protocol' $XRAY_PATH_CONFIG)
uuid=$(jq --argjson index "$index" -r '.inbounds[0].settings.clients[$index].id' $XRAY_PATH_CONFIG)
pbk=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/Password/ {print $2}')
sid=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/shortsid/ {print $2}')
username=$(jq --argjson index "$index" -r '.inbounds[0].settings.clients[$index].email' $XRAY_PATH_CONFIG)
sni=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' $XRAY_PATH_CONFIG)
ip=$(hostname -I | awk '{print $1}')
link="$protocol://$uuid@$ip?security=reality&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid&alpn=h2&type=tcp&flow=xtls-rprx-vision&encryption=none&packetEncoding=xudp#vless-reality-cloud-warp-$username"
echo ""
echo "Ссылка для подключения":
echo "$link"
else
echo "Пользователь с таким именем уже существует. Попробуйте снова." 
fi
EOF
chmod +x /usr/local/bin/xraynewuser


# Исполняемый файл для удаления клиентов
touch /usr/local/bin/xrayrmuser
cat << 'EOF' > /usr/local/bin/xrayrmuser
#!/bin/bash
emails=($(jq -r '.inbounds[0].settings.clients[].email' "$XRAY_PATH_CONFIG"))

if [[ ${#emails[@]} -eq 0 ]]; then
    echo "Нет клиентов для удаления."
    exit 1
fi

echo "Список клиентов:"
for i in "${!emails[@]}"; do
    echo "$((i+1)). ${emails[$i]}"
done

read -p "Введите номер клиента для удаления: " choice

if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#emails[@]} )); then
    echo "Ошибка: номер должен быть от 1 до ${#emails[@]}"
    exit 1
fi

selected_email="${emails[$((choice - 1))]}"

jq --arg email "$selected_email" \
   '(.inbounds[0].settings.clients) |= map(select(.email != $email))' \
   "$XRAY_PATH_CONFIG" > tmp && mv tmp "$XRAY_PATH_CONFIG"

systemctl restart xray

echo "Клиент $selected_email удалён."
EOF
chmod +x /usr/local/bin/xrayrmuser

# исполняемый файл для ссылки основного пользователя
touch /usr/local/bin/xraymainuser
cat << 'EOF' > /usr/local/bin/xraymainuser
#!/bin/bash
protocol=$(jq -r '.inbounds[0].protocol' $XRAY_PATH_CONFIG)
echo "$protocol"
uuid=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/uuid/ {print $2}')
pbk=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/Password/ {print $2}')
sid=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/shortsid/ {print $2}')
sni=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' $XRAY_PATH_CONFIG)
ip=$(hostname -I | awk '{print $1}')
link="$protocol://$uuid@$ip?security=reality&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid&alpn=h2&type=tcp&flow=xtls-rprx-vision&packetEncoding=xudp&encryption=none#vless-reality-cloud-warp-main"
echo ""
echo "Ссылка для подключения":
echo "$link"
EOF
chmod +x /usr/local/bin/xraymainuser

# Исполняемый файл для вывода списка пользователей и создания ссылкок
touch /usr/local/bin/xraysharelink
cat << 'EOF' > /usr/local/bin/xraysharelink
#!/bin/bash
emails=($(jq -r '.inbounds[0].settings.clients[].email' $XRAY_PATH_CONFIG))

for i in "${!emails[@]}"; do
   echo "$((i + 1)). ${emails[$i]}"
done

read -p "Выберите клиента: " client

if ! [[ "$client" =~ ^[0-9]+$ ]] || (( client < 1 || client > ${#emails[@]} )); then
    echo "Ошибка: номер должен быть от 1 до ${#emails[@]}"
    exit 1
fi

selected_email="${emails[$((client - 1))]}"


index=$(jq --arg email "$selected_email" '.inbounds[0].settings.clients | to_entries[] | select(.value.email == $email) | .key'  $XRAY_PATH_CONFIG)
protocol=$(jq -r '.inbounds[0].protocol' $XRAY_PATH_CONFIG)
uuid=$(jq --argjson index "$index" -r '.inbounds[0].settings.clients[$index].id' $XRAY_PATH_CONFIG)
pbk=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/Password/ {print $2}')
sid=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/shortsid/ {print $2}')
username=$(jq --argjson index "$index" -r '.inbounds[0].settings.clients[$index].email' $XRAY_PATH_CONFIG)
sni=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' $XRAY_PATH_CONFIG)
ip=$(curl -4 -s icanhazip.com)
link="$protocol://$uuid@$ip?security=reality&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid&alpn=h2&type=tcp&flow=xtls-rprx-vision&packetEncoding=xudp&encryption=none##vless-reality-cloud-warp-$username"
echo ""
echo "Ссылка для подключения":
echo "$link"
EOF
chmod +x /usr/local/bin/xraysharelink

}

install_xray() {
  echo "$INFO Installing Xray"
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

  [ -f /usr/local/etc/xray/.keys ] && rm /usr/local/etc/xray/.keys
  touch /usr/local/etc/xray/.keys
  echo "shortsid: $(openssl rand -hex 8)" >> /usr/local/etc/xray/.keys
  echo "uuid: $(xray uuid)" >> /usr/local/etc/xray/.keys
  xray x25519 >> /usr/local/etc/xray/.keys
}

main() {
  apt update && apt upgrade
  apt install -y dnsutils iptables iptables-persistent curl fail2ban jq openssl 

  install_xray
  set_xray_config
  apply_sysctl
  set_protocols_forwarding
  add_commands
}

main


echo "$INFO Xray-core успешно установлен"
xraymainuser

# Создаем файл с подсказками
touch $HOME/help
cat << 'EOF' > $HOME/help

Команды для управления пользователями Xray:

    xraymainuser - выводит ссылку для подключения основного пользователя
    xraynewuser - создает нового пользователя
    xrayrmuser - удаление пользователей
    xraysharelink - выводит список пользователей и позволяет создать для них ссылки для подключения



Файл конфигурации находится по адресу:

    $XRAY_PATH_CONFIG

Команда для перезагрузки ядра Xray:

    systemctl restart xray

EOF
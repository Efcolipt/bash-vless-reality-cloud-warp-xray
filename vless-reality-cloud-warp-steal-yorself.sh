#/bin/bash
set -e

INFO="[INFO]"
WARN="[WARN]"
ERROR="[ERROR]"

WORKSPACE_PATH=/opt/vps

BASE_GIT_PATH="https://raw.githubusercontent.com/Efcolipt/bash-vless-reality-cloud-warp-xray/refs/heads/main"
GIT_SERVER_CONFIGS_PATH="$BASE_GIT_PATH/configs/server"

SSH_USER=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8; echo)
SSH_USER_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13; echo)
SSH_PORT=$(shuf -i 1499-31999 -n 1)

export CADDY_PORT=$(shuf -i 32000-62000 -n 1)

export XRAY_XHTTP_PATH=$(openssl rand -hex 12)

#######################################
# Logging / errors
#######################################
die() { echo "$ERROR $*" >&2; exit 1; }
log() { echo "$INFO $*"; }
warn() { echo "$WARN $*" >&2; }


[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Please run this script with root privilege"

set_domain() {
  read -ep "Enter your domain:"$'\n' INPUT_SERVER_DOMAIN

  export SERVER_DOMAIN=$(echo $INPUT_SERVER_DOMAIN | idn)

  SERVER_IPS=$(hostname -I)

  RESOLVED_IP=$(dig +short $SERVER_DOMAIN | tail -n1)

  if [ -z "$RESOLVED_IP" ]; then
    echo "Warning: Domain has no DNS record"
    read -ep "Are you sure? That domain has no DNS record. If you didn't add that you will have to restart xray and caddy by yourself [y/N]"$'\n' prompt_response
    if [[ "$prompt_response" =~ ^([yY])$ ]]; then
      echo "Ok, proceeding without DNS verification"
    else 
      echo "Come back later"
      exit 1
    fi
  else
    local MATCH_FOUND=false
    for SERVER_IP in "${SERVER_IPS[@]}"; do
      if [ "$RESOLVED_IP" == "$SERVER_IP" ]; then
        MATCH_FOUND=true
        break
      fi
    done
    
    if [ "$MATCH_FOUND" = true ]; then
      echo "✓ DNS record points to this server ($RESOLVED_IP)"
    else
      echo "Warning: DNS record exists but points to different IP"
      echo "  Domain resolves to: $RESOLVED_IP"
      echo "  This server's IPs: ${SERVER_IPS[*]}"
      exit 1
    fi
  fi
}

install_docker_compose() {
  log "Installing Docker Compose"
  wget -qO- "$GIT_SERVER_CONFIGS_PATH/compose" | envsubst > "$WORKSPACE_PATH/docker-compose.yml"
}

install_caddy() {
  log "Installing Caddy"

  wget -qO- "$GIT_SERVER_CONFIGS_PATH/confluence" | envsubst > "$WORKSPACE_PATH/caddy/templates/index.html"
  wget -qO- "$GIT_SERVER_CONFIGS_PATH/caddyfile" | envsubst > "$WORKSPACE_PATH/caddy/Caddyfile"
}

get_warp() {
  log "Get warp config"
  local WARP_INFO="$(curl -fsSL https://warp-reg.vercel.app | bash)"

  local WARP_PRIV="$(jq -er '.private_key'   <<<"$WARP_INFO")"
  local WARP_PUB="$(jq -er '.public_key'    <<<"$WARP_INFO")"
  local WARP_V6="$(jq -er '.v6'             <<<"$WARP_INFO")"
  local WARP_RESERVED="$(jq -er '.reserved_str' <<<"$WARP_INFO")"

  [[ -n "$WARP_PRIV" && -n "$WARP_PUB" && -n "$WARP_V6" && -n "$WARP_RESERVED" ]] || die "Failed to parse warp-reg output"

  export WARP_PRIV WARP_PUB WARP_V6 WARP_RESERVED
}

install_xray() {
  log "Installing Xray"
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

  local KEYS="$(xray x25519)"

  export XRAY_PRIV="$(awk -F': ' '/PrivateKey/ {print $2; exit}' <<< "$KEYS")"
  export XRAY_PUB="$(awk -F': ' '/Password/ {print $2; exit}' <<< "$KEYS")"
  export XRAY_UUID="$(xray uuid)"
  export XRAY_EMAIL="$(openssl rand -hex 12)"
  export SHORT_ID="$(openssl rand -hex 8)"

  get_warp

  wget -qO- "$GIT_SERVER_CONFIGS_PATH/xray-config.json" | envsubst > "$WORKSPACE_PATH/xray/config.json"
}

install_vps() {
  mkdir -p "$WORKSPACE_PATH/caddy/templates"
  mkdir -p "$WORKSPACE_PATH/xray"

  install_docker_compose
  install_caddy
  install_xray
}

install_deps() {
  log "Installing deps"
  apt update
  apt install dnsutils iptables fail2ban netfilter-persistent iptables-persistent curl jq openssl -y


  if ! command -v docker 2>&1 >/dev/null; then
    curl -fsSL https://get.docker.com | sh
  fi
}

iptables_add() {
  iptables -C "$@" 2>/dev/null || iptables -A "$@"
}

set_iptables_config() {
  log "Set iptables config"
  iptables_add INPUT -p icmp -j ACCEPT
  iptables_add INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables_add INPUT -p tcp -m state --state NEW -m tcp --dport "$SSH_PORT" -j ACCEPT
  iptables_add INPUT -p tcp -m tcp --dport 80 -j ACCEPT
  iptables_add INPUT -p tcp -m tcp --dport 443 -j ACCEPT
  iptables_add INPUT -i lo -j ACCEPT
  iptables_add OUTPUT -o lo -j ACCEPT
  iptables -P INPUT DROP
  netfilter-persistent save
}

set_nets() {
  log "Set nets bbr"
 cat >/etc/sysctl.d/99-bbr-tune.conf <<'EOF'
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.netdev_max_backlog=10000
net.core.somaxconn=4096

net.ipv4.tcp_syncookies=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=30

net.ipv4.tcp_keepalive_time=1200
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_keepalive_intvl=30

net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_max_tw_buckets=5000

net.ipv4.tcp_fastopen=3

net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864

net.ipv4.udp_mem=4096 51200 102400

net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0

net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

 sysctl --system >/dev/null
}

start_services() {
  docker run -v "$WORKSPACE_PATH/caddy/Caddyfile:$WORKSPACE_PATH/Caddyfile" --rm caddy caddy fmt --overwrite "$WORKSPACE_PATH/Caddyfile"
  docker compose -f "$WORKSPACE_PATH/docker-compose.yml" up -d --remove-orphans
}

set_ssh_access() {
  log "Set ssh access"
  local INPUT_SSH_PUB
  read -ep "Enter SSH public key:"$'\n' INPUT_SSH_PUB

  echo "$INPUT_SSH_PUB" > ./test_pbk

  ssh-keygen -l -f ./test_pbk

  local PBK_STATUS=$(echo $?)

  if [ "$PBK_STATUS" -eq 255 ]; then
    echo "Can't verify the public key. Try again and make sure to include 'ssh-rsa' or 'ssh-ed25519' followed by 'user@pcname' at the end of the file."
    exit
  fi

  rm ./test_pbk

  useradd $SSH_USER -s /bin/bash
  usermod -aG sudo $SSH_USER

  echo $SSH_USER:$SSH_USER_PASS | chpasswd

  mkdir -p /home/$SSH_USER/.ssh
  touch /home/$SSH_USER/.ssh/authorized_keys

  echo $INPUT_SSH_PUB >> /home/$SSH_USER/.ssh/authorized_keys

  chmod 700 /home/$SSH_USER/.ssh/
  chmod 600 /home/$SSH_USER/.ssh/authorized_keys
  chown $SSH_USER:$SSH_USER -R /home/$SSH_USER
  usermod -aG docker $SSH_USER

  sed -i "s/^#\?Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
  sed -i "s/^#\?PasswordAuthentication .*/PasswordAuthentication no/" /etc/ssh/sshd_config
  sed -i "s/^#\?PermitRootLogin .*/PermitRootLogin no/" /etc/ssh/sshd_config

    
  systemctl daemon-reload
  systemctl restart ssh
}

set_fail2ban() {
  log "Configuring fail2ban"

  mkdir -p /etc/fail2ban/jail.d

  cat >/etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
maxretry = 6
findtime = 1h
bantime = 1d
ignoreip = 127.0.0.1/8
EOF

  systemctl enable fail2ban
  systemctl restart fail2ban
}


main() {
  debconf-set-selections <<EOF
iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
EOF

  install_deps

  set_domain

  set_ssh_access

  install_vps
  set_iptables_config
  set_nets
  set_fail2ban

  start_services

  echo "New user for ssh: $SSH_USER, password for user: $SSH_USER_PASS. New port for SSH: $SSH_PORT."
  echo "vless://$XRAY_UUID@$SERVER_DOMAIN:443?security=reality&sni=$SERVER_DOMAIN&fp=chrome&pbk=$XRAY_PUB&sid=$SHORT_ID&alpn=h2%2Chttp%2F1.1&type=tcp&flow=xtls-rprx-vision&encryption=none&packetEncoding=xudp#$XRAY_EMAIL"
}

main

#/bin/bash
set -e

INFO="[INFO]"
WARN="[WARN]"
ERROR="[ERROR]"

WORKSPACE_PATH=/opt/vps

BASE_GIT_PATH="https://raw.githubusercontent.com/Efcolipt/bash-vless-reality-cloud-warp-xray/refs/heads/main"
GIT_SERVER_CONFIGS_PATH="$BASE_GIT_PATH/configs/server"

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Please run this script with root privilege"

SSH_USER=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8; echo)
SSH_USER_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13; echo)
SSH_PORT=$(shuf -i 1499-31999 -n 1)

export CADDY_PORT=$(shuf -i 32000-62000 -n 1)

export XRAY_XHTTP_PATH=$(openssl rand -hex 12)

#######################################
# Logging / errors
#######################################
die()  { printf '\033[31m%s\033[0m %s\n' "$ERROR" "$*" >&2; exit 1; }
warn() { printf '\033[33m%s\033[0m %s\n' "$WARN"  "$*" >&2; }
log()  { printf '\033[32m%s\033[0m %s\n' "$INFO"  "$*"; }


ask() { read -ep "$1 [y/N] " a; [[ "$a" =~ ^[Yy]$ ]]; }

set_domain() {
  read -ep "Enter your domain:"$'\n' INPUT_SERVER_DOMAIN

  export SERVER_DOMAIN="$(echo "$INPUT_SERVER_DOMAIN" | idn)"

  read -ra SERVER_IPS <<< "$(hostname -I)"

  SERVER_IPS=($(printf "%s\n" "${SERVER_IPS[@]}" | grep -Ev '^172\.|^10\.|^192\.168\.'))

  RESOLVED_IP="$(dig +short "$SERVER_DOMAIN" | grep -E '^[0-9.]+' | tail -n1)"

  if [ -z "$RESOLVED_IP" ]; then
    warn "Domain has no DNS record"
    ask "Proceed without DNS verification? If you didn't add that you will have to restart xray and caddy by yourself" || exit 1
    log "Proceeding without DNS verification"
    return
  fi

  for SERVER_IP in "${SERVER_IPS[@]}"; do
    if [ "$RESOLVED_IP" = "$SERVER_IP" ]; then
      log "✓ DNS record points to this server ($RESOLVED_IP)"
      return
    fi
  done

  warn "Domain resolves to: $RESOLVED_IP"
  warn "This server's IPs: ${SERVER_IPS[*]}"
  die "DNS record exists but points to different IP"
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
  local WARP_INFO

  for i in 1 2 3; do
    WARP_INFO="$(curl -fsSL https://warp-reg.vercel.app | bash 2>/dev/null || true)"

    echo "$WARP_INFO" | jq -e . >/dev/null 2>&1 && break

    warn "warp-reg returned non-JSON (try $i/3)"
    sleep 2
  done

  echo "$WARP_INFO" | jq -e . >/dev/null 2>&1 || die "Failed to get valid warp config"

  WARP_PRIV="$(jq -er '.private_key'   <<<"$WARP_INFO")"
  WARP_PUB="$(jq -er '.public_key'    <<<"$WARP_INFO")"
  WARP_V6="$(jq -er '.v6'             <<<"$WARP_INFO")"
  WARP_RESERVED="$(jq -er '.reserved_str' <<<"$WARP_INFO")"

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
  apt install idn dnsutils iptables fail2ban netfilter-persistent iptables-persistent curl jq openssl -y


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
    warn "Can't verify the public key. Try again and make sure to include 'ssh-rsa' or 'ssh-ed25519' followed by 'user@pcname' at the end of the file."
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

uninstall() {
  if command -v docker >/dev/null 2>&1 && [ -f "$WORKSPACE_PATH/docker-compose.yml" ]; then
    log "Stopping docker compose stack"
    docker compose -f "$WORKSPACE_PATH/docker-compose.yml" down --remove-orphans 2>/dev/null || true
  fi

  if command -v xray >/dev/null 2>&1; then
    log "Removing Xray"
    bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove 2>/dev/null || true
  fi

  rm -rf "$WORKSPACE_PATH" 2>/dev/null || true

  if [ -f /etc/sysctl.d/99-bbr-tune.conf ]; then
    log "Removing sysctl tuning"
    rm -f /etc/sysctl.d/99-bbr-tune.conf
    sysctl --system >/dev/null 2>&1 || true
  fi

  if dpkg -l | grep -q '^ii  fail2ban'; then
    log "Removing Fail2ban completely"
    systemctl stop fail2ban 2>/dev/null || true
    systemctl disable fail2ban 2>/dev/null || true

    apt-get purge -y fail2ban 2>/dev/null || true
    rm -rf /etc/fail2ban /var/lib/fail2ban 2>/dev/null || true
  fi

  apt-get autoremove -y 2>/dev/null || true

  warn "NOTE: iptables rules were NOT flushed (to avoid SSH lockout)."
}


judgment_parameters() {
  INSTALL=0
  UNINSTALL=0

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      install) INSTALL=1 ;;
      uninstall|remove) UNINSTALL=1 ;;
      *) echo "Unknown option: $1"; return 1 ;;
    esac
    shift
  done

  (( INSTALL + UNINSTALL == 0 )) && INSTALL=1
  (( INSTALL + UNINSTALL > 1 )) && { echo "Choose one: install|uninstall"; return 1; }
}

main() {
  judgment_parameters "$@" || exit 1
  
  if (( UNINSTALL )); then
    uninstall
    exit 0
  fi

  debconf-set-selections <<EOF
iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
EOF

  install_deps

  set_domain

  ask "Add new ssh user?" && set_ssh_access

  install_vps

  ask "Apply iptables firewall?"  && set_iptables_config

  set_nets

  ask "Install Fail2ban for SSH?" && set_fail2ban

  start_services

  log "New user for ssh: $SSH_USER, password for user: $SSH_USER_PASS. New port for SSH: $SSH_PORT."
  log "vless://$XRAY_UUID@$SERVER_DOMAIN:443?security=reality&sni=$SERVER_DOMAIN&fp=chrome&pbk=$XRAY_PUB&sid=$SHORT_ID&alpn=h2%2Chttp%2F1.1&type=tcp&flow=xtls-rprx-vision&encryption=none&packetEncoding=xudp#$XRAY_EMAIL"
}

main "$@"

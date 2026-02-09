#!/bin/bash
set -euo pipefail
set +x
trap 'echo "[FATAL] exit on line $LINENO, status=$?" >&2' ERR



# ============================================================
# Global constants and paths
# ============================================================

INFO="[INFO]"
WARN="[WARN]"
ERROR="[ERROR]"

WORKSPACE_PATH="/opt/vps"
BASE_GIT_PATH="https://raw.githubusercontent.com/Efcolipt/bash-vless-reality-cloud-warp-xray/refs/heads/main"
GIT_SERVER_CONFIGS_PATH="$BASE_GIT_PATH/configs/server"

# ============================================================
# Logging helpers (colored output)
# ============================================================

die()  { printf '\033[31m%s\033[0m %s\n' "$ERROR" "$*" >&2; exit 1; }
warn() { printf '\033[33m%s\033[0m %s\n' "$WARN"  "$*" >&2; }
log()  { printf '\033[32m%s\033[0m %s\n' "$INFO"  "$*"; }

# ============================================================
# Basic helpers
# ============================================================

ask() {
  read -rp "$1 [y/N] " a
  [[ "$a" =~ ^[Yy]$ ]]
}

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Please run this script as root"
}

# ============================================================
# Platform / package manager detection (Linux-only)
# ============================================================

detect_platform() {
  [[ "$(uname -s)" == "Linux" ]] || die "This script supports Linux only"

  if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
    PKG_UPDATE="apt-get update -y"
    PKG_INSTALL="apt-get install -y"
    PKG_REMOVE="apt-get purge -y"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
    PKG_UPDATE="dnf -y makecache"
    PKG_INSTALL="dnf -y install"
    PKG_REMOVE="dnf -y remove"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
    PKG_UPDATE="yum -y makecache"
    PKG_INSTALL="yum -y install"
    PKG_REMOVE="yum -y remove"
  else
    die "Unsupported package manager (apt/dnf/yum required)"
  fi

  log "Detected package manager: $PKG_MGR"
}

# ============================================================
# Runtime-generated variables
# ============================================================

init_runtime_vars() {
  export CADDY_PORT="$(shuf -i 32000-62000 -n 1)"
  export XRAY_XHTTP_PATH="$(openssl rand -hex 12)"
}

# ============================================================
# Domain and DNS validation
# ============================================================

set_domain() {
  read -rp "Enter your domain:"$'\n' INPUT_SERVER_DOMAIN

  export SERVER_DOMAIN="$(idn <<<"$INPUT_SERVER_DOMAIN")" || die "Invalid domain"

  read -ra SERVER_IPS <<<"$(hostname -I)"

  SERVER_IPS=($(printf "%s\n" "${SERVER_IPS[@]}" | grep -Ev '^10\.|^172\.|^192\.168\.'))
  RESOLVED_IP="$(dig +short "$SERVER_DOMAIN" | grep -E '^[0-9.]+' | tail -n1)"

  if [[ -z "$RESOLVED_IP" ]]; then
    warn "Domain has no DNS record"
    ask "Proceed without DNS verification?" || exit 1
    return
  fi

  for ip in "${SERVER_IPS[@]}"; do
    [[ "$RESOLVED_IP" == "$ip" ]] && {
      log "✓ DNS record points to this server ($RESOLVED_IP)"
      return
    }
  done

  warn "Domain resolves to: $RESOLVED_IP"
  warn "Server IPs: ${SERVER_IPS[*]}"
  die "DNS record points to a different server"
}

# ============================================================
# Dependency installation (portable)
# ============================================================

install_packages() {
  case "$PKG_MGR" in
    apt)
      debconf-set-selections <<EOF
iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
EOF
      $PKG_INSTALL \
        idn bind9-dnsutils iptables \
        netfilter-persistent iptables-persistent \
        curl jq openssl
      ;;
    dnf|yum)
      $PKG_INSTALL epel-release || true
      $PKG_INSTALL \
        idn bind-utils iptables iptables-services \
        curl jq openssl
      ;;
  esac
}

install_deps() {
  log "Installing dependencies"
  $PKG_UPDATE
  install_packages

  if ! command -v docker >/dev/null 2>&1; then
    log "Installing Docker"
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh
    rm -f /tmp/get-docker.sh
  fi
}

# ============================================================
# iptables helpers
# ============================================================

iptables_add() {
  iptables -C "$@" 2>/dev/null || iptables -A "$@"
}

iptables_save() {
  case "$PKG_MGR" in
    apt) netfilter-persistent save ;;
    dnf|yum) service iptables save 2>/dev/null || true ;;
  esac
}

set_iptables_config() {
  log "Configuring iptables firewall"

  iptables_add INPUT -p icmp -j ACCEPT
  iptables_add INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables_add INPUT -p tcp -m tcp --dport 80 -j ACCEPT
  iptables_add INPUT -p tcp -m tcp --dport 443 -j ACCEPT
  iptables_add INPUT -i lo -j ACCEPT
  iptables_add OUTPUT -o lo -j ACCEPT

  iptables -P INPUT DROP
  iptables_save
}

# ============================================================
# Network tuning (BBR)
# ============================================================

set_nets() {
  log "Applying network tuning (BBR)"

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

# ============================================================
# Fail2ban
# ============================================================

set_fail2ban() {
  log "Configuring Fail2ban"

  $PKG_INSTALL fail2ban

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

# ============================================================
# Xray / WARP / Caddy / Docker
# ============================================================

get_warp() {
  log "Fetching Cloudflare WARP config"
  local WARP_INFO

  for _ in 1 2 3; do
    WARP_INFO="$(curl -fsSL https://warp-reg.vercel.app | bash 2>/dev/null || true)"
    echo "$WARP_INFO" | jq -e . >/dev/null 2>&1 && break
    sleep 2
  done

  echo "$WARP_INFO" | jq -e . >/dev/null || die "Failed to get WARP config"

  export WARP_PRIV="$(jq -r '.private_key' <<<"$WARP_INFO")"
  export WARP_PUB="$(jq -r '.public_key' <<<"$WARP_INFO")"
  export WARP_V6="$(jq -r '.v6' <<<"$WARP_INFO")"
  export WARP_RESERVED="$(jq -r '.reserved_str' <<<"$WARP_INFO")"
}

install_xray() {
  export XRAY_PRIV="$(docker run --rm ghcr.io/xtls/xray-core x25519 | head -n1 | cut -d' ' -f 2)"
  export XRAY_PUB="$(docker run --rm ghcr.io/xtls/xray-core x25519 -i $XRAY_PRIV | tail -2 | head -1 | cut -d' ' -f 2)"
  export XRAY_UUID="$(docker run --rm ghcr.io/xtls/xray-core uuid)"
  export XRAY_EMAIL="$(openssl rand -hex 12)"
  export SHORT_ID="$(openssl rand -hex 8)"

  get_warp

  mkdir -p "$WORKSPACE_PATH/xray"
  wget -qO- "$GIT_SERVER_CONFIGS_PATH/xray-config.json" | envsubst >"$WORKSPACE_PATH/xray/config.json"
}

install_vps() {
  mkdir -p "$WORKSPACE_PATH/caddy/templates"

  wget -qO- "$GIT_SERVER_CONFIGS_PATH/compose" | envsubst >"$WORKSPACE_PATH/docker-compose.yml"
  wget -qO- "$GIT_SERVER_CONFIGS_PATH/confluence" | envsubst >"$WORKSPACE_PATH/caddy/templates/index.html"
  wget -qO- "$GIT_SERVER_CONFIGS_PATH/caddyfile" | envsubst >"$WORKSPACE_PATH/caddy/Caddyfile"

  install_xray
}

# ============================================================
# Uninstall logic (script-owned only)
# ============================================================

uninstall() {
  if command -v docker >/dev/null && [[ -f "$WORKSPACE_PATH/docker-compose.yml" ]]; then
    log "Docker down"
    docker compose -f "$WORKSPACE_PATH/docker-compose.yml" down --remove-orphans || true
  fi

  log "Remove workspace"
  rm -rf "$WORKSPACE_PATH"

  log "Remove bbr tune"
  rm -f /etc/sysctl.d/99-bbr-tune.conf
  sysctl --system >/dev/null || true

  if systemctl list-unit-files | grep -q fail2ban; then
    log "Remove fail2ban"
    systemctl stop fail2ban || true
    $PKG_REMOVE fail2ban || true
  fi

  warn "iptables rules were NOT flushed (SSH-safe)"

  exit 0
}

# ============================================================
# Argument parsing
# ============================================================

judgment_parameters() {
  INSTALL=0
  REMOVE=0

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      install) INSTALL=1 ;;
      uninstall|remove) REMOVE=1 ;;
      *) echo "Unknown option: $1"; return 1 ;;
    esac
    shift
  done

  if (( INSTALL + REMOVE == 0 )); then
    INSTALL=1
  elif (( INSTALL + REMOVE > 1 )); then
    echo "Choose only one action: install | uninstall"
    return 1
  fi
}

add_new_ssh_user() {
  log "Add new user SSH"
  local INPUT_SSH_PUB
  read -rp "Enter SSH public key:"$'\n' INPUT_SSH_PUB

  echo "$INPUT_SSH_PUB" > ./test_pbk

  ssh-keygen -l -f ./test_pbk

  local PBK_STATUS=$(echo $?)

  if [ "$PBK_STATUS" -eq 255 ]; then
    die "Can't verify the public key. Try again and make sure to include 'ssh-rsa' or 'ssh-ed25519' followed by 'user@pcname' at the end of the file."
  fi

  rm ./test_pbk

  SSH_USER="$(head -c 64 /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)"
  SSH_USER_PASS="$(head -c 64 /dev/urandom | tr -dc A-Za-z0-9 | head -c 13)"
  SSH_PORT="$(shuf -i 1499-31999 -n 1)"

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

  iptables_add INPUT -p tcp -m state --state NEW -m tcp --dport "$SSH_PORT" -j ACCEPT

  iptables_save
}

# ============================================================
# Main entrypoint
# ============================================================

show_info() {
  clear
  
  if [[ -n "${SSH_USER:-}" ]]; then
    log "New user for ssh: $SSH_USER, password for user: $SSH_USER_PASS. New port for SSH: $SSH_PORT."
  fi

  log "vless://$XRAY_UUID@$SERVER_DOMAIN:443?security=reality&sni=$SERVER_DOMAIN&fp=chrome&pbk=$XRAY_PUB&sid=$SHORT_ID&alpn=h2%2Chttp%2F1.1&type=tcp&flow=xtls-rprx-vision&encryption=none&packetEncoding=xudp#$XRAY_EMAIL"
}

main() {
  require_root
  judgment_parameters "$@" || return 1

  detect_platform

  if [[ "$REMOVE" -eq 1 ]]; then
    uninstall
  fi

  install_deps
  init_runtime_vars

  set_domain
  install_vps

  set_nets
  set_iptables_config
  
  ask "Install Fail2ban for SSH?" && set_fail2ban
  ask "Add new SSH user (access by pubkey)?" && add_new_ssh_user

  docker run -v "$WORKSPACE_PATH/caddy/Caddyfile:$WORKSPACE_PATH/Caddyfile" --rm caddy caddy fmt --overwrite "$WORKSPACE_PATH/Caddyfile"
  docker compose -f "$WORKSPACE_PATH/docker-compose.yml" up -d --remove-orphans
  docker rmi ghcr.io/xtls/xray-core:latest caddy:latest

  show_info
}

main "$@"

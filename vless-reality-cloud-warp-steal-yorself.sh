#!/usr/bin/env bash
set -e

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

INFO="[INFO]"
WARN="[WARN]"
ERROR="[ERROR]"

WORKSPACE_PATH="/opt/vps"
BASE_GIT_PATH="https://raw.githubusercontent.com/Efcolipt/bash-vless-reality-cloud-warp-xray/refs/heads/main"
GIT_SERVER_CONFIGS_PATH="$BASE_GIT_PATH/configs/server"

export XRAY_IMAGE="ghcr.io/xtls/xray-core:26.2.6"
export CADDY_IMAGE="caddy:2.9"

die()  { printf '\033[31m%s\033[0m %s\n' "$ERROR" "$*" >&2; exit 1; }
warn() { printf '\033[33m%s\033[0m %s\n' "$WARN"  "$*" >&2; }
log()  { printf '\033[32m%s\033[0m %s\n' "$INFO"  "$*"; }

ask() {
  read -rp "$1 [y/N] " a
  [[ "$a" =~ ^[Yy]$ ]]
}

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Please run this script as root"
}

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

init_runtime_vars() {
  export CADDY_PORT="$(shuf -i 32000-62000 -n 1)"
  export XRAY_XHTTP_PATH="$(openssl rand -hex 12)"

  SSH_PORT="22"
}

set_domain() {
  local INPUT_SERVER_DOMAIN

  read -rp "Enter your domain:"$'\n' INPUT_SERVER_DOMAIN

  export SERVER_DOMAIN="$(idn <<<"$INPUT_SERVER_DOMAIN")" || die "Invalid domain"

  local SERVER_IPV4="$(hostname -I | tr ' ' '\n' \
    | grep -E '^[0-9.]+' \
    | grep -Ev '^10\.|^172\.|^192\.168\.' \
    | head -n1)"

  local SERVER_IPV6="$(ip -6 addr show scope global \
    | awk '/inet6/ {print $2}' \
    | cut -d/ -f1 \
    | head -n1)"

  mapfile -t RESOLVED_A < <(dig +short A "$SERVER_DOMAIN")
  mapfile -t RESOLVED_AAAA < <(dig +short AAAA "$SERVER_DOMAIN")

  if [[ ${#RESOLVED_A[@]} -eq 0 ]]; then
    die "Domain has no A record"
  fi

  if ! printf "%s\n" "${RESOLVED_A[@]}" | grep -qx "$SERVER_IPV4"; then
    warn "Domain A records: ${RESOLVED_A[*]}"
    warn "Server IPv4:      $SERVER_IPV4"
    die "IPv4 mismatch"
  fi

  if [[ -n "$SERVER_IPV6" ]]; then
    if [[ ${#RESOLVED_AAAA[@]} -eq 0 ]]; then
      die "Server has IPv6 but domain has no AAAA record"
    fi

    if ! printf "%s\n" "${RESOLVED_AAAA[@]}" | grep -qx "$SERVER_IPV6"; then
      warn "Domain AAAA records: ${RESOLVED_AAAA[*]}"
      warn "Server IPv6:         $SERVER_IPV6"
      die "IPv6 mismatch"
    fi

    DOMAIN_STRATEGY="UseIP"
  else
    DOMAIN_STRATEGY="UseIPv4"
  fi

  export DOMAIN_STRATEGY
}

install_packages() {
  case "$PKG_MGR" in
    apt)
      $PKG_INSTALL \
        idn bind9-dnsutils nftables  \
        curl jq openssl
      ;;
    dnf|yum)
      $PKG_INSTALL epel-release || true
      $PKG_INSTALL \
        idn bind-utils nftables  \
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

svc_stop_disable_mask() {
  for svc in "$@"; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    systemctl mask "$svc" 2>/dev/null || true
  done
}

svc_unmask() {
  for svc in "$@"; do
    systemctl unmask "$svc" 2>/dev/null || true
  done
}

set_firewall() {
  log "Configuring firewall"

  svc_stop_disable_mask \
    ufw firewalld iptables ip6tables ebtables \
    netfilter-persistent iptables-persistent

  cat >/etc/nftables.conf <<EOF
flush ruleset

table inet filter {

  chain input {
    type filter hook input priority 0;
    policy drop;

    # Loopback
    iif lo accept

    # Established connections
    ct state established,related accept

    # ICMP (v4 + v6)
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept

    # SSH
    tcp dport $SSH_PORT accept

    # HTTP / HTTPS
    tcp dport 80 accept
    tcp dport 443 accept
  }

  chain forward {
    type filter hook forward priority 0;
    policy drop;
  }

  chain output {
    type filter hook output priority 0;
    policy accept;
  }
}
EOF

  nft -f /etc/nftables.conf || die "Failed to apply nft rules"

  systemctl enable nftables
  systemctl restart nftables

  nft list ruleset >/dev/null 2>&1 || die "nftables not active"

  log "Firewall successfully configured"
}

reset_firewall() {
  systemctl stop nftables 2>/dev/null || true
  systemctl disable nftables 2>/dev/null || true

  nft flush ruleset 2>/dev/null || true

  cat >/etc/nftables.conf <<'EOF'
flush ruleset
EOF

  svc_unmask \
    ufw firewalld iptables ip6tables ebtables \
    netfilter-persistent iptables-persistent
}

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
  mkdir -p "$WORKSPACE_PATH/xray"
  
  local XRAY_KEYS="$(docker run --rm "$XRAY_IMAGE" x25519)"
  
  export XRAY_PRIV="$(awk -F': ' '/PrivateKey/ {print $2; exit}' <<<"$XRAY_KEYS")"
  export XRAY_PUB="$(awk -F': ' '/Password/  {print $2; exit}' <<<"$XRAY_KEYS")"
  export XRAY_UUID="$(docker run --rm "$XRAY_IMAGE" uuid)"
  export XRAY_EMAIL="$(openssl rand -hex 12)"
  export SHORT_ID="$(openssl rand -hex 8)"

  get_warp

  wget -qO- "$GIT_SERVER_CONFIGS_PATH/xray-config.json" | envsubst >"$WORKSPACE_PATH/xray/config.json"
}

instsall_caddy() {
  mkdir -p "$WORKSPACE_PATH/caddy/templates"

  wget -qO- "$GIT_SERVER_CONFIGS_PATH/confluence.html" | envsubst >"$WORKSPACE_PATH/caddy/templates/index.html"
  wget -qO- "$GIT_SERVER_CONFIGS_PATH/caddyfile" | envsubst >"$WORKSPACE_PATH/caddy/Caddyfile"

  docker run -v "$WORKSPACE_PATH/caddy/Caddyfile:$WORKSPACE_PATH/Caddyfile" --rm caddy caddy fmt --overwrite "$WORKSPACE_PATH/Caddyfile"
}

install_vps() {
  mkdir -p $WORKSPACE_PATH
  wget -qO- "$GIT_SERVER_CONFIGS_PATH/compose" | envsubst >"$WORKSPACE_PATH/docker-compose.yml"

  instsall_caddy
  install_xray
}

uninstall() {
  log "Starting uninstall process"

  if command -v docker >/dev/null && [[ -f "$WORKSPACE_PATH/docker-compose.yml" ]]; then
    log "Stopping Docker services"
    docker compose -f "$WORKSPACE_PATH/docker-compose.yml" down --remove-orphans || true
  fi

  log "Removing workspace"
  rm -rf "$WORKSPACE_PATH"

  if [[ -f /etc/sysctl.d/99-bbr-tune.conf ]]; then
    log "Removing BBR tuning"
    rm -f /etc/sysctl.d/99-bbr-tune.conf
    sysctl --system >/dev/null || true
  fi

  if systemctl list-unit-files | grep -q fail2ban; then
    log "Removing Fail2ban"
    systemctl stop fail2ban 2>/dev/null || true
    systemctl disable fail2ban 2>/dev/null || true
    $PKG_REMOVE fail2ban 2>/dev/null || true
  fi

  ask "Reset firewall (disable nftables)?" && reset_firewall

  warn "SSH configuration was NOT reverted"

  log "Uninstall complete"

  exit 0
}

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

  if ! ssh-keygen -l -f ./test_pbk >/dev/null 2>&1; then
    rm -f ./test_pbk
    die "Invalid SSH public key"
  fi

  rm -f ./test_pbk

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
  systemctl restart ssh 2>/dev/null || systemctl restart sshd
}

show_info() {
  clear
  
  if [[ -n "${SSH_USER:-}" ]]; then
    log "New user for ssh: $SSH_USER, password for user: $SSH_USER_PASS. New port for SSH: $SSH_PORT."
  fi

  log "vless://$XRAY_UUID@$SERVER_DOMAIN:443?security=reality&sni=$SERVER_DOMAIN&fp=chrome&pbk=$XRAY_PUB&sid=$SHORT_ID&alpn=h2%2Chttp%2F1.1&type=tcp&flow=xtls-rprx-vision&encryption=none&packetEncoding=xudp#$XRAY_EMAIL"
}

main() {
  pidof systemd >/dev/null 2>&1 || die "systemd is required"

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

  ask "Add new SSH user (access by pubkey)?" && add_new_ssh_user


  set_nets
  set_firewall
  
  ask "Install Fail2ban for SSH?" && set_fail2ban

  docker compose -f "$WORKSPACE_PATH/docker-compose.yml" up -d --remove-orphans

  show_info
}

main "$@"

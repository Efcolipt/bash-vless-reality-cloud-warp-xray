# Server basics shared by the node and the head: packages, kernel, SSH, firewall, fail2ban.

log() { printf '\033[32m==>\033[0m %s\n' "$*"; }
die() {
  printf '\033[31mError:\033[0m %s\n' "$*" >&2
  exit 1
}

require_root() { [[ $EUID -eq 0 ]] || die "Run as root."; }

install_packages() {
  command -v apt-get >/dev/null || die "Debian or Ubuntu is required."
  apt-get update -q
  # Hoster images lag months behind on kernel and OpenSSH security fixes.
  DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y -q -o Dpkg::Options::=--force-confold
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@"
}

default_interface() { ip -o -4 route show default | awk '{ print $5; exit }'; }

ssh_ports() { sshd -T | awk '$1 == "port" { print $2 }' | paste -sd, -; }

tune_kernel() {
  log "Kernel: BBR, fq and buffers sized for QUIC"
  install -m 644 "$root/config/sysctl.conf" /etc/sysctl.d/99-vpn.conf
  sysctl -q --system
  local interface
  interface="$(default_interface)"
  cat >/etc/systemd/system/qdisc-fq.service <<UNIT
[Unit]
Description=fq qdisc on $interface
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$(command -v tc) qdisc replace dev $interface root fq
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now -q qdisc-fq.service
}

ssh_access_file=/root/vpn-ssh.txt

# A new sudo user on a random port, key login only; root and passwords stop working. The access line is
# printed and kept in $ssh_access_file at once, so a later failed step cannot lock the owner out, and a
# rerun keeps that user instead of adding another one.
harden_ssh() {
  local public_key="$1" key_file port group ssh_user ssh_password
  if [[ -s "$ssh_access_file" ]]; then
    log "SSH already hardened: $(head -1 "$ssh_access_file")"
    return 0
  fi
  key_file="$(mktemp)"
  printf '%s\n' "$public_key" >"$key_file"
  ssh-keygen -l -f "$key_file" >/dev/null 2>&1 || {
    rm -f "$key_file"
    die "Not an SSH public key: $public_key"
  }
  rm -f "$key_file"

  log "SSH: new sudo user, random port, key login only"
  # SSH_USER and SSH_PORT let a remote operator know the new access before the session that started it drops.
  ssh_user="${SSH_USER:-$(shuf -n 1 -e orbit falcon cedar quartz harbor lumen nimbus ember tundra vertex)$(shuf -i 1000-9999 -n 1)}"
  ssh_password="$(openssl rand -base64 24 | tr -d '/+=' | head -c 20)"
  port="${SSH_PORT:-$(shuf -i 20000-49000 -n 1)}"
  getent group sudo >/dev/null && group=sudo || group=wheel
  useradd -m -s /bin/bash -G "$group" "$ssh_user"
  echo "$ssh_user:$ssh_password" | chpasswd
  install -d -m 700 -o "$ssh_user" -g "$ssh_user" "/home/$ssh_user/.ssh"
  printf '%s\n' "$public_key" >"/home/$ssh_user/.ssh/authorized_keys"
  chown "$ssh_user:$ssh_user" "/home/$ssh_user/.ssh/authorized_keys"
  chmod 600 "/home/$ssh_user/.ssh/authorized_keys"
  echo "$ssh_user ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/90-vpn
  chmod 440 /etc/sudoers.d/90-vpn
  visudo -c -q

  # 00- sorts before the 50-cloud-init.conf of cloud images, and sshd keeps the first value it reads.
  cat >/etc/ssh/sshd_config.d/00-vpn.conf <<CONF
Port $port
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
CONF
  sshd -t
  install -m 600 /dev/null "$ssh_access_file"
  printf 'ssh -p %s %s@<server ip>   (root and passwords are off)\nSudo password for the hoster console: %s\n' \
    "$port" "$ssh_user" "$ssh_password" >"$ssh_access_file"
  if systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
    systemctl daemon-reload
    systemctl restart ssh.socket
  else
    systemctl restart ssh
  fi
  log "SSH: $(head -1 "$ssh_access_file") — also in $ssh_access_file"
}

# protect <tcp ports> [udp ports] [udp hop range] [nft rule …]: default-drop firewall plus fail2ban on SSH;
# the rules open a port to one address.
protect() {
  local tcp_ports="$1" udp_ports="${2:-}" hop_ports="${3:-}" ssh_port_list interface udp_rule="" hop_table=""
  local rule rule_lines=""
  shift $(($# < 3 ? $# : 3))
  for rule in "$@"; do rule_lines+=$'\n\t\t'"$rule"; done
  ssh_port_list="$(ssh_ports)"
  interface="$(default_interface)"
  log "Firewall: drop everything but SSH ($ssh_port_list) and the VPN ports"
  [[ -n "$udp_ports" ]] && udp_rule="udp dport { $udp_ports } accept"
  # Hysteria2 clients hop over this range; the redirect only sees the first packet of a flow, so replies
  # to the server's own outgoing UDP (WARP, DNS) are never caught by it.
  [[ -n "$hop_ports" ]] && hop_table="table inet hysteria_hop {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname \"$interface\" udp dport $hop_ports redirect to :$hysteria_port
	}
}"
  systemctl disable --now ufw firewalld >/dev/null 2>&1 || true
  # ICMP goes before the invalid drop: conntrack marks IPv6 neighbour discovery invalid, and dropping it
  # loses the IPv6 gateway, so every IPv6 connection times out.
  cat >/etc/nftables.conf <<NFT
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iif lo accept
		ct state established,related accept
		meta l4proto { icmp, ipv6-icmp } accept
		ct state invalid drop
		tcp dport { $ssh_port_list, $tcp_ports } accept
		$udp_rule$rule_lines
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}

$hop_table
NFT
  nft -c -f /etc/nftables.conf
  systemctl enable -q nftables
  systemctl restart nftables

  cat >/etc/fail2ban/jail.d/sshd.local <<JAIL
[sshd]
enabled = true
port = $ssh_port_list
backend = systemd
banaction = nftables-multiport
maxretry = 6
findtime = 1h
bantime = 1d
JAIL
  # flush ruleset above dropped fail2ban's tables; a restart recreates them.
  systemctl enable -q fail2ban
  systemctl restart fail2ban
}

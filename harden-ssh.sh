#!/usr/bin/env bash
# SSH in two phases, so a mistake cannot lock you out of a fresh server:
#   sudo ./harden-ssh.sh "<your ssh public key>"   adds a sudo user and a random port next to 22
#   sudo ./harden-ssh.sh --lock <port>             after a key login on the new port works: key only, no root, no 22
set -euo pipefail
config=/etc/ssh/sshd_config.d/99-hardening.conf

[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }

if [[ "${1:-}" == "--lock" ]]; then
  port="${2:?usage: sudo ./harden-ssh.sh --lock <port>}"
  cat >"$config" <<CONF
Port $port
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
CONF
  sshd -t
  systemctl restart ssh
  # fail2ban watches port 22 unless its jail is told otherwise.
  if systemctl is-active --quiet fail2ban; then
    printf '[sshd]\nport = %s\n' "$port" >/etc/fail2ban/jail.d/sshd-port.conf
    systemctl restart fail2ban
  fi
  sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication) '
  exit 0
fi

public_key="${1:?usage: sudo ./harden-ssh.sh \"<your ssh public key>\"}"
user="$(shuf -n 1 -e orbit falcon cedar quartz harbor lumen nimbus ember tundra vertex)$(shuf -i 1000-9999 -n 1)"
port="$(shuf -i 20000-49000 -n 1)"
password="$(openssl rand -base64 24 | tr -d '/+=' | head -c 20)"

command -v sudo >/dev/null || { apt-get update -q; apt-get install -y -q sudo; }
adduser --disabled-password --gecos "" "$user"
echo "$user:$password" | chpasswd
usermod -aG sudo "$user"
install -d -m 700 -o "$user" -g "$user" "/home/$user/.ssh"
install -m 600 -o "$user" -g "$user" /dev/null "/home/$user/.ssh/authorized_keys"
echo "$public_key" >"/home/$user/.ssh/authorized_keys"
echo "$user ALL=(ALL) NOPASSWD:ALL" >"/etc/sudoers.d/90-$user"
chmod 440 "/etc/sudoers.d/90-$user"
visudo -c -q

cat >"$config" <<CONF
Port 22
Port $port
PubkeyAuthentication yes
CONF
sshd -t
systemctl restart ssh

cat <<DONE

  User:     $user
  Port:     $port
  Password: $password   (sudo does not ask for it; keep it for the hoster's console)

Keep this session open and check the login from another terminal:
  ssh -p $port $user@<server ip>

When it works, close root, passwords and port 22:
  sudo $(readlink -f "$0") --lock $port
DONE

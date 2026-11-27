#!/usr/bin/env bash
# VPN servers on 3x-ui. Run as root from the clone in /opt/vpn:
#   install.sh node <domain> [ssh public key]               VPN node
#   install.sh exit <domain> <bridge ip> [ssh public key]   node abroad that serves only the bridge
#   install.sh bridge <domain> <exit link> [ssh public key] node in the users' country: its sites direct, the rest via the exit
#   install.sh head [ssh public key]                        head panel, one subscription for all nodes
#   install.sh share-address <old ip> <new ip> [panel url]  after the server's IP changes
#   install.sh update-geodata                               what the nightly timer runs
#   install.sh check-exit                                   what a bridge's exit check runs
set -euo pipefail

root="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
source "$root/lib/system.sh"
source "$root/lib/panel.sh"
source "$root/lib/decoy.sh"
source "$root/lib/monitor.sh"

xui_version=v3.11.0
xray_version="${XRAY_VERSION:-v26.11.9}"
# Brutal sends at exactly this rate (bytes per second): set the server's real bandwidth.
hysteria_bandwidth="${HYSTERIA_BANDWIDTH:-125000000}"
# The users' country: its geosite:category-<code> and geoip:<code> sites leave a bridge directly and a node
# through WARP.
country="${COUNTRY:-ru}"
# A domestic site that mobile whitelists keep reachable, borrowed by a bridge's second REALITY inbound.
whitelist_sni="${WHITELIST_SNI:-}"
whitelist_port=2053
reality_port=443
xhttp_port=11849
hysteria_port=11274
hysteria_hop_ports=20000-50000
decoy_port=8443
# Minimal Debian images ship without sudo, which the SSH user needs.
base_packages=(curl jq openssl nftables fail2ban sudo)
install_log=/root/vpn-install.log

# SSH and the firewall change under the session that runs an install, and that session may drop. The install
# runs as a transient systemd unit that outlives it; this terminal only follows the log.
if [[ -z "${INVOCATION_ID:-}" && "${1:-}" =~ ^(node|exit|bridge|head)$ ]]; then
  require_root
  unit="vpn-install-$(date +%s)"
  : >"$install_log"
  # --wait returns when the unit ends, with its result; a dropped session leaves the unit running. tail --pid
  # prints the log to its last line and stops once the waiting client is gone.
  systemd-run --quiet --wait --unit "$unit" \
    --setenv=XRAY_VERSION="$xray_version" --setenv=HYSTERIA_BANDWIDTH="$hysteria_bandwidth" \
    --setenv=XUI_ACME_EMAIL="${XUI_ACME_EMAIL:-}" --setenv=SSH_USER="${SSH_USER:-}" --setenv=SSH_PORT="${SSH_PORT:-}" \
    --setenv=HEAD_IP="${HEAD_IP:-}" --setenv=COUNTRY="$country" --setenv=WHITELIST_SNI="$whitelist_sni" \
    --setenv=TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}" --setenv=TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}" \
    --property=StandardOutput="append:$install_log" --property=StandardError="append:$install_log" \
    "$root/install.sh" "$@" &
  runner=$!
  tail -n +1 -f --pid="$runner" "$install_log"
  wait "$runner" || die "The install failed: see $install_log."
  exit 0
fi

# install_node <node | exit | bridge> <domain> <bridge ip | exit link | ""> [ssh public key]
# An exit takes VLESS REALITY only from its bridge; a bridge sends what is not the users' country's on to its
# exit. Both keep just TCP 443, which looks like any HTTPS site; HEAD_IP leaves the panel to the head alone.
install_node() {
  local mode="$1" domain="${2:?usage: install.sh $1 <domain> …}" peer="$3" public_key="${4:-}"
  local tcp_ports=80 udp_ports="" hop_ports="" rules=()
  require_root
  [[ "$country" =~ ^[a-z]{2}$ ]] || die "COUNTRY must be a two-letter code, such as ru."
  [[ "$mode" != exit ]] || require_ipv4 "$peer" "The bridge IP"
  [[ -z "${HEAD_IP:-}" ]] || require_ipv4 "$HEAD_IP" HEAD_IP
  [[ "$whitelist_sni" =~ ^([a-z0-9-]+\.)*[a-z0-9-]+\.[a-z]+$ || -z "$whitelist_sni" ]] ||
    die "WHITELIST_SNI must be a domain name, such as ya.ru."
  [[ -z "${TELEGRAM_BOT_TOKEN:-}" || -n "${TELEGRAM_CHAT_ID:-}" ]] || die "Set TELEGRAM_CHAT_ID with TELEGRAM_BOT_TOKEN."
  [[ -n "$(getent ahostsv4 "$domain")" ]] || die "$domain does not resolve: create its A record first."
  install_packages "${base_packages[@]}"
  tune_kernel
  fit_memory
  [[ -z "$public_key" ]] || harden_ssh "$public_key"
  install_panel "$domain"
  install_decoy "$domain"
  pin_xray
  if [[ "$mode" == bridge ]]; then configure_bridge "$peer"; else configure_xray; fi
  add_inbounds "$domain" "$mode"
  configure_subscription "$domain"
  schedule_geodata
  [[ "$mode" != bridge || -z "${TELEGRAM_BOT_TOKEN:-}" ]] || schedule_exit_check
  case "$mode" in
    node) tcp_ports+=", $reality_port, $xhttp_port" udp_ports="$hysteria_port, $hysteria_hop_ports" hop_ports="$hysteria_hop_ports" ;;
    exit) rules+=("ip saddr $peer tcp dport $reality_port accept") ;;
    bridge) tcp_ports+=", $reality_port${whitelist_sni:+, $whitelist_port}" ;;
  esac
  if [[ -n "${HEAD_IP:-}" ]]; then
    rules+=("ip saddr $HEAD_IP tcp dport $XUI_PANEL_PORT accept")
  else
    tcp_ports+=", $XUI_PANEL_PORT"
  fi
  # An exit's only client is the bridge, whose link is printed below: its subscription port stays closed.
  [[ -n "${HEAD_IP:-}" || "$mode" == exit ]] || tcp_ports+=", $subscription_port"
  protect "$tcp_ports" "$udp_ports" "$hop_ports" "${rules[@]}"
  systemctl restart x-ui
  wait_for_panel
  if [[ "$mode" == exit ]]; then
    local exit_link
    exit_link="$(curl -fsSk --resolve "$domain:$subscription_port:127.0.0.1" "$subscription_base$sub_id" |
      base64 -d | grep -m1 '^vless://')" || die "No exit link: copy the admin client's VLESS link from the panel."
    summary "Exit link for the bridge: $exit_link"
  else
    summary "Subscription: $subscription_base$sub_id"
  fi
}

install_head() {
  local public_key="${1:-}"
  require_root
  install_packages "${base_packages[@]}"
  tune_kernel
  fit_memory
  [[ -z "$public_key" ]] || harden_ssh "$public_key"
  install_panel
  local host="${panel#*://}"
  configure_subscription "${host%%[:/]*}"
  protect "80, $XUI_PANEL_PORT, $subscription_port" "" ""
  systemctl restart x-ui
  wait_for_panel
  summary "Subscriptions: $subscription_base<subscription ID>"
}

summary() {
  cat <<DONE

Done.
  Panel:  $XUI_ACCESS_URL
  Login:  $XUI_USERNAME / $XUI_PASSWORD
  Xray:   $(api GET server/status | jq -r .xray.version)
  $1
DONE
  [[ ! -s "$ssh_access_file" ]] || sed 's/^/  /' "$ssh_access_file"
  echo "The login, the password and the API token are kept in /etc/x-ui/install-result.env."
  # Container VPSes have no /boot kernels: find prints nothing there, and nothing is said.
  local latest_kernel
  latest_kernel="$(find /boot -maxdepth 1 -name 'vmlinuz-*' | sort -V | tail -1)"
  [[ -z "$latest_kernel" || "$latest_kernel" == "/boot/vmlinuz-$(uname -r)" ]] ||
    echo "A newer kernel is installed: reboot to load it (systemctl reboot)."
}

case "${1:-}" in
  node) install_node node "${2:-}" "" "${3:-}" ;;
  exit) install_node exit "${2:-}" "${3:?usage: install.sh exit <domain> <bridge ip> [ssh public key]}" "${4:-}" ;;
  bridge) install_node bridge "${2:-}" "${3:?usage: install.sh bridge <domain> <exit vless link> [ssh public key]}" "${4:-}" ;;
  head) install_head "${@:2}" ;;
  share-address)
    [[ $# -ge 3 ]] || die "usage: install.sh share-address <old ip> <new ip> [panel url]"
    if [[ -n "${4:-}" ]]; then
      panel="${4%/}"
      : "${XUI_API_TOKEN:?set XUI_API_TOKEN to the token of that panel}"
    else
      load_panel
    fi
    share_address "$2" "$3"
    ;;
  update-geodata)
    load_panel
    update_geodata
    ;;
  check-exit)
    load_panel
    check_exit
    ;;
  *) sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//' >&2 && exit 1 ;;
esac

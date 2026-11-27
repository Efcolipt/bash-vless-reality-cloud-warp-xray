#!/usr/bin/env bash
# VPN servers on 3x-ui. Run as root from the clone in /opt/vpn:
#   install.sh node <domain> [ssh public key]               VPN node
#   install.sh bridge <domain> <exit link> [ssh public key] node in Russia: Russian sites direct, the rest via the exit
#   install.sh head [ssh public key]                        head panel, one subscription for all nodes
#   install.sh share-address <old ip> <new ip> [panel url]  after the server's IP changes
#   install.sh update-geodata                               what the nightly timer runs
set -euo pipefail

root="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
source "$root/lib/system.sh"
source "$root/lib/panel.sh"
source "$root/lib/decoy.sh"

xui_version=v3.11.0
xray_version="${XRAY_VERSION:-v26.11.9}"
# Brutal sends at exactly this rate (bytes per second): set the server's real bandwidth.
hysteria_bandwidth="${HYSTERIA_BANDWIDTH:-125000000}"
reality_port=443
xhttp_port=11849
hysteria_port=11274
hysteria_hop_ports=20000-50000
decoy_port=8443
# Minimal Debian images ship without sudo, which the SSH user needs.
base_packages=(curl jq openssl nftables fail2ban sudo)

# install_node <domain> [ssh public key] [exit link]: with an exit link the node is a bridge.
install_node() {
  local domain="${1:?usage: install.sh node <domain> [ssh public key]}" public_key="${2:-}" exit_link="${3:-}"
  require_root
  [[ -n "$(getent ahostsv4 "$domain")" ]] || die "$domain does not resolve: create its A record first."
  install_packages "${base_packages[@]}"
  tune_kernel
  [[ -z "$public_key" ]] || harden_ssh "$public_key"
  install_panel "$domain"
  install_decoy "$domain"
  pin_xray
  if [[ -n "$exit_link" ]]; then configure_bridge "$exit_link"; else configure_xray; fi
  add_inbounds "$domain"
  configure_subscription "$domain"
  schedule_geodata
  protect "80, $reality_port, $xhttp_port, $XUI_PANEL_PORT, $subscription_port" \
    "$hysteria_port, $hysteria_hop_ports" "$hysteria_hop_ports"
  systemctl restart x-ui
  wait_for_panel
  summary "Subscription: $subscription_base$sub_id"
}

install_head() {
  local public_key="${1:-}"
  require_root
  install_packages "${base_packages[@]}"
  tune_kernel
  [[ -z "$public_key" ]] || harden_ssh "$public_key"
  install_panel
  local host="${panel#*://}"
  configure_subscription "${host%%[:/]*}"
  protect "80, $XUI_PANEL_PORT, $subscription_port"
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
}

case "${1:-}" in
  node) install_node "${2:-}" "${3:-}" ;;
  bridge) install_node "${2:-}" "${4:-}" "${3:?usage: install.sh bridge <domain> <exit vless link> [ssh public key]}" ;;
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
  *) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//' >&2 && exit 1 ;;
esac

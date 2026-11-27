#!/usr/bin/env bash
# Moves every inbound that hands out <old ip> in subscriptions to <new ip>, after the server's IP changes.
#   On a node:          sudo ./set-share-address.sh <old ip> <new ip>
#   On any other panel: XUI_API_TOKEN=<token> ./set-share-address.sh <old ip> <new ip> <panel url with base path>
# Run it against the panel that serves the subscription (the head, when nodes are attached) and on the node.
set -euo pipefail

old="${1:?usage: set-share-address.sh <old ip> <new ip> [panel url]}"
new="${2:?usage: set-share-address.sh <old ip> <new ip> [panel url]}"
if [[ -z "${XUI_API_TOKEN:-}" && -r /etc/x-ui/install-result.env ]]; then
  # shellcheck source=/dev/null
  source /etc/x-ui/install-result.env
fi
panel="${3:-${XUI_ACCESS_URL:?pass the panel url}}"
panel="${panel%/}"
: "${XUI_API_TOKEN:?set XUI_API_TOKEN}"
source "$(dirname "$0")/panel-api.sh"

api GET inbounds/list |
  jq -c --arg old "$old" --arg new "$new" '.[] | select(.shareAddr == $old) | .shareAddr = $new' |
  while read -r inbound; do
    id="$(jq -r .id <<<"$inbound")"
    api POST "inbounds/update/$id" -H 'Content-Type: application/json' --data "$inbound" >/dev/null
    echo "inbound $id ($(jq -r .remark <<<"$inbound")): $old -> $new"
  done

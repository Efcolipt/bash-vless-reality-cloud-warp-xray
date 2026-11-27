# 3x-ui: install, API, Xray core, WARP, routing, inbounds, subscription, geodata, share address.

# install_panel <domain | ip>: installs 3x-ui on PostgreSQL with a Let's Encrypt certificate for the
# domain, or for the server's IP when no domain is given; sets panel, certificate_dir and XUI_*.
install_panel() {
  local domain="${1:-}" ssl_mode=ip
  [[ -n "$domain" ]] && ssl_mode=domain
  log "3x-ui $xui_version on PostgreSQL"
  curl -fsSL -o /tmp/x-ui-install.sh "https://raw.githubusercontent.com/MHSanaei/3x-ui/$xui_version/install.sh"
  XUI_NONINTERACTIVE=1 XUI_SSL_MODE="$ssl_mode" XUI_DOMAIN="$domain" XUI_DB_TYPE=postgres \
    bash /tmp/x-ui-install.sh "$xui_version" </dev/null
  certificate_dir="/root/cert/${domain:-ip}"
  [[ -s "$certificate_dir/fullchain.pem" ]] ||
    die "No certificate in $certificate_dir: check the A record and that port 80 is reachable."
  load_panel
  mkdir -p /etc/systemd/system/x-ui.service.d
  printf '[Service]\nLimitNOFILE=1048576\nLimitNPROC=infinity\n' >/etc/systemd/system/x-ui.service.d/limits.conf
  systemctl daemon-reload
  wait_for_panel
}

load_panel() {
  # shellcheck source=/dev/null
  source /etc/x-ui/install-result.env
  panel="${XUI_ACCESS_URL%/}"
}

# api <method> <path> [curl args]: prints the answer's obj, fails when the panel answers success: false.
api() {
  local method="$1" path="$2"
  shift 2
  curl -fsS -X "$method" -H "Authorization: Bearer $XUI_API_TOKEN" "$panel/panel/api/$path" "$@" |
    jq -c 'if .success then .obj else error(.msg) end'
}

wait_for_panel() {
  for _ in {1..30}; do
    api GET server/status >/dev/null 2>&1 && return 0
    sleep 2
  done
  api GET server/status >/dev/null
}

pin_xray() {
  log "Xray $xray_version"
  api POST "server/installXray/$xray_version" >/dev/null
}

# Registers a WARP device through the panel and writes the routing, DNS and policy template with it.
configure_xray() {
  log "Cloudflare WARP, routing, DNS and policy"
  local xray_binary keys warp reserved warp_outbound
  xray_binary="$(ls /usr/local/x-ui/bin/xray-linux-*)"
  keys="$("$xray_binary" wg)"
  warp="$(api POST xray/warp/reg \
    --data-urlencode "privateKey=$(awk -F': ' '/^PrivateKey/ { print $2 }' <<<"$keys")" \
    --data-urlencode "publicKey=$(awk -F': ' '/PublicKey/ { print $2 }' <<<"$keys")" | jq -r .)"
  # reserved is the three raw bytes of client_id; jq's @base64d would mangle bytes above 127.
  # The endpoint is Cloudflare's IPv4: by name the core may dial the AAAA, which never answers (3x-ui #5205).
  reserved="$(jq -r '.config.config.client_id // .data.client_id' <<<"$warp" | base64 -d | od -An -tu1 | jq -sc .)"
  warp_outbound="$(jq -c --argjson reserved "$reserved" '.config.config as $device | {
    tag: "warp",
    protocol: "wireguard",
    streamSettings: { sockopt: { domainStrategy: "ForceIPv4v6" } },
    targetStrategy: "ForceIPv4v6",
    settings: {
      mtu: 1280,
      workers: 2,
      noKernelTun: true,
      secretKey: .data.private_key,
      address: [($device.interface.addresses.v4 + "/32"), ($device.interface.addresses.v6 + "/128")],
      reserved: $reserved,
      peers: [{
        publicKey: $device.peers[0].public_key,
        endpoint: (($device.peers[0].endpoint.v4 | sub(":[0-9]+$"; "")) + ":" + ($device.peers[0].endpoint.ports[0] | tostring))
      }]
    }
  }' <<<"$warp")"
  api POST xray/update --data-urlencode \
    "xraySetting=$(jq -c --argjson warp "$warp_outbound" '.outbounds += [$warp]' "$root/config/xray-template.json")" >/dev/null
}

# add_inbounds <domain>: three inbounds that share one client "admin"; sets sub_id, its subscription ID.
add_inbounds() {
  local domain="$1" name="${1%%.*}" server_ip uuid hysteria_auth
  log "Inbounds: VLESS REALITY $reality_port, XHTTP REALITY $xhttp_port, Hysteria2 $hysteria_port"
  server_ip="$(getent ahostsv4 "$domain" | awk 'NR == 1 { print $1 }')"
  uuid="$(api GET server/getNewUUID | jq -r .uuid)"
  sub_id="$(openssl rand -hex 8)"
  hysteria_auth="$(openssl rand -hex 16)"

  inbound_client() {
    jq -nc --arg flow "$1" --arg id "$uuid" --arg auth "$hysteria_auth" --arg sub_id "$sub_id" '{
      email: "admin", id: $id, auth: $auth, flow: $flow, subId: $sub_id,
      enable: true, limitIp: 0, totalGB: 0, expiryTime: 0, tgId: 0, comment: "", reset: 0
    }'
  }

  # Self-steal: the handshake comes from our own decoy site, so the SNI is our domain and resolves here.
  reality_settings() {
    api GET server/getNewX25519Cert | jq -c --arg domain "$domain" --arg target "127.0.0.1:$decoy_port" \
      --arg short_id "$(openssl rand -hex 8)" '{
      show: false,
      xver: 0,
      target: $target,
      serverNames: [$domain],
      privateKey: .privateKey,
      shortIds: [$short_id],
      settings: { publicKey: .publicKey, fingerprint: "chrome", serverName: "", spiderX: "/" }
    }'
  }

  add_inbound() {
    jq -c --arg name "$name" --arg server_ip "$server_ip" '. + {
      remark: ($name + " | " + .remark),
      enable: true,
      listen: "",
      expiryTime: 0,
      total: 0,
      shareAddrStrategy: "custom",
      shareAddr: $server_ip,
      sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], routeOnly: true }
    }' | api POST inbounds/add -H 'Content-Type: application/json' --data @- >/dev/null
  }

  jq -nc --argjson client "$(inbound_client xtls-rprx-vision)" --argjson reality "$(reality_settings)" --argjson port "$reality_port" '{
    remark: "VLESS Reality",
    port: $port,
    protocol: "vless",
    settings: { clients: [$client], decryption: "none", encryption: "none" },
    streamSettings: {
      network: "tcp",
      tcpSettings: { acceptProxyProtocol: false, header: { type: "none" } },
      security: "reality",
      realitySettings: $reality
    }
  }' | add_inbound

  jq -nc --argjson client "$(inbound_client '')" --argjson reality "$(reality_settings)" --argjson port "$xhttp_port" '{
    remark: "XHTTP Reality",
    port: $port,
    protocol: "vless",
    settings: { clients: [$client], decryption: "none", encryption: "none" },
    streamSettings: {
      network: "xhttp",
      xhttpSettings: {
        path: "/api/v1/updates",
        host: "",
        mode: "stream-one",
        xPaddingBytes: "100-1000",
        xmux: {
          maxConcurrency: "16-32",
          maxConnections: 0,
          cMaxReuseTimes: 0,
          hMaxRequestTimes: "600-900",
          hMaxReusableSecs: "1800-3000",
          hKeepAlivePeriod: 45
        }
      },
      security: "reality",
      realitySettings: $reality
    }
  }' | add_inbound

  # Brutal sends at exactly hysteria_bandwidth bytes per second; udpHop advertises the hop range in links.
  jq -nc --argjson client "$(inbound_client '')" --argjson port "$hysteria_port" --arg domain "$domain" \
    --arg certificate_dir "$certificate_dir" --arg bandwidth "$hysteria_bandwidth" --arg hop_ports "$hysteria_hop_ports" \
    --arg obfs "$(openssl rand -hex 16)" '{
    remark: "HY2",
    port: $port,
    protocol: "hysteria",
    settings: { clients: [$client], version: 2 },
    streamSettings: {
      network: "hysteria",
      hysteriaSettings: { version: 2, udpIdleTimeout: 60 },
      security: "tls",
      tlsSettings: {
        serverName: $domain,
        minVersion: "1.2",
        maxVersion: "1.3",
        alpn: ["h3"],
        certificates: [{
          certificateFile: ($certificate_dir + "/fullchain.pem"),
          keyFile: ($certificate_dir + "/privkey.pem"),
          ocspStapling: 3600,
          oneTimeLoading: false,
          usage: "encipherment",
          buildChain: false
        }],
        settings: { fingerprint: "chrome" }
      },
      finalmask: {
        udp: [{ type: "salamander", settings: { password: $obfs } }],
        quicParams: {
          congestion: "brutal",
          brutalUp: $bandwidth,
          brutalDown: $bandwidth,
          udpHop: { ports: $hop_ports, interval: "5-10" },
          initStreamReceiveWindow: 8388608,
          maxStreamReceiveWindow: 8388608,
          initConnectionReceiveWindow: 20971520,
          maxConnectionReceiveWindow: 20971520,
          maxIdleTimeout: 30,
          keepAlivePeriod: 10,
          disablePathMTUDiscovery: false,
          maxIncomingStreams: 1024
        }
      }
    }
  }' | add_inbound
}

# configure_subscription <host>: HTTPS (plain HTTP would leak every client key) and client auto-setup
# from the RoscomVPN routing profiles, which the panel refreshes in the background: Happ and JSON
# subscriptions, Incy and Clash/Mihomo get split routing (Russian sites direct, ads blocked).
# Sets subscription_port and subscription_base, the link without the ID.
configure_subscription() {
  local settings routing=https://raw.githubusercontent.com/hydraponique/roscomvpn-routing/refs/heads/main
  log "Subscription: HTTPS and client auto-setup"
  settings="$(api POST setting/all | jq -c --arg certificate_dir "$certificate_dir" --arg routing "$routing" '. + {
    subCertFile: ($certificate_dir + "/fullchain.pem"),
    subKeyFile: ($certificate_dir + "/privkey.pem"),
    subUpdates: 3,
    subEnableRouting: true,
    subRoutingRules: ($routing + "/HAPP/DEFAULT.JSON"),
    subJsonRoutingRules: ($routing + "/HAPP/DEFAULT.JSON"),
    subHappAutoDetect: true,
    subHappAutoConnect: true,
    subHappAutoConnectType: "lowestdelay",
    subHappSubExpire: true,
    subHappNotificationExpire: true,
    subHappExcludeRoutes: "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16",
    subHappExcludeApns: true,
    subIncyAppAutoDetect: true,
    subIncyEnableRouting: true,
    subIncyRoutingRules: ($routing + "/INCY/DEFAULT.JSON"),
    subClashEnable: true,
    subClashAutoDetect: true,
    subClashEnableRouting: true,
    subClashRules: ($routing + "/MIHOMO/default.yaml"),
    subClashRemoteDNS: true
  }')"
  api POST setting/update -H 'Content-Type: application/json' --data "$settings" >/dev/null
  subscription_port="$(jq -r .subPort <<<"$settings")"
  subscription_base="https://$1:$subscription_port$(jq -r .subPath <<<"$settings")"
}

# geodata changes restart the core and drop every connection, so the refresh runs once a night.
schedule_geodata() {
  log "Nightly geodata refresh"
  cat >/etc/systemd/system/vpn-geodata.service <<UNIT
[Unit]
Description=Refresh Xray geodata through the 3x-ui panel

[Service]
Type=oneshot
ExecStart=$root/install.sh update-geodata
UNIT
  cat >/etc/systemd/system/vpn-geodata.timer <<UNIT
[Unit]
Description=Refresh Xray geodata every night

[Timer]
OnCalendar=*-*-* 04:00 Europe/Moscow
Persistent=true

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now -q vpn-geodata.timer
  update_geodata
}

update_geodata() { api POST server/updateGeofile >/dev/null; }

# share_address <old ip> <new ip>: moves every inbound that hands out the old IP in subscriptions.
share_address() {
  local old="$1" new="$2" inbound id
  api GET inbounds/list |
    jq -c --arg old "$old" --arg new "$new" '.[] | select(.shareAddr == $old) | .shareAddr = $new' |
    while read -r inbound; do
      id="$(jq -r .id <<<"$inbound")"
      api POST "inbounds/update/$id" -H 'Content-Type: application/json' --data "$inbound" >/dev/null
      echo "inbound $id ($(jq -r .remark <<<"$inbound")): $old -> $new"
    done
}

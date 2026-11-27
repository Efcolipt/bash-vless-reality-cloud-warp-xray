# Self-steal decoy for REALITY: Caddy serves config/decoy on 127.0.0.1 with the domain's certificate.
# A prober that is not a client gets this site, and the SNI clients send is our own domain.

# install_decoy <domain>: run after install_panel. The caddy package starts on port 80 when installed,
# and the certificate request in install_panel needs that port.
install_decoy() {
  local domain="$1"
  log "Decoy site for REALITY on 127.0.0.1:$decoy_port"
  install_packages caddy
  install -d /var/www/decoy
  install -m 644 "$root/config/decoy/index.html" /var/www/decoy/index.html
  install -d -m 750 -g caddy /etc/caddy/certs
  sed -e "s/@DOMAIN@/$domain/g" -e "s/@PORT@/$decoy_port/g" "$root/config/caddy/Caddyfile" >/etc/caddy/Caddyfile

  # acme.sh renews into /root/cert, which the caddy user cannot read, so every renewal is copied over.
  cat >/etc/systemd/system/decoy-certificate.service <<UNIT
[Unit]
Description=Copy the $domain certificate to Caddy

[Service]
Type=oneshot
ExecStart=/usr/bin/install -m 640 -g caddy $certificate_dir/fullchain.pem $certificate_dir/privkey.pem /etc/caddy/certs/
ExecStart=/usr/bin/systemctl reload-or-restart caddy
UNIT
  cat >/etc/systemd/system/decoy-certificate.path <<UNIT
[Unit]
Description=Watch the $domain certificate

[Path]
PathChanged=$certificate_dir/fullchain.pem

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable -q caddy
  systemctl enable --now -q decoy-certificate.path
  systemctl start decoy-certificate.service
}

# Exit watch for a bridge. A head reports a node that stops answering, not a bridge whose path to the exit got
# blocked: every five minutes the bridge probes its exit through the panel and tells Telegram when that changes.

monitor_env=/etc/vpn-monitor.env
exit_state=/var/lib/vpn-monitor/exit

schedule_exit_check() {
  log "Exit check every 5 minutes, changes reported to Telegram"
  install -m 600 /dev/null "$monitor_env"
  printf 'TELEGRAM_BOT_TOKEN=%s\nTELEGRAM_CHAT_ID=%s\n' "$TELEGRAM_BOT_TOKEN" "$TELEGRAM_CHAT_ID" >"$monitor_env"
  cat >/etc/systemd/system/vpn-exit-check.service <<UNIT
[Unit]
Description=Probe the bridge's exit through the panel

[Service]
Type=oneshot
EnvironmentFile=$monitor_env
ExecStart=$root/install.sh check-exit
UNIT
  cat >/etc/systemd/system/vpn-exit-check.timer <<UNIT
[Unit]
Description=Probe the bridge's exit every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now -q vpn-exit-check.timer
}

# check_exit: probes the exit outbound for real and messages Telegram when the result differs from the last run.
check_exit() {
  local template result state previous=up text
  template="$(api POST xray/ | jq -r . | jq -c .xraySetting)"
  result="$(api POST xray/testOutbound --data-urlencode "outbound=$(jq -c '.outbounds[] | select(.tag == "exit")' <<<"$template")" \
    --data-urlencode "allOutbounds=$(jq -c .outbounds <<<"$template")" --data-urlencode mode=real)" ||
    result='{"success": false, "error": "the panel did not answer"}'
  state="$(jq -r 'if .success then "up" else "down" end' <<<"$result")"
  [[ ! -s "$exit_state" ]] || previous="$(<"$exit_state")"
  install -D -m 644 /dev/null "$exit_state"
  echo "$state" >"$exit_state"
  [[ "$state" != "$previous" ]] || return 0
  if [[ "$state" == up ]]; then
    text="🟢 $(hostname -s): the exit answers again ($(jq -r .delay <<<"$result") ms)"
  else
    text="🔴 $(hostname -s): the exit does not answer ($(jq -r '.error // .msg // "no answer"' <<<"$result"))"
  fi
  curl -fsS -o /dev/null "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
    --data-urlencode "chat_id=$TELEGRAM_CHAT_ID" --data-urlencode "text=$text"
}

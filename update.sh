#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run sudo wg-auto-update'; exit 1; }
[[ -e /etc/wireguard/.wg-auto-managed ]] || { echo 'Run install.sh first.'; exit 1; }
exec 8>/run/wg-auto-update.lock
flock -n 8 || { echo 'An update is already running.'; exit 1; }
if [[ ${1:-} == --install ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y python3 curl ca-certificates tar openssl
fi
if ! command -v openssl >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y openssl
fi
base=/opt/wg-auto
install -d -m 700 "$base/releases" /etc/wireguard/wg-auto-panel
stage=$(mktemp -d "$base/releases/stage.XXXXXXXX")
cleanup() { [[ -z ${stage:-} ]] || rm -rf -- "$stage"; }
trap cleanup EXIT
repo=https://api.github.com/repos/asalabanowwaw/wireguard-host-probe/commits/main
sha=$(curl -fsSL --retry 2 --connect-timeout 10 --max-time 30 "$repo" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')
[[ $sha =~ ^[a-f0-9]{40}$ ]] || { echo 'Invalid release commit.'; exit 1; }
old=$(readlink -f "$base/current" || true)
release="$base/releases/$sha"
# Reapply service/firewall setup even at the current release, so rerunning this
# command can repair a stopped service or an interrupted HTTP-to-HTTPS migration.
curl -fsSL --retry 2 --connect-timeout 10 --max-time 60 "https://codeload.github.com/asalabanowwaw/wireguard-host-probe/tar.gz/$sha" -o "$stage/source.tgz"
tar -xzf "$stage/source.tgz" -C "$stage" --strip-components=1 \
  "wireguard-host-probe-$sha/panel.py" \
  "wireguard-host-probe-$sha/panel.html" \
  "wireguard-host-probe-$sha/update.sh"
rm "$stage/source.tgz"
python3 -m py_compile "$stage/panel.py"
bash -n "$stage/update.sh"
printf '%s\n' "${sha:0:12}" > "$stage/VERSION"
chmod 700 "$stage/update.sh"
if [[ ! -d $release ]]; then mv "$stage" "$release"; stage=''; fi
cat > /etc/systemd/system/wg-auto-panel.service <<'EOF'
[Unit]
Description=WireGuard minimal administration panel
After=network.target wg-quick@wgauto0.service
Wants=wg-quick@wgauto0.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/wg-auto/current/panel.py
Restart=on-failure
RestartSec=3
UMask=0077
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStartPre=/bin/sh -c '/usr/sbin/iptables -C INPUT -p tcp --dport 8787 -m comment --comment wg-auto-panel -j ACCEPT 2>/dev/null || /usr/sbin/iptables -I INPUT 1 -p tcp --dport 8787 -m comment --comment wg-auto-panel -j ACCEPT'
ExecStopPost=/bin/sh -c '/usr/sbin/iptables -D INPUT -p tcp --dport 8787 -m comment --comment wg-auto-panel -j ACCEPT 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF
ln -sfn "$release" "$base/current.next"
mv -Tf "$base/current.next" "$base/current"
ln -sfn /opt/wg-auto/current/update.sh /usr/local/sbin/wg-auto-update
systemctl daemon-reload
systemctl enable wg-auto-panel
systemctl restart wg-auto-panel
healthy=0
for attempt in $(seq 1 15); do
  code=$(curl -s --cacert /etc/wireguard/wg-auto-panel/tls.crt -o /dev/null -w '%{http_code}' --max-time 2 https://127.0.0.1:8787/ || true)
  if [[ $code == 401 ]] && systemctl is-active --quiet wg-auto-panel; then healthy=1; break; fi
  sleep 1
done
if ((healthy == 0)); then
  if [[ -n $old && -d $old ]]; then
    ln -sfn "$old" "$base/current.rollback"
    mv -Tf "$base/current.rollback" "$base/current"
    systemctl restart wg-auto-panel
  fi
  echo 'Panel failed its startup check. Previous release restored when available.' >&2
  echo 'Inspect: journalctl -u wg-auto-panel -n 50' >&2
  exit 1
fi
echo "Panel installed/updated: $sha"
host=$(python3 -c 'import json; print(json.load(open("/etc/wireguard/wg-auto-panel/state.json"))["host"])')
echo "Open https://$host:8787 in your browser. Username: admin"
echo 'The automatically generated certificate is self-signed; your browser will show a certificate warning.'
echo 'If your provider has a cloud firewall, allow inbound TCP 8787.'
echo 'Read password: sudo cat /etc/wireguard/wg-auto-panel/password'
echo 'Future updates: sudo wg-auto-update (or use the panel update button).'

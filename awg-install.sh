#!/usr/bin/env bash
# Embedded into panel.py by build_panel.py. Official sources, isolated native interface.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Root is required.' >&2; exit 1; }
[[ -d /run/systemd/system && -c /dev/net/tun ]] || { echo 'A systemd VPS with /dev/net/tun is required.' >&2; exit 1; }
. /etc/os-release
[[ $ID == ubuntu || $ID == debian ]] || { echo 'Ubuntu or Debian is required.' >&2; exit 1; }
exec 9>/run/wg-auto-awg-install.lock
flock -n 9 || { echo 'An AmneziaWG install is running.' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
base=/opt/wg-auto/awg
config=/etc/amnezia/amneziawg/awgauto0.conf
data=/etc/wireguard/wg-auto-panel
service=wg-auto-awg
if [[ -f $config ]]; then
  [[ -f $data/awg-managed ]] || { echo 'Existing unmanaged AWG configuration found; refusing to overwrite it.' >&2; exit 1; }
  systemctl enable --now "$service"
  /usr/bin/python3 /opt/wg-auto/current/panel.py --initialize-awg
  exit 0
fi
ip link show awgauto0 >/dev/null 2>&1 && { echo 'Interface awgauto0 already exists and is not managed by this panel.' >&2; exit 1; }
case $(uname -m) in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo 'Supported CPU architectures: amd64 and arm64.' >&2; exit 1;; esac
apt-get update
apt-get install -y build-essential pkg-config libmnl-dev ca-certificates curl tar iproute2 iptables qrencode
stage=$(mktemp -d /opt/wg-auto/awg-build.XXXXXXXX)
created=0
success=0
cleanup() {
  if (( created && ! success )); then
    systemctl stop "$service" || true
    systemctl disable "$service" || true
    rm -f "$config" "$data/awg-managed"
  fi
  rm -rf -- "$stage"
}
trap cleanup EXIT
# Go's official download manifest includes a SHA256 for the platform archive.
curl -fsSL --retry 2 --connect-timeout 15 --max-time 60 'https://go.dev/dl/?mode=json' -o "$stage/go.json"
read -r gofile gosum < <(python3 - "$stage/go.json" "$arch" <<'PY'
import json,sys
versions=json.load(open(sys.argv[1]))
for version in versions:
    if not version['stable']: continue
    for f in version['files']:
        if f['os']=='linux' and f['arch']==sys.argv[2] and f['kind']=='archive':
            print(f['filename'], f['sha256']); sys.exit(0)
raise SystemExit('No matching Go toolchain')
PY
)
[[ $gofile =~ ^go[0-9.]+\.linux-(amd64|arm64)\.tar\.gz$ && $gosum =~ ^[a-f0-9]{64}$ ]] || exit 1
curl -fsSL --retry 2 --connect-timeout 15 --max-time 600 "https://go.dev/dl/$gofile" -o "$stage/go.tgz"
printf '%s  %s\n' "$gosum" "$stage/go.tgz" | sha256sum -c -
tar -xzf "$stage/go.tgz" -C "$stage"
# Reviewed upstream releases, pinned to immutable commits.
go_sha=b5928efb6ca19f0153958460c3d141f04abc5c2e
tools_sha=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
for spec in "amneziawg-go:$go_sha" "amneziawg-tools:$tools_sha"; do
  repo=${spec%:*}; sha=${spec#*:}
  curl -fsSL --retry 2 --connect-timeout 15 --max-time 120 "https://codeload.github.com/amnezia-vpn/$repo/tar.gz/$sha" -o "$stage/$repo.tgz"
  mkdir "$stage/$repo"
  tar -xzf "$stage/$repo.tgz" -C "$stage/$repo" --strip-components=1
done
export PATH="$stage/go/bin:$PATH"
export GOTOOLCHAIN=local
export GOCACHE="$stage/go-cache" GOPATH="$stage/go-path"
(cd "$stage/amneziawg-go" && GOMAXPROCS=2 go build -p 1 -trimpath -o "$stage/amneziawg-go.bin" .)
make -C "$stage/amneziawg-tools/src" -j2
install -d -m 700 "$base/bin" /etc/amnezia/amneziawg "$data"
install -m 755 "$stage/amneziawg-go.bin" "$base/bin/amneziawg-go"
install -m 755 "$stage/amneziawg-tools/src/wg" "$base/bin/awg"
# Force the pinned Go engine; an older installed kernel module must not silently
# consume a newer 3.1 configuration. Preserve upstream license/copyright headers.
python3 - "$stage/amneziawg-tools/src/wg-quick/linux.bash" <<'PY'
import sys
from pathlib import Path
p=Path(sys.argv[1]); source=p.read_text()
a=source.index('add_if() {'); b=source.index('\ndel_if() {',a)
source=source[:a]+'add_if() {\n    cmd "${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}" "$INTERFACE"\n}\n'+source[b:]
p.write_text(source)
PY
install -m 755 "$stage/amneziawg-tools/src/wg-quick/linux.bash" "$base/bin/awg-quick"
printf 'amneziawg-go %s\namneziawg-tools %s\n' "$go_sha" "$tools_sha" > "$base/SOURCES"
# Generate an unused /24 and UDP port without changing the original WireGuard.
export AWG_INSTALL_CONFIG="$config"
created=1
python3 - <<'PY'
import ipaddress,json,os,secrets,subprocess
from pathlib import Path
def run(*args, data=None):
    return subprocess.run(args,input=data,text=True,capture_output=True,check=True).stdout.strip()
routes=json.loads(run('ip','-j','-4','route','show','table','all'))
nets=[ipaddress.ip_network(r['dst'],strict=False) for r in routes if r.get('dst') not in (None,'default')]
net=next((ipaddress.ip_network(f'10.204.{i}.0/24') for i in range(240,255)
          if not any(ipaddress.ip_network(f'10.204.{i}.0/24').overlaps(n) for n in nets)),None)
if not net: raise SystemExit('No free AWG subnet found')
ports={int(line.split()[3].rsplit(':',1)[-1]) for line in run('ss','-H','-lun').splitlines() if line.split()[3].rsplit(':',1)[-1].isdigit()}
port=next((p for p in range(51821,51922) if p not in ports),None)
if not port: raise SystemExit('No free AWG UDP port found')
wan=json.loads(run('ip','-j','-4','route','get','1.1.1.1'))[0]['dev']
import re
if not re.fullmatch(r'[A-Za-z0-9_.:-]+',wan): raise SystemExit('Invalid WAN interface')
awg='/opt/wg-auto/awg/bin/awg'
lines=['[Interface]',f'Address = {net.network_address+1}/24',f'ListenPort = {port}',
       'PrivateKey = '+run(awg,'genkey'),'MTU = 1280', 'Jc = 4','Jmin = 40','Jmax = 700',
       f'S1 = {16+secrets.randbelow(16)}',f'S2 = {40+secrets.randbelow(16)}','S3 = 64','S4 = 16',
       'HeaderProtectionKey = '+run(awg,'genkey'),'ContentPaddingAddition = 0-16']
headers=secrets.SystemRandom().sample(range(100000,4294967295),4)
lines += [f'H{i} = {value}' for i,value in enumerate(headers,1)]
rules=[f'INPUT -p udp --dport {port} -j ACCEPT',
       f'FORWARD -i %i -o {wan} -s {net} -j ACCEPT',
       f'FORWARD -i {wan} -o %i -d {net} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT']
for rule in rules:
    lines += ['PostUp = iptables -I '+rule,'PostDown = iptables -D '+rule]
lines += [f'PostUp = iptables -t nat -A POSTROUTING -s {net} -o {wan} -j MASQUERADE',
          f'PostDown = iptables -t nat -D POSTROUTING -s {net} -o {wan} -j MASQUERADE']
path=Path(os.environ['AWG_INSTALL_CONFIG']);path.write_text('\n'.join(lines)+'\n');path.chmod(0o600)
PY
created=1
touch "$data/awg-managed"
cat > /etc/systemd/system/wg-auto-awg.service <<'EOF'
[Unit]
Description=Diana native AmneziaWG interface
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
Environment=PATH=/opt/wg-auto/awg/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/opt/wg-auto/awg/bin/awg-quick up /etc/amnezia/amneziawg/awgauto0.conf
ExecStop=/opt/wg-auto/awg/bin/awg-quick down /etc/amnezia/amneziawg/awgauto0.conf
TimeoutStartSec=45
UMask=0077
[Install]
WantedBy=multi-user.target
EOF
sysctl -w net.ipv4.ip_forward=1
systemctl daemon-reload
systemctl enable --now "$service"
"$base/bin/awg" show awgauto0 public-key >/dev/null
/usr/bin/python3 /opt/wg-auto/current/panel.py --initialize-awg
success=1
echo 'AmneziaWG is ready. Create an AmneziaWG device in Diana and import its config into an AmneziaWG 3.1 compatible app.'

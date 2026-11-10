#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'Run this installer with sudo bash.'
[[ -r /etc/os-release ]] || die 'Only Debian/Ubuntu with systemd are supported.'
. /etc/os-release
[[ ${ID:-} == ubuntu || ${ID:-} == debian ]] || die 'Only Debian and Ubuntu are supported.'
[[ -d /run/systemd/system ]] || die 'A systemd VPS is required, not a restricted application container.'
command -v flock >/dev/null || die 'Install util-linux first.'
exec 9>/run/wg-auto-install.lock
flock -n 9 || die 'Another installation is running.'

iface=wgauto0
config=/etc/wireguard/$iface.conf
client=/root/wireguard-client.conf
marker=/etc/wireguard/.wg-auto-managed
if [[ -e $config ]]; then
  [[ -e $marker && -s $client ]] || die "Existing $config found; refusing to overwrite it."
  systemctl enable --now "wg-quick@$iface"
  printf 'Already installed. Client configuration: %s\n' "$client"
  command -v qrencode >/dev/null && qrencode -t ansiutf8 < "$client"
  exit 0
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y wireguard-tools iproute2 iptables curl ca-certificates qrencode

endpoint=${WG_ENDPOINT:-}
if [[ -z $endpoint ]]; then
  endpoint=$(curl -4fsS --connect-timeout 5 --max-time 10 https://api.ipify.org || true)
  [[ -n $endpoint ]] || endpoint=$(curl -4fsS --connect-timeout 5 --max-time 10 https://ipv4.icanhazip.com || true)
fi
[[ $endpoint =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'Public IPv4 detection failed; rerun with WG_ENDPOINT set to your public IPv4.'
IFS=. read -r a b c d <<< "$endpoint"
for octet in "$a" "$b" "$c" "$d"; do
  [[ ${#octet} -le 3 ]] && ((10#$octet <= 255)) || die 'Invalid endpoint IPv4.'
done
wan=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1);exit}}')
[[ $wan =~ ^[a-zA-Z0-9_.:-]+$ ]] || die 'Could not detect outbound network interface.'
port=${WG_PORT:-51820}
[[ $port =~ ^[0-9]{1,5}$ ]] || die 'Invalid WG_PORT.'
port=$((10#$port))
((port >= 1024 && port <= 65535)) || die 'WG_PORT must be 1024..65535.'
ss -H -lun | awk '{print $4}' | grep -Eq ":${port}$" && die "UDP port $port is already occupied."

# Pick a private /24 that does not overlap an existing IPv4 route.
subnet=''
routes=$(ip -4 route show table all)
for n in $(seq 240 254); do
  candidate="10.203.$n"
  overlap=0
  while read -r route _; do
    [[ $route == */* && $route != default ]] || continue
    addr=${route%/*}; bits=${route#*/}
    [[ $addr =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && $bits =~ ^[0-9]+$ ]] || continue
    ((bits > 0 && bits <= 32)) || continue
    IFS=. read -r x y z w <<< "$addr"
    value=$(( (x<<24) | (y<<16) | (z<<8) | w ))
    mask=$(( (0xffffffff << (32-bits)) & 0xffffffff ))
    base=$(( (10<<24) | (203<<16) | (n<<8) ))
    # Compare with the shorter prefix to detect contained subnets too.
    ((bits > 24)) && mask=4294967040
    if (((value & mask) == (base & mask))); then overlap=1; break; fi
  done <<< "$routes"
  if ((overlap == 0)); then subnet=$candidate; break; fi
done
[[ -n $subnet ]] || die 'No unused VPN subnet was found.'
ip link add "$iface" type wireguard || die 'Kernel WireGuard support or NET_ADMIN is unavailable.'
ip link delete "$iface"
install -d -m 700 /etc/wireguard
server_key=$(wg genkey)
server_pub=$(printf '%s' "$server_key" | wg pubkey)
client_key=$(wg genkey)
client_pub=$(printf '%s' "$client_key" | wg pubkey)
psk=$(wg genpsk)
cat > "$config" <<EOF
[Interface]
Address = $subnet.1/24
ListenPort = $port
PrivateKey = $server_key
PostUp = iptables -I INPUT 1 -p udp --dport $port -j ACCEPT
PostUp = iptables -I FORWARD 1 -i %i -o $wan -s $subnet.0/24 -j ACCEPT
PostUp = iptables -I FORWARD 1 -i $wan -o %i -d $subnet.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -s $subnet.0/24 -o $wan -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport $port -j ACCEPT
PostDown = iptables -D FORWARD -i %i -o $wan -s $subnet.0/24 -j ACCEPT
PostDown = iptables -D FORWARD -i $wan -o %i -d $subnet.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s $subnet.0/24 -o $wan -j MASQUERADE

[Peer]
PublicKey = $client_pub
PresharedKey = $psk
AllowedIPs = $subnet.2/32
EOF
cat > "$client" <<EOF
[Interface]
PrivateKey = $client_key
Address = $subnet.2/32
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280

[Peer]
PublicKey = $server_pub
PresharedKey = $psk
Endpoint = $endpoint:$port
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-wg-auto.conf
sysctl -w net.ipv4.ip_forward=1
touch "$marker"
if ! systemctl enable --now "wg-quick@$iface"; then
  printf 'Startup failed. Files preserved for diagnosis; inspect: journalctl -u wg-quick@%s\n' "$iface" >&2
  exit 1
fi
wg show "$iface" >/dev/null
printf '\nWireGuard started. Client config: %s\n' "$client"
printf 'Public endpoint: %s:%s/UDP\n' "$endpoint" "$port"
printf 'Scan this QR code in the WireGuard app (it contains your private client key):\n'
qrencode -t ansiutf8 < "$client"
printf '\nImport /root/wireguard-client.conf, or display it using: sudo cat /root/wireguard-client.conf\n'
printf 'If your VPS provider has a cloud firewall, allow inbound UDP %s there.\n' "$port"
printf 'IPv4 internet is routed through the VPS; IPv6 is captured but not provided.\n'
printf 'Server startup verified; connect your client to verify handshake and internet access.\n'

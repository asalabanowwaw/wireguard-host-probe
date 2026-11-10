#!/usr/bin/env bash
# Real AWG 3.1 tunnel smoke test in disposable Linux network namespaces.
# Never uses existing VPN keys, configuration, interfaces or firewall rules.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run this test as root in a disposable Linux VM.' >&2; exit 1; }
bin=${1:?Pass a directory containing built awg and amneziawg-go binaries}
bin=$(realpath "$bin")
stage=$(mktemp -d)
suffix=$$
server="diana-s-$suffix"
client="diana-c-$suffix"
srv_if="awgs$suffix"
cli_if="awgc$suffix"
srv_pid=''; cli_pid=''; http_pid=''
cleanup() {
  [[ -z $http_pid ]] || kill "$http_pid" 2>/dev/null || true
  [[ -z $srv_pid ]] || kill "$srv_pid" 2>/dev/null || true
  [[ -z $cli_pid ]] || kill "$cli_pid" 2>/dev/null || true
  ip netns del "$server" 2>/dev/null || true
  ip netns del "$client" 2>/dev/null || true
  rm -rf -- "$stage"
}
trap cleanup EXIT
ip netns add "$server"
ip netns add "$client"
ip link add ds-veth type veth peer name dc-veth
ip link set ds-veth netns "$server"
ip link set dc-veth netns "$client"
ip -n "$server" addr add 192.0.2.1/30 dev ds-veth
ip -n "$client" addr add 192.0.2.2/30 dev dc-veth
for spec in "$server:ds-veth" "$client:dc-veth"; do
  ns=${spec%:*}; iface=${spec#*:}
  ip -n "$ns" link set lo up
  ip -n "$ns" link set "$iface" up
done
ip netns exec "$server" "$bin/amneziawg-go" -f "$srv_if" >"$stage/server.log" 2>&1 & srv_pid=$!
ip netns exec "$client" "$bin/amneziawg-go" -f "$cli_if" >"$stage/client.log" 2>&1 & cli_pid=$!
for attempt in $(seq 1 40); do
  if ip -n "$server" link show "$srv_if" >/dev/null 2>&1 && ip -n "$client" link show "$cli_if" >/dev/null 2>&1; then break; fi
  sleep .1
done
server_key=$("$bin/awg" genkey)
client_key=$("$bin/awg" genkey)
server_pub=$(printf '%s' "$server_key" | "$bin/awg" pubkey)
client_pub=$(printf '%s' "$client_key" | "$bin/awg" pubkey)
psk=$("$bin/awg" genpsk)
header_key=$("$bin/awg" genkey)
for role in server client; do
  if [[ $role == server ]]; then private=$server_key; peer=$client_pub; address=10.207.0.2; endpoint=192.0.2.2; else private=$client_key; peer=$server_pub; address=10.207.0.1; endpoint=192.0.2.1; fi
  cat > "$stage/$role.conf" <<EOF
[Interface]
PrivateKey = $private
ListenPort = 51999
Jc = 4
Jmin = 40
Jmax = 700
S1 = 20
S2 = 50
S3 = 64
S4 = 16
H1 = 100001
H2 = 200001
H3 = 300001
H4 = 400001
HeaderProtectionKey = $header_key
ContentPaddingAddition = 0-16
[Peer]
PublicKey = $peer
PresharedKey = $psk
AllowedIPs = $address/32
Endpoint = $endpoint:51999
PersistentKeepalive = 25
EOF
done
ip netns exec "$server" "$bin/awg" setconf "$srv_if" "$stage/server.conf"
ip netns exec "$client" "$bin/awg" setconf "$cli_if" "$stage/client.conf"
ip -n "$server" addr add 10.207.0.1/24 dev "$srv_if"
ip -n "$client" addr add 10.207.0.2/24 dev "$cli_if"
ip -n "$server" link set "$srv_if" mtu 1280 up
ip -n "$client" link set "$cli_if" mtu 1280 up
ip netns exec "$client" ping -c 3 -W 5 10.207.0.1
printf 'diana-awg-3.1-smoke\n' > "$stage/index.html"
chmod 755 "$stage"
ip netns exec "$server" python3 -m http.server 18080 --bind 10.207.0.1 --directory "$stage" >"$stage/http.log" 2>&1 & http_pid=$!
response=$(ip netns exec "$client" curl --noproxy '*' --retry 5 --retry-connrefused --retry-delay 1 --max-time 15 -fsS http://10.207.0.1:18080/)
[[ $response == diana-awg-3.1-smoke ]]
echo 'PASS: AWG 3.1 handshake, ICMP and HTTP over an isolated obfuscated tunnel.'

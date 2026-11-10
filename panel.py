#!/usr/bin/env python3
"""Password-protected WireGuard administration over public HTTPS."""
import base64
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import socket
import subprocess
import tempfile
import time
import traceback
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

ROOT = Path(os.environ.get('WG_AUTO_DATA', '/etc/wireguard/wg-auto-panel'))
CONFIG = Path(os.environ.get('WG_AUTO_CONFIG', '/etc/wireguard/wgauto0.conf'))
ORIGINAL_CLIENT = Path('/root/wireguard-client.conf')
IFACE = 'wgauto0'
MUTATION_LOCK = threading.Lock()
AUTH_LOCK = threading.Lock()
AUTH_FAILURES = {}
PROFILES = {
    'compatible': dict(label='Compatibility — smaller packets', mtu=1280, keepalive=25),
    'balanced': dict(label='Balanced — try on stable connections', mtu=1360, keepalive=25),
    'large': dict(label='Larger packets — test before using', mtu=1420, keepalive=25),
    'idle': dict(label='Less idle traffic — keepalive disabled', mtu=1280, keepalive=0),
}


def run(*args, data=None):
    return subprocess.run(args, input=data, text=True, capture_output=True, check=True, timeout=20).stdout.strip()


def atomic(path, text):
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def fields(text):
    return dict(re.findall(r'^\s*(\w+)\s*=\s*(.*?)\s*$', text, re.M))


def load():
    return json.loads((ROOT / 'state.json').read_text())


def initialize():
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not (ROOT / 'password').exists():
        atomic(ROOT / 'password', secrets.token_urlsafe(24) + '\n')
    if (ROOT / 'state.json').exists():
        return
    original = CONFIG.read_text()
    parts = original.split('[Peer]')
    server = fields(parts[0])
    client_path = ORIGINAL_CLIENT
    client = fields(client_path.read_text()) if client_path.exists() else {}
    endpoint = client.get('Endpoint', '')
    if not re.fullmatch(r'[A-Za-z0-9.-]+:\d+', endpoint):
        raise RuntimeError('Original client endpoint is missing or unsupported.')
    host, port = endpoint.rsplit(':', 1)
    state = dict(header=parts[0].rstrip(), unmanaged=[], clients=[], host=host, port=int(port),
                 dns=client.get('DNS', '1.1.1.1, 1.0.0.1'), mtu=int(client.get('MTU', '1280')),
                 serverPublic=run('wg', 'pubkey', data=server['PrivateKey'] + '\n'),
                 network=str(ipaddress.ip_interface(server['Address']).network))
    client_pub = run('wg', 'pubkey', data=client['PrivateKey'] + '\n') if client.get('PrivateKey') else None
    for block in parts[1:]:
        peer = fields(block)
        if peer.get('PublicKey') == client_pub:
            state['clients'].append(dict(id=secrets.token_hex(8), name='original-client',
                private=client['PrivateKey'], public=client_pub, psk=peer.get('PresharedKey', ''),
                address=client['Address'].split('/')[0]))
        else:
            state['unmanaged'].append(block.strip())
    atomic(ROOT / 'original-server.conf', original)
    atomic(ROOT / 'state.json', json.dumps(state))


def render_server(state):
    blocks = list(state['unmanaged'])
    for c in state['clients']:
        blocks.append(f"PublicKey = {c['public']}\nPresharedKey = {c['psk']}\nAllowedIPs = {c['address']}/32")
    return state['header'] + '\n\n' + ''.join('[Peer]\n' + b + '\n\n' for b in blocks)


def sync(text):
    # wg strips Address and hook settings before sending the kernel configuration.
    fd, name = tempfile.mkstemp(dir=ROOT, suffix='.conf')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text)
        stripped = run('wg-quick', 'strip', name)
        Path(name).write_text(stripped)
        run('wg', 'syncconf', IFACE, name)
    finally:
        os.unlink(name)


def save(state):
    old = CONFIG.read_text()
    old_state = (ROOT / 'state.json').read_text()
    text = render_server(state)
    # Preserve the last working state for recovery as well as rolling back errors.
    atomic(ROOT / 'previous-server.conf', old)
    atomic(ROOT / 'previous-state.json', old_state)
    try:
        sync(text)
        atomic(CONFIG, text)
        atomic(ROOT / 'state.json', json.dumps(state))
    except Exception:
        atomic(CONFIG, old)
        atomic(ROOT / 'state.json', old_state)
        sync(old)
        raise


def client_config(state, c):
    tuning = effective_tuning(state, c)
    mtu_line = f"MTU = {tuning['mtu']}"
    return f"""[Interface]
PrivateKey = {c['private']}
Address = {c['address']}/32
DNS = {tuning['dns']}
{mtu_line}

[Peer]
PublicKey = {state['serverPublic']}
PresharedKey = {c['psk']}
Endpoint = {state['host']}:{state['port']}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = {tuning['keepalive']}
"""


def effective_tuning(state, c):
    tuning = c.get('tuning', {})
    return dict(profile=tuning.get('profile', 'default'), mtu=tuning.get('mtu', state['mtu']),
                keepalive=tuning.get('keepalive', 25), dns=tuning.get('dns') or state['dns'])


def set_tuning(client, body):
    profile = body.get('profile', 'default')
    if profile == 'default':
        client.pop('tuning', None)
        return
    if profile == 'custom':
        mtu, keepalive = int(body['mtu']), int(body['keepalive'])
    elif profile in PROFILES:
        mtu, keepalive = PROFILES[profile]['mtu'], PROFILES[profile]['keepalive']
    else:
        raise ValueError('Unknown network profile.')
    if not 1280 <= mtu <= 1420 or not 0 <= keepalive <= 120:
        raise ValueError('MTU must be 1280–1420; keepalive must be 0–120 seconds.')
    raw_dns = str(body.get('dns', '')).strip()
    dns = ', '.join(str(ipaddress.ip_address(x.strip())) for x in raw_dns.split(',')) if raw_dns else ''
    if dns and len(dns.split(',')) > 3:
        raise ValueError('Provide at most three DNS addresses.')
    client['tuning'] = dict(profile=profile, mtu=mtu, keepalive=keepalive, dns=dns)


def make_server(host='0.0.0.0', port=8787):
    cert, key = ROOT / 'tls.crt', ROOT / 'tls.key'
    if not cert.exists() or not key.exists():
        name = load()['host']
        try:
            ipaddress.ip_address(name)
            san = 'IP:' + name
        except ValueError:
            san = 'DNS:' + name
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
            '-days', '3650', '-keyout', str(key), '-out', str(cert),
            '-subj', '/CN=WireGuard Panel', '-addext', 'subjectAltName=' + san + ',IP:127.0.0.1')
        key.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    server = PanelServer((host, port), Handler)
    server.tls_context = context
    return server


class PanelServer(ThreadingHTTPServer):
    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(10)
        return sock, address

    def finish_request(self, sock, address):
        try:
            first = sock.recv(1, socket.MSG_PEEK)
            if not first:
                return
            if first != b'\x16':
                # Never authenticate or serve private data over plaintext HTTP.
                host = load()['host']
                location = f'https://{host}:{self.server_port}/'
                sock.sendall(('HTTP/1.1 308 Permanent Redirect\r\nLocation: ' + location +
                              '\r\nContent-Length: 0\r\nConnection: close\r\n\r\n').encode('ascii'))
                return
            with self.tls_context.wrap_socket(sock, server_side=True) as secured:
                super().finish_request(secured, address)
        except (ssl.SSLError, TimeoutError, ConnectionError):
            # Browser certificate rejection, scanners and interrupted handshakes
            # are connection failures, not application failures.
            return


def settings(state, body):
    host = str(body.get('host', '')).strip()
    if len(host) > 253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host):
        raise ValueError('Enter a public IPv4 address or DNS hostname without a protocol or port.')
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        if re.fullmatch(r'[0-9.]+', host) or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in host.split('.')):
            raise ValueError('Invalid hostname or IPv4 address.')
    port, mtu = int(body['port']), int(body['mtu'])
    if not 1 <= port <= 65535 or not 1280 <= mtu <= 1420:
        raise ValueError('Port must be 1–65535; MTU must be 1280–1420.')
    dns = [str(ipaddress.ip_address(x.strip())) for x in str(body['dns']).split(',')]
    if not 1 <= len(dns) <= 3:
        raise ValueError('Provide one to three DNS IP addresses.')
    state.update(host=host, port=port, mtu=mtu, dns=', '.join(dns))


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *args):
        pass  # Do not log download URLs or credentials.

    def send(self, code, body, kind='application/json', filename=None):
        if not isinstance(body, (str, bytes)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', kind)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'")
        if code == 401:
            self.send_header('WWW-Authenticate', 'Basic realm="WireGuard panel"')
        if filename:
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        address, now = self.client_address[0], time.monotonic()
        with AUTH_LOCK:
            failures, start = AUTH_FAILURES.get(address, (0, now))
            if now - start > 60:
                failures, start = 0, now
            limited = failures >= 10
        if limited:
            self.send(429, {'error': 'Too many failed logins. Try again in one minute.'})
            return False
        expected = 'Basic ' + base64.b64encode(('admin:' + (ROOT / 'password').read_text().strip()).encode()).decode()
        if not hmac.compare_digest(self.headers.get('Authorization', ''), expected):
            # Visiting the login prompt without credentials is not a failed password.
            if self.headers.get('Authorization'):
                with AUTH_LOCK:
                    if len(AUTH_FAILURES) > 10000:
                        AUTH_FAILURES.clear()
                    AUTH_FAILURES[address] = (failures + 1, start)
            self.send(401, {'error': 'Authentication required'})
            return False
        with AUTH_LOCK:
            AUTH_FAILURES.pop(address, None)
        return True

    def do_GET(self):
        if not self.authorized():
            return
        try:
            if self.path == '/':
                return self.send(200, Path(__file__).with_name('panel.html').read_bytes(), 'text/html; charset=utf-8')
            state = load()
            if self.path == '/api/status':
                peers, error = {}, None
                try:
                    dump = run('wg', 'show', IFACE, 'dump').splitlines()
                    for line in dump[1:]:
                        p = line.split('\t')
                        peers[p[0]] = dict(handshake=int(p[4]), received=int(p[5]), sent=int(p[6]))
                except Exception:
                    error = 'WireGuard is unavailable. Check sudo systemctl status wg-quick@wgauto0.'
                return self.send(200, dict(host=state['host'], port=state['port'], dns=state['dns'], mtu=state['mtu'],
                    profiles=PROFILES,
                    listenPort=fields(state['header'])['ListenPort'], error=error,
                    version=Path(__file__).with_name('VERSION').read_text().strip(),
                    unmanaged=len(state['unmanaged']), clients=[dict(id=c['id'], name=c['name'], address=c['address'], tuning=effective_tuning(state, c), dnsOverride=c.get('tuning', {}).get('dns', ''), **peers.get(c['public'], {})) for c in state['clients']]))
            match = re.fullmatch(r'/api/clients/([a-f0-9]{16})/config', self.path)
            if match:
                c = next((c for c in state['clients'] if c['id'] == match[1]), None)
                if c:
                    return self.send(200, client_config(state, c), 'text/plain', c['name'] + '.conf')
            self.send(404, {'error': 'Not found'})
        except Exception:
            traceback.print_exc()
            self.send(500, {'error': 'Unable to read panel state. Check the service journal.'})

    def do_POST(self):
        if not MUTATION_LOCK.acquire(blocking=False):
            return self.send(409, {'error': 'Another operation is running. Try again shortly.'})
        try:
            self.post_locked()
        finally:
            MUTATION_LOCK.release()

    def post_locked(self):
        if not self.authorized():
            return
        # Custom header prevents browser form/CSRF requests; no cross-origin CORS access.
        if self.headers.get('X-WG-Panel') != '1' or self.headers.get('Content-Type') != 'application/json':
            return self.send(403, {'error': 'Invalid panel request'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 4096:
                raise ValueError('Invalid request length')
            body = json.loads(self.rfile.read(length))
            state = load()
            tuning_match = re.fullmatch(r'/api/clients/([a-f0-9]{16})/tuning', self.path)
            if tuning_match:
                client = next((c for c in state['clients'] if c['id'] == tuning_match[1]), None)
                if not client:
                    raise ValueError('Client not found.')
                set_tuning(client, body)
                atomic(ROOT / 'state.json', json.dumps(state))
            elif self.path == '/api/settings':
                settings(state, body)
                # Endpoint/DNS/MTU changes affect exported configs, not the server listener.
                atomic(ROOT / 'state.json', json.dumps(state))
            elif self.path == '/api/clients':
                name = str(body.get('name', '')).strip()
                if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}', name):
                    raise ValueError('Use 1–40 letters, numbers, underscores or hyphens.')
                if any(c['name'] == name for c in state['clients']):
                    raise ValueError('Client name already exists.')
                used = {c['address'] for c in state['clients']}
                for block in state['unmanaged']:
                    for addr in fields(block).get('AllowedIPs', '').split(','):
                        if addr.strip():
                            for host in ipaddress.ip_network(state['network']).hosts():
                                if host in ipaddress.ip_network(addr.strip(), strict=False):
                                    used.add(str(host))
                address = next((str(a) for a in list(ipaddress.ip_network(state['network']).hosts())[1:] if str(a) not in used), None)
                if not address:
                    raise ValueError('No client addresses remain.')
                private = run('wg', 'genkey')
                state['clients'].append(dict(id=secrets.token_hex(8), name=name, private=private,
                    public=run('wg', 'pubkey', data=private + '\n'), psk=run('wg', 'genpsk'), address=address))
                save(state)
            elif self.path == '/api/revoke':
                target = body.get('id')
                if not any(c['id'] == target for c in state['clients']):
                    raise ValueError('Client not found.')
                state['clients'] = [c for c in state['clients'] if c['id'] != target]
                save(state)
            elif self.path == '/api/update':
                run('systemd-run', '--unit=wg-auto-update-' + str(int(time.time())), '/usr/local/sbin/wg-auto-update')
            else:
                return self.send(404, {'error': 'Not found'})
            self.send(200, {'ok': True})
        except (ValueError, KeyError, TypeError) as e:
            self.send(400, {'error': str(e)})
        except Exception:
            traceback.print_exc()
            self.send(500, {'error': 'Operation failed. Previous VPN state was preserved where possible; check journalctl -u wg-auto-panel.'})


if __name__ == '__main__':
    os.umask(0o077)
    initialize()
    server = make_server()
    server.timeout = 15
    server.socket.settimeout(15)
    server.serve_forever()

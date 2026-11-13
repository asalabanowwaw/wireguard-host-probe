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
import sys
import io
import zipfile
import subprocess
import tempfile
import time
import traceback
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from urllib.parse import quote, urlencode

ROOT = Path(os.environ.get('WG_AUTO_DATA', '/etc/wireguard/wg-auto-panel'))
CONFIG = Path(os.environ.get('WG_AUTO_CONFIG', '/etc/wireguard/wgauto0.conf'))
ORIGINAL_CLIENT = Path('/root/wireguard-client.conf')
IFACE = 'wgauto0'
AWG_CONFIG = Path('/etc/amnezia/amneziawg/awgauto0.conf')
AWG_BIN = '/opt/wg-auto/awg/bin/'
AWG_HISTORY = []
AWG_SAMPLES = {}
AWG_KEYS = ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'HeaderProtectionKey', 'ContentPaddingAddition')
MUTATION_LOCK = threading.Lock()
AUTH_LOCK = threading.Lock()
AUTH_FAILURES = {}
METRICS_LOCK = threading.Lock()
PEER_SAMPLES = {}
TRAFFIC_HISTORY = []
PROFILES = {
    'small': dict(label='Small packets — IPv4 only', mtu=1200, keepalive=25),
    'compatible': dict(label='Compatibility — smaller packets', mtu=1280, keepalive=25),
    'balanced': dict(label='Balanced — try on stable connections', mtu=1360, keepalive=25),
    'large': dict(label='Larger packets — test before using', mtu=1420, keepalive=25),
    'idle': dict(label='Less idle traffic — keepalive disabled', mtu=1280, keepalive=0),
}
# Curated IPv4 catalog; documentation is not a live reachability guarantee.
DNS_PRESETS = {'shecan': {'label': 'Shecan / شکن',
            'dns': '178.22.122.100, 185.51.200.2',
            'region': 'Iran',
            'category': 'Anti-sanction',
            'source': 'https://t.me/s/shecan_ir',
            'note': 'Access can depend on source IP; test through your VPN.',
            'verification': 'Provider documented'},
 'begzar': {'label': 'Begzar / بگذر',
            'dns': '185.55.226.26, 185.55.225.25, 185.55.224.24',
            'region': 'Iran',
            'category': 'Anti-sanction',
            'source': 'https://begzar.ir/',
            'note': 'For supported services; availability from a foreign VPS may differ.',
            'verification': 'Provider documented'},
 'electro': {'label': 'Electro / الکترو',
             'dns': '78.157.42.100, 78.157.42.101',
             'region': 'Iran',
             'category': 'Anti-sanction',
             'source': 'https://github.com/roozysoft/DNSs',
             'note': 'Legacy DNS addresses. Current service availability is unconfirmed.',
             'verification': 'Community listed / unverified'},
 '403': {'label': '403 / ۴۰۳',
         'dns': '10.202.10.202, 10.202.10.102',
         'region': 'Iran',
         'category': 'Network-only',
         'source': 'https://github.com/roozysoft/DNSs',
         'note': 'Private addresses: normally unreachable from a foreign VPS; requires a compatible Iranian '
                 'network route.',
         'verification': 'Community listed / unverified'},
 'radar': {'label': 'Radar / رادار',
           'dns': '10.202.10.10, 10.202.10.11',
           'region': 'Iran',
           'category': 'Network-only',
           'source': 'https://github.com/roozysoft/DNSs',
           'note': 'Private addresses: normally unreachable from a foreign VPS; requires a compatible '
                   'Iranian network route.',
           'verification': 'Community listed / unverified'},
 'shelter': {'label': 'Shelter / شلتر',
             'dns': '94.103.125.157, 94.103.125.158',
             'region': 'Iran',
             'category': 'Anti-sanction',
             'source': 'https://github.com/roozysoft/DNSs',
             'note': 'Provider documentation and current availability not confirmed.',
             'verification': 'Community listed / unverified'},
 'beshkan': {'label': 'Beshkan / بشکن',
             'dns': '181.41.194.177, 181.41.194.186',
             'region': 'Iran',
             'category': 'Anti-sanction',
             'source': 'https://github.com/roozysoft/DNSs',
             'note': 'Provider documentation and current availability not confirmed.',
             'verification': 'Community listed / unverified'},
 'pishgaman': {'label': 'Pishgaman / پیشگامان',
               'dns': '5.202.100.100, 5.202.100.101',
               'region': 'Iran',
               'category': 'ISP',
               'source': 'https://github.com/roozysoft/DNSs',
               'note': 'May restrict clients by network. Public access is not confirmed.',
               'verification': 'Community listed / unverified'},
 'shatel': {'label': 'Shatel / شاتل',
            'dns': '85.15.1.14, 85.15.1.15',
            'region': 'Iran',
            'category': 'ISP',
            'source': 'https://github.com/roozysoft/DNSs',
            'note': 'May restrict clients by network. Public access is not confirmed.',
            'verification': 'Community listed / unverified'},
 'cloudflare': {'label': 'Cloudflare',
                'dns': '1.1.1.1, 1.0.0.1',
                'region': 'Global',
                'category': 'Unfiltered',
                'source': 'https://developers.cloudflare.com/1.1.1.1/ip-addresses/',
                'note': '',
                'verification': 'Provider documented'},
 'cloudflare-security': {'label': 'Cloudflare Malware',
                         'dns': '1.1.1.2, 1.0.0.2',
                         'region': 'Global',
                         'category': 'Security',
                         'source': 'https://developers.cloudflare.com/1.1.1.1/ip-addresses/',
                         'note': '',
                         'verification': 'Provider documented'},
 'cloudflare-family': {'label': 'Cloudflare Family',
                       'dns': '1.1.1.3, 1.0.0.3',
                       'region': 'Global',
                       'category': 'Family',
                       'source': 'https://developers.cloudflare.com/1.1.1.1/ip-addresses/',
                       'note': '',
                       'verification': 'Provider documented'},
 'google': {'label': 'Google',
            'dns': '8.8.8.8, 8.8.4.4',
            'region': 'Global',
            'category': 'Unfiltered',
            'source': 'https://developers.google.com/speed/public-dns/docs/using',
            'note': '',
            'verification': 'Provider documented'},
 'quad9': {'label': 'Quad9 Security',
           'dns': '9.9.9.9, 149.112.112.112',
           'region': 'Global',
           'category': 'Security',
           'source': 'https://quad9.net/service/service-addresses-and-features/',
           'note': '',
           'verification': 'Provider documented'},
 'quad9-ecs': {'label': 'Quad9 Security ECS',
               'dns': '9.9.9.11, 149.112.112.11',
               'region': 'Global',
               'category': 'Security',
               'source': 'https://quad9.net/service/service-addresses-and-features/',
               'note': 'ECS shares a client subnet hint with upstream servers.',
               'verification': 'Provider documented'},
 'quad9-unfiltered': {'label': 'Quad9 Unfiltered',
                      'dns': '9.9.9.10, 149.112.112.10',
                      'region': 'Global',
                      'category': 'Unfiltered',
                      'source': 'https://quad9.net/service/service-addresses-and-features/',
                      'note': '',
                      'verification': 'Provider documented'},
 'adguard': {'label': 'AdGuard',
             'dns': '94.140.14.14, 94.140.15.15',
             'region': 'Global',
             'category': 'Ad blocking',
             'source': 'https://adguard-dns.io/en/public-dns.html',
             'note': '',
             'verification': 'Provider documented'},
 'adguard-unfiltered': {'label': 'AdGuard Unfiltered',
                        'dns': '94.140.14.140, 94.140.14.141',
                        'region': 'Global',
                        'category': 'Unfiltered',
                        'source': 'https://adguard-dns.io/en/public-dns.html',
                        'note': '',
                        'verification': 'Provider documented'},
 'adguard-family': {'label': 'AdGuard Family',
                    'dns': '94.140.14.15, 94.140.15.16',
                    'region': 'Global',
                    'category': 'Family',
                    'source': 'https://adguard-dns.io/en/public-dns.html',
                    'note': '',
                    'verification': 'Provider documented'},
 'cleanbrowsing-security': {'label': 'CleanBrowsing Security',
                            'dns': '185.228.168.9, 185.228.169.9',
                            'region': 'Global',
                            'category': 'Security',
                            'source': 'https://cleanbrowsing.org/filters',
                            'note': '',
                            'verification': 'Provider documented'},
 'cleanbrowsing-adult': {'label': 'CleanBrowsing Adult',
                         'dns': '185.228.168.10, 185.228.169.11',
                         'region': 'Global',
                         'category': 'Family',
                         'source': 'https://cleanbrowsing.org/filters',
                         'note': '',
                         'verification': 'Provider documented'},
 'cleanbrowsing-family': {'label': 'CleanBrowsing Family',
                          'dns': '185.228.168.168, 185.228.169.168',
                          'region': 'Global',
                          'category': 'Family',
                          'source': 'https://cleanbrowsing.org/filters',
                          'note': 'Family filter also blocks proxy/VPN domains and some mixed-content sites.',
                          'verification': 'Provider documented'},
 'controld-0': {'label': 'Control D Unfiltered',
                'dns': '76.76.2.0, 76.76.10.0',
                'region': 'Global',
                'category': 'Unfiltered',
                'source': 'https://docs.controld.com/docs/free-dns',
                'note': '',
                'verification': 'Provider documented'},
 'controld-1': {'label': 'Control D Malware',
                'dns': '76.76.2.1, 76.76.10.1',
                'region': 'Global',
                'category': 'Security',
                'source': 'https://docs.controld.com/docs/free-dns',
                'note': '',
                'verification': 'Provider documented'},
 'controld-2': {'label': 'Control D Ads and Tracking',
                'dns': '76.76.2.2, 76.76.10.2',
                'region': 'Global',
                'category': 'Ad blocking',
                'source': 'https://docs.controld.com/docs/free-dns',
                'note': '',
                'verification': 'Provider documented'},
 'controld-3': {'label': 'Control D Social',
                'dns': '76.76.2.3, 76.76.10.3',
                'region': 'Global',
                'category': 'Social blocking',
                'source': 'https://docs.controld.com/docs/free-dns',
                'note': '',
                'verification': 'Provider documented'},
 'controld-4': {'label': 'Control D Family',
                'dns': '76.76.2.4, 76.76.10.4',
                'region': 'Global',
                'category': 'Family',
                'source': 'https://docs.controld.com/docs/free-dns',
                'note': '',
                'verification': 'Provider documented'},
 'controld-5': {'label': 'Control D Uncensored',
                'dns': '76.76.2.5, 76.76.10.5',
                'region': 'Global',
                'category': 'Uncensored',
                'source': 'https://docs.controld.com/docs/free-dns',
                'note': '',
                'verification': 'Provider documented'},
 'opendns': {'label': 'OpenDNS',
             'dns': '208.67.222.222, 208.67.220.220',
             'region': 'Global',
             'category': 'Security',
             'source': 'https://www.opendns.com/setupguide/',
             'note': '',
             'verification': 'Provider documented'},
 'opendns-family': {'label': 'OpenDNS FamilyShield',
                    'dns': '208.67.222.123, 208.67.220.123',
                    'region': 'Global',
                    'category': 'Family',
                    'source': 'https://www.opendns.com/setupguide/',
                    'note': '',
                    'verification': 'Provider documented'},
 'yandex': {'label': 'Yandex Basic',
            'dns': '77.88.8.8, 77.88.8.1',
            'region': 'Global',
            'category': 'Unfiltered',
            'source': 'https://dns.yandex.com/',
            'note': '',
            'verification': 'Provider documented'},
 'yandex-safe': {'label': 'Yandex Safe',
                 'dns': '77.88.8.88, 77.88.8.2',
                 'region': 'Global',
                 'category': 'Security',
                 'source': 'https://dns.yandex.com/',
                 'note': '',
                 'verification': 'Provider documented'},
 'yandex-family': {'label': 'Yandex Family',
                   'dns': '77.88.8.7, 77.88.8.3',
                   'region': 'Global',
                   'category': 'Family',
                   'source': 'https://dns.yandex.com/',
                   'note': '',
                   'verification': 'Provider documented'},
 'dnssb': {'label': 'DNS.SB',
           'dns': '185.222.222.222, 45.11.45.11',
           'region': 'Global',
           'category': 'Unfiltered',
           'source': 'https://dns.sb/guide/',
           'note': '',
           'verification': 'Provider documented'}}


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


def state_path(state=None):
    return ROOT / ('awg-state.json' if (state or {}).get('protocol') == 'amneziawg' else 'state.json')


def engine(state):
    if state.get('protocol') == 'amneziawg':
        return AWG_BIN + 'awg', AWG_BIN + 'awg-quick', 'awgauto0', AWG_CONFIG, 'wg-auto-awg'
    return 'wg', 'wg-quick', IFACE, CONFIG, 'wg-quick@' + IFACE


def load(protocol='wireguard'):
    return json.loads(state_path({'protocol': protocol}).read_text())


def initialize_awg():
    if state_path({'protocol': 'amneziawg'}).exists():
        return
    if not AWG_CONFIG.exists() or not (ROOT / 'awg-managed').exists():
        raise ValueError('Install AmneziaWG from the protocol card first.')
    base = load()
    parts = AWG_CONFIG.read_text().split('[Peer]')
    header = parts[0].rstrip()
    server = fields(header)
    state = dict(protocol='amneziawg', header=header, unmanaged=[block.strip() for block in parts[1:]], clients=[],
                 host=base['host'], port=int(server['ListenPort']), dns=base['dns'], mtu=1280,
                 network=str(ipaddress.ip_interface(server['Address']).network),
                 serverPublic=run(AWG_BIN + 'awg', 'pubkey', data=server['PrivateKey'] + '\n'))
    atomic(state_path(state), json.dumps(state))


def awg_install_status():
    path = ROOT / 'awg-install.json'
    result = json.loads(path.read_text()) if path.exists() else {'status': 'not-installed'}
    result['installed'] = state_path({'protocol': 'amneziawg'}).exists()
    if result.get('status') == 'installing' and time.time() - result.get('time', 0) > 1800:
        result.update(status='failed', message='Installation exceeded 30 minutes. Check the install journal before retrying.')
    return result



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
        if not c.get('enabled', True):
            continue
        blocks.append(f"PublicKey = {c['public']}\nPresharedKey = {c['psk']}\nAllowedIPs = {c['address']}/32")
    return state['header'] + '\n\n' + ''.join('[Peer]\n' + b + '\n\n' for b in blocks)


def sync(text, state=None):
    command, quick, iface, _, _ = engine(state or {})
    # wg strips Address and hook settings before sending the kernel configuration.
    fd, name = tempfile.mkstemp(dir=ROOT, suffix='.conf')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text)
        stripped = run(quick, 'strip', name)
        Path(name).write_text(stripped)
        run(command, 'syncconf', iface, name)
    finally:
        os.unlink(name)


def save(state):
    config = engine(state)[3]
    path = state_path(state)
    old, old_state = config.read_text(), path.read_text()
    text = render_server(state)
    prefix = 'awg-' if state.get('protocol') == 'amneziawg' else ''
    atomic(ROOT / (prefix + 'previous-server.conf'), old)
    atomic(ROOT / (prefix + 'previous-state.json'), old_state)
    try:
        sync(text, state)
        atomic(config, text)
        atomic(path, json.dumps(state))
    except Exception:
        atomic(config, old)
        atomic(path, old_state)
        sync(old, state)
        raise


def client_config(state, c):
    tuning = effective_tuning(state, c)
    mtu_line = f"MTU = {tuning['mtu']}"
    if state.get('protocol') == 'amneziawg':
        server = fields(state['header'])
        mtu_line += '\n' + '\n'.join(key + ' = ' + server[key] for key in AWG_KEYS if key in server)
    low_mtu = tuning['mtu'] < 1280
    warning = '# IPv4-only low-MTU profile. IPv6 is not captured and may bypass this VPN.\n' if low_mtu else ''
    routes = '0.0.0.0/0' if low_mtu else '0.0.0.0/0, ::/0'
    return f"""{warning}[Interface]
PrivateKey = {c['private']}
Address = {c['address']}/32
DNS = {tuning['dns']}
{mtu_line}

[Peer]
PublicKey = {state['serverPublic']}
PresharedKey = {c['psk']}
Endpoint = {state['host']}:{state['port']}
AllowedIPs = {routes}
PersistentKeepalive = {tuning['keepalive']}
"""


def effective_tuning(state, c):
    tuning = c.get('tuning', {})
    profile = tuning.get('profile', 'default')
    if profile not in {'default', 'custom', *PROFILES, *state.get('connectionPresets', {})}:
        profile = 'custom'
    return dict(profile=profile, mtu=tuning.get('mtu', state['mtu']),
                keepalive=tuning.get('keepalive', 25), dns=tuning.get('dns') or state['dns'])


def normalize_dns(value, required=False):
    raw = str(value).strip()
    if not raw and not required:
        return ''
    addresses = [str(ipaddress.ip_address(x.strip())) for x in raw.split(',')]
    if not 1 <= len(addresses) <= 3:
        raise ValueError('Provide one to three DNS addresses.')
    return ', '.join(addresses)


def set_tuning(client, body, state=None):
    profile = body.get('profile', 'default')
    if profile == 'default':
        dns = normalize_dns(body.get('dns', ''))
        if dns:
            client['tuning'] = dict(profile='default', dns=dns)
        else:
            client.pop('tuning', None)
        return
    if profile == 'custom':
        mtu, keepalive = int(body['mtu']), int(body['keepalive'])
    elif profile in {**PROFILES, **(state or {}).get('connectionPresets', {})}:
        selected = {**PROFILES, **(state or {}).get('connectionPresets', {})}[profile]
        mtu, keepalive = selected['mtu'], selected['keepalive']
    else:
        raise ValueError('Unknown network profile.')
    if not 576 <= mtu <= 1420 or not 0 <= keepalive <= 120:
        raise ValueError('MTU must be 1280–1420; keepalive must be 0–120 seconds.')
    dns = normalize_dns(body.get('dns', ''))
    client['tuning'] = dict(profile=profile, mtu=mtu, keepalive=keepalive, dns=dns)


def manage_preset(state, body):
    kind = body.get('kind')
    if kind not in ('connection', 'dns'):
        raise ValueError('Choose a connection or DNS preset.')
    presets = state.setdefault(kind + 'Presets', {})
    if body.get('action') == 'delete':
        key = body.get('id')
        if key not in presets:
            raise ValueError('Saved preset not found.')
        del presets[key]
        return
    if body.get('action') != 'save':
        raise ValueError('Unknown preset action.')
    name = str(body.get('name', '')).strip()
    if not re.fullmatch(r'[A-Za-z0-9 _-]{1,40}', name):
        raise ValueError('Preset names need 1–40 letters, numbers, spaces, underscores or hyphens.')
    key = next((key for key, value in presets.items() if value['label'].lower() == name.lower()), None)
    if key is None and len(presets) >= 50:
        raise ValueError('Limit of 50 saved presets reached.')
    key = key or 'saved-' + secrets.token_hex(8)
    if kind == 'dns':
        value = dict(label=name, dns=normalize_dns(body.get('dns', ''), required=True))
    else:
        mtu, keepalive = int(body['mtu']), int(body['keepalive'])
        if not 576 <= mtu <= 1420 or not 0 <= keepalive <= 120:
            raise ValueError('MTU must be 1280–1420; keepalive must be 0–120.')
        value = dict(label=name, mtu=mtu, keepalive=keepalive)
    presets[key] = value


def share_uri(state, client):
    if state.get('protocol') == 'amneziawg':
        raise ValueError('Use an AmneziaWG 3.1 compatible app and the native .conf or QR export. Standard WireGuard/Xray exports cannot preserve this protocol.')
    tuning = effective_tuning(state, client)
    query = urlencode(dict(publickey=state['serverPublic'], presharedkey=client['psk'],
                           address=client['address'] + '/32', mtu=tuning['mtu'],
                           dns=tuning['dns'].replace(' ', ''), reserved='0,0,0'), quote_via=quote)
    return 'wireguard://' + quote(client['private'], safe='') + '@' + state['host'] + ':' + str(state['port']) + '?' + query + '#' + quote(client['name'], safe='')


def xray_config(state, client):
    if state.get('protocol') == 'amneziawg':
        raise ValueError('Use an AmneziaWG 3.1 compatible app and the native .conf or QR export. Standard WireGuard/Xray exports cannot preserve this protocol.')
    tuning = effective_tuning(state, client)
    dns = [x.strip() for x in tuning['dns'].split(',')]
    return dict(log=dict(loglevel='warning'), dns=dict(servers=dns, queryStrategy='UseIPv4'),
        inbounds=[dict(tag='mixed', listen='127.0.0.1', port=10808, protocol='mixed', settings=dict(auth='noauth', udp=True)),
                  dict(tag='http', listen='127.0.0.1', port=10809, protocol='http', settings={})],
        outbounds=[dict(tag='proxy', protocol='wireguard', settings=dict(secretKey=client['private'],
            address=[client['address'] + '/32'], mtu=tuning['mtu'], noKernelTun=True,
            remoteDNS=dns, peers=[dict(endpoint=state['host'] + ':' + str(state['port']),
                publicKey=state['serverPublic'], preSharedKey=client['psk'], keepAlive=tuning['keepalive'], allowedIPs=['0.0.0.0/0'])])),
            dict(tag='block', protocol='blackhole', settings={})],
        routing=dict(domainStrategy='AsIs', rules=[dict(type='field', ip=['::/0'], outboundTag='block')]))


def diagnostics(state):
    _, _, iface, _, service = engine(state)
    checks = []
    def check(label, command, expected=None):
        try:
            output = run(*command)
            ok = output == expected if expected is not None else True
            checks.append(dict(label=label, ok=ok, detail=output[:500] or ('Present' if ok else 'Missing')))
            return output
        except Exception:
            checks.append(dict(label=label, ok=False, detail='Command failed or rule was not found'))
            return None
    check('AmneziaWG service' if state.get('protocol') == 'amneziawg' else 'WireGuard service', ('systemctl', 'is-active', service), 'active')
    check('IPv4 forwarding', ('sysctl', '-n', 'net.ipv4.ip_forward'), '1')
    wan = None
    try:
        routes = json.loads(run('ip', '-j', '-4', 'route', 'get', '1.1.1.1'))
        wan = routes[0]['dev']
        checks.append(dict(label='Outbound route', ok=True, detail='Interface: ' + wan))
    except Exception:
        checks.append(dict(label='Outbound route', ok=False, detail='Could not determine the outbound interface'))
    port = fields(state['header'])['ListenPort']
    check('WireGuard host firewall rule', ('iptables', '-C', 'INPUT', '-p', 'udp', '--dport', port, '-j', 'ACCEPT'))
    if wan:
        subnet = state['network']
        check('Outbound VPN forwarding rule', ('iptables', '-C', 'FORWARD', '-i', iface, '-o', wan, '-s', subnet, '-j', 'ACCEPT'))
        check('Return traffic forwarding rule', ('iptables', '-C', 'FORWARD', '-i', wan, '-o', iface, '-d', subnet, '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'))
        check('VPN internet NAT rule', ('iptables', '-t', 'nat', '-C', 'POSTROUTING', '-s', subnet, '-o', wan, '-j', 'MASQUERADE'))
    public_ip = check('VPS internet HTTPS access', ('curl', '-4fsS', '--connect-timeout', '3', '--max-time', '5', 'https://api.ipify.org'))
    if public_ip:
        try:
            ipaddress.IPv4Address(public_ip)
        except ValueError:
            checks[-1].update(ok=False, detail='Unexpected response from IP check')
    return dict(checks=checks, note='These are read-only server checks. A handshake proves peer connectivity, not internet access. Cloud firewalls, ISP filtering, client routing and path MTU require client-side tests.')


def client_metrics(state, peers, now=None):
    samples = AWG_SAMPLES if state.get('protocol') == 'amneziawg' else PEER_SAMPLES
    history = AWG_HISTORY if state.get('protocol') == 'amneziawg' else TRAFFIC_HISTORY
    now = time.time() if now is None else now
    clients, received_rate, sent_rate = [], 0.0, 0.0
    with METRICS_LOCK:
        for client in state['clients']:
            peer = dict(peers.get(client['public'], {}))
            enabled = client.get('enabled', True)
            before = samples.get(client['id'])
            rx, tx = peer.get('received', 0), peer.get('sent', 0)
            down, up, changes = 0.0, 0.0, before.get('changes', 0) if before else 0
            endpoint = peer.get('endpoint', '')
            if before:
                elapsed = now - before['time']
                if 1 <= elapsed <= 120 and rx >= before['rx'] and tx >= before['tx']:
                    down, up = (rx - before['rx']) / elapsed, (tx - before['tx']) / elapsed
                elif 0 <= elapsed < 1:
                    down, up = before.get('down', 0), before.get('up', 0)
                if endpoint and before.get('endpoint') and endpoint != before['endpoint']:
                    changes += 1
            if not enabled:
                down, up = 0.0, 0.0
            sample_time, sample_rx, sample_tx = now, rx, tx
            if before and 0 <= now - before['time'] < 1:
                sample_time, sample_rx, sample_tx = before['time'], before['rx'], before['tx']
            samples[client['id']] = dict(time=sample_time, rx=sample_rx, tx=sample_tx, endpoint=endpoint,
                                             changes=changes, down=down, up=up)
            handshake = peer.get('handshake', 0)
            recent = bool(enabled and handshake and 0 <= now - handshake <= 180)
            hints = []
            if not enabled:
                hints.append(dict(level='info', text='Paused. This peer is removed from WireGuard until resumed.'))
            elif not handshake:
                hints.append(dict(level='warning', text='No handshake recorded. Check endpoint, keys and UDP reachability.'))
            elif now - handshake > 300:
                hints.append(dict(level='info', text='No recent handshake. The device may be idle, offline or unable to reach the server.'))
            tuning = effective_tuning(state, client)
            if tuning['mtu'] < 1280:
                hints.append(dict(level='warning', text='Native config is IPv4-only below MTU 1280. IPv6 can bypass the VPN unless blocked on the device.'))
            if changes >= 2:
                hints.append(dict(level='info', text='Peer endpoint changed repeatedly. Check network switching or two apps sharing the same client keys.'))
            received_rate += down
            sent_rate += up
            clients.append(dict(id=client['id'], name=client['name'], address=client['address'], enabled=enabled,
                recent=recent, status='paused' if not enabled else ('recent' if recent else ('idle' if handshake else 'new')),
                tuning=tuning, dnsOverride=client.get('tuning', {}).get('dns', ''), receivedRate=round(down),
                sentRate=round(up), endpointChanges=changes, hints=hints, **peer))
        known = {c['id'] for c in state['clients']}
        for key in list(samples):
            if key not in known:
                del samples[key]
        point = dict(time=int(now), received=round(received_rate), sent=round(sent_rate))
        if not history or now - history[-1]['time'] >= 2:
            history.append(point)
            del history[:-60]
        return dict(clients=clients, traffic=dict(**point, history=list(history)),
                    summary=dict(total=len(clients), enabled=sum(c['enabled'] for c in clients),
                    recent=sum(c['recent'] for c in clients), received=sum(c.get('received', 0) for c in clients),
                    sent=sum(c.get('sent', 0) for c in clients)))


def audit(event):
    path = ROOT / 'activity.json'
    try:
        entries = json.loads(path.read_text()) if path.exists() else []
        entries.append(dict(time=int(time.time()), text=event))
        atomic(path, json.dumps(entries[-80:]))
    except (OSError, ValueError):
        pass


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
    if not 1 <= port <= 65535 or not 576 <= mtu <= 1420:
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
        self.send_header('Content-Security-Policy', "default-src 'self'; img-src 'self' data: blob:; font-src 'self' data:; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'")
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

    def route_protocol(self):
        protocol = 'wireguard'
        if self.path.startswith('/api/awg/'):
            self.path = '/api/' + self.path[len('/api/awg/'):]
            protocol = 'amneziawg'
        return protocol

    def do_GET(self):
        if not self.authorized():
            return
        try:
            if self.path == '/':
                return self.send(200, Path(__file__).with_name('panel.html').read_bytes(), 'text/html; charset=utf-8')
            protocol = self.route_protocol()
            if self.path == '/api/engines':
                return self.send(200, {'amneziawg': awg_install_status()})
            if protocol == 'amneziawg' and not state_path({'protocol': protocol}).exists():
                return self.send(409, {'error': 'AmneziaWG is not installed. Use the protocol installation card.'})
            state = load(protocol)
            if self.path == '/api/activity':
                path = ROOT / 'activity.json'
                return self.send(200, json.loads(path.read_text()) if path.exists() else [])
            if self.path == '/api/diagnostics':
                return self.send(200, diagnostics(state))
            if self.path == '/api/status':
                peers, error = {}, None
                try:
                    command, _, iface, _, service = engine(state)
                    dump = run(command, 'show', iface, 'dump').splitlines()
                    for line in dump[1:]:
                        p = line.split('\t')
                        peers[p[0]] = dict(endpoint='' if p[2] == '(none)' else p[2], handshake=int(p[4]), received=int(p[5]), sent=int(p[6]))
                except Exception:
                    error = 'VPN interface is unavailable. Check sudo systemctl status ' + engine(state)[4] + '.'
                return self.send(200, dict(protocol=state.get('protocol', 'wireguard'), interface=engine(state)[2],
                    obfuscation={k: v for k, v in fields(state['header']).items() if k in AWG_KEYS and k != 'HeaderProtectionKey'},
                    host=state['host'], port=state['port'], dns=state['dns'], mtu=state['mtu'],
                    profiles={**PROFILES, **state.get('connectionPresets', {})},
                    connectionPresets=state.get('connectionPresets', {}),
                    dnsPresets={**DNS_PRESETS, **state.get('dnsPresets', {})}, savedDnsPresets=state.get('dnsPresets', {}),
                    listenPort=fields(state['header'])['ListenPort'], error=error,
                    version=Path(__file__).with_name('VERSION').read_text().strip(),
                    unmanaged=len(state['unmanaged']), **client_metrics(state, peers)))
            match = re.fullmatch(r'/api/clients/([a-f0-9]{16})/(config|dns.zip|uri|xray|compatible|qr\.svg)', self.path)
            if match:
                c = next((c for c in state['clients'] if c['id'] == match[1]), None)
                if c:
                    if protocol == 'amneziawg' and match[2] not in ('config', 'qr.svg', 'dns.zip'):
                        return self.send(400, {'error': 'AmneziaWG requires a compatible 3.1 app. Download its native config or QR.'})
                    if match[2] == 'dns.zip':
                        presets = {**DNS_PRESETS, **state.get('dnsPresets', {})}
                        output = io.BytesIO()
                        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
                            for key, preset in presets.items():
                                tag = re.sub(r'[^A-Za-z0-9_-]', '-', key)[:60]
                                variant = dict(c, tuning={**c.get('tuning', {}), 'dns': preset['dns']})
                                archive.writestr(tag + '-' + c['name'] + '.conf', '# DNS preset: ' + preset['label'] + '\n' + client_config(state, variant))
                            archive.writestr('README.txt', 'These profiles share one client key. Activate only one at a time. DNS availability depends on the VPN exit network. Private Iranian resolvers may be unreachable from a foreign VPS.\n')
                        return self.send(200, output.getvalue(), 'application/zip', c['name'] + '-all-dns.zip')
                    if match[2] == 'qr.svg':
                        try:
                            svg = run('qrencode', '-t', 'SVG', '-m', '2', data=client_config(state, c))
                        except FileNotFoundError:
                            return self.send(503, {'error': 'Install qrencode on the VPS to enable QR exports.'})
                        return self.send(200, svg, 'image/svg+xml')
                    if match[2] == 'compatible':
                        c = dict(c, tuning=dict(profile='custom', mtu=1280, keepalive=25, dns='1.1.1.1, 1.0.0.1'))
                        return self.send(200, json.dumps(xray_config(state, c), indent=2), 'application/json', c['name'] + '-compatible-xray.json')
                    if match[2] == 'uri':
                        return self.send(200, share_uri(state, c) + '\n', 'text/plain', c['name'] + '-v2ray.txt')
                    if match[2] == 'xray':
                        return self.send(200, json.dumps(xray_config(state, c), indent=2), 'application/json', c['name'] + '-xray.json')
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
            if not isinstance(body, dict):
                raise ValueError('JSON object required.')
            protocol = self.route_protocol()
            if self.path == '/api/password':
                current, password = body.get('current'), body.get('password')
                if not isinstance(current, str) or not hmac.compare_digest(current.encode(), (ROOT / 'password').read_text().strip().encode()):
                    return self.send(403, {'error': 'Current password is incorrect.'})
                if not isinstance(password, str) or not 12 <= len(password) <= 200 or any(ord(c) < 32 or ord(c) == 127 for c in password) or password != password.strip():
                    raise ValueError('Use 12-200 characters without control characters or surrounding spaces.')
                atomic(ROOT / 'password', password + '\n')
                audit('Changed panel password')
                return self.send(200, {'ok': True})
            if self.path == '/api/awg-install':
                if protocol != 'wireguard':
                    raise ValueError('Invalid install route.')
                if awg_install_status().get('status') == 'installing':
                    return self.send(409, {'error': 'Installation is already running.'})
                unit = 'wg-auto-awg-install-' + str(int(time.time()))
                atomic(ROOT / 'awg-install.json', json.dumps(dict(status='installing', time=time.time(), unit=unit,
                    message='Building official AmneziaWG sources. This can take several minutes.')))
                try:
                    run('systemd-run', '--unit=' + unit, '--property=RuntimeMaxSec=1800',
                        '/usr/bin/python3', str(Path(__file__).resolve()), '--install-awg')
                except Exception:
                    atomic(ROOT / 'awg-install.json', json.dumps(dict(status='failed', message='Could not start install job.')))
                    raise
                return self.send(202, {'ok': True, 'unit': unit})
            if protocol == 'amneziawg' and not state_path({'protocol': protocol}).exists():
                return self.send(409, {'error': 'Install AmneziaWG before creating devices.'})
            state = load(protocol)
            details_match = re.fullmatch(r'/api/clients/([a-f0-9]{16})/details', self.path)
            tuning_match = re.fullmatch(r'/api/clients/([a-f0-9]{16})/tuning', self.path)
            if details_match:
                client = next((c for c in state['clients'] if c['id'] == details_match[1]), None)
                if not client:
                    raise ValueError('Client not found.')
                if 'name' in body:
                    name = str(body['name']).strip()
                    if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}', name):
                        raise ValueError('Use 1–40 letters, numbers, underscores or hyphens.')
                    if any(c['id'] != client['id'] and c['name'] == name for c in state['clients']):
                        raise ValueError('Client name already exists.')
                    client['name'] = name
                if 'enabled' in body:
                    if not isinstance(body['enabled'], bool):
                        raise ValueError('Enabled must be true or false.')
                    client['enabled'] = body['enabled']
                    save(state)
                else:
                    atomic(state_path(state), json.dumps(state))
                audit('Updated client ' + client['name'])
            elif self.path == '/api/clients/bulk':
                ids = body.get('ids')
                action = body.get('action')
                if not isinstance(ids, list) or not 1 <= len(ids) <= 64 or action not in ('enable', 'disable'):
                    raise ValueError('Select 1–64 clients and choose enable or disable.')
                if any(not isinstance(item, str) for item in ids):
                    raise ValueError('Invalid client selection.')
                selected = [c for c in state['clients'] if c['id'] in ids]
                if {c['id'] for c in selected} != set(ids):
                    raise ValueError('A selected client no longer exists.')
                for client in selected:
                    client['enabled'] = action == 'enable'
                save(state)
                audit(('Resumed ' if action == 'enable' else 'Paused ') + str(len(selected)) + ' client(s)')
            elif tuning_match:
                client = next((c for c in state['clients'] if c['id'] == tuning_match[1]), None)
                if not client:
                    raise ValueError('Client not found.')
                set_tuning(client, body, state)
                atomic(state_path(state), json.dumps(state))
                audit('Updated network settings for ' + client['name'])
            elif self.path == '/api/presets':
                manage_preset(state, body)
                atomic(state_path(state), json.dumps(state))
            elif self.path == '/api/settings':
                settings(state, body)
                # Endpoint/DNS/MTU changes affect exported configs, not the server listener.
                atomic(state_path(state), json.dumps(state))
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
                command = engine(state)[0]
                private = run(command, 'genkey')
                state['clients'].append(dict(id=secrets.token_hex(8), name=name, private=private,
                    public=run(command, 'pubkey', data=private + '\n'), psk=run(command, 'genpsk'), address=address))
                save(state)
                audit('Created client ' + name)
            elif self.path == '/api/revoke':
                target = body.get('id')
                if not any(c['id'] == target for c in state['clients']):
                    raise ValueError('Client not found.')
                state['clients'] = [c for c in state['clients'] if c['id'] != target]
                save(state)
                audit('Revoked a client')
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


# BEGIN EMBEDDED AWG INSTALLER
AWG_INSTALL_SCRIPT = '#!/usr/bin/env bash\n# Embedded into panel.py by build_panel.py. Official sources, isolated native interface.\nset -Eeuo pipefail\numask 077\n[[ $EUID -eq 0 ]] || { echo \'Root is required.\' >&2; exit 1; }\n[[ -d /run/systemd/system && -c /dev/net/tun ]] || { echo \'A systemd VPS with /dev/net/tun is required.\' >&2; exit 1; }\n. /etc/os-release\n[[ $ID == ubuntu || $ID == debian ]] || { echo \'Ubuntu or Debian is required.\' >&2; exit 1; }\nexec 9>/run/wg-auto-awg-install.lock\nflock -n 9 || { echo \'An AmneziaWG install is running.\' >&2; exit 1; }\nexport DEBIAN_FRONTEND=noninteractive\nbase=/opt/wg-auto/awg\nconfig=/etc/amnezia/amneziawg/awgauto0.conf\ndata=/etc/wireguard/wg-auto-panel\nservice=wg-auto-awg\nif [[ -f $config ]]; then\n  [[ -f $data/awg-managed ]] || { echo \'Existing unmanaged AWG configuration found; refusing to overwrite it.\' >&2; exit 1; }\n  systemctl enable --now "$service"\n  /usr/bin/python3 /opt/wg-auto/current/panel.py --initialize-awg\n  exit 0\nfi\nip link show awgauto0 >/dev/null 2>&1 && { echo \'Interface awgauto0 already exists and is not managed by this panel.\' >&2; exit 1; }\ncase $(uname -m) in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo \'Supported CPU architectures: amd64 and arm64.\' >&2; exit 1;; esac\napt-get update\napt-get install -y build-essential pkg-config libmnl-dev ca-certificates curl tar iproute2 iptables qrencode\nstage=$(mktemp -d /opt/wg-auto/awg-build.XXXXXXXX)\ncreated=0\nsuccess=0\ncleanup() {\n  if (( created && ! success )); then\n    systemctl stop "$service" || true\n    systemctl disable "$service" || true\n    rm -f "$config" "$data/awg-managed"\n  fi\n  rm -rf -- "$stage"\n}\ntrap cleanup EXIT\n# Go\'s official download manifest includes a SHA256 for the platform archive.\ncurl -fsSL --retry 2 --connect-timeout 15 --max-time 60 \'https://go.dev/dl/?mode=json\' -o "$stage/go.json"\nread -r gofile gosum < <(python3 - "$stage/go.json" "$arch" <<\'PY\'\nimport json,sys\nversions=json.load(open(sys.argv[1]))\nfor version in versions:\n    if not version[\'stable\']: continue\n    for f in version[\'files\']:\n        if f[\'os\']==\'linux\' and f[\'arch\']==sys.argv[2] and f[\'kind\']==\'archive\':\n            print(f[\'filename\'], f[\'sha256\']); sys.exit(0)\nraise SystemExit(\'No matching Go toolchain\')\nPY\n)\n[[ $gofile =~ ^go[0-9.]+\\.linux-(amd64|arm64)\\.tar\\.gz$ && $gosum =~ ^[a-f0-9]{64}$ ]] || exit 1\ncurl -fsSL --retry 2 --connect-timeout 15 --max-time 600 "https://go.dev/dl/$gofile" -o "$stage/go.tgz"\nprintf \'%s  %s\\n\' "$gosum" "$stage/go.tgz" | sha256sum -c -\ntar -xzf "$stage/go.tgz" -C "$stage"\n# Reviewed upstream releases, pinned to immutable commits.\ngo_sha=b5928efb6ca19f0153958460c3d141f04abc5c2e\ntools_sha=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843\nfor spec in "amneziawg-go:$go_sha" "amneziawg-tools:$tools_sha"; do\n  repo=${spec%:*}; sha=${spec#*:}\n  curl -fsSL --retry 2 --connect-timeout 15 --max-time 120 "https://codeload.github.com/amnezia-vpn/$repo/tar.gz/$sha" -o "$stage/$repo.tgz"\n  mkdir "$stage/$repo"\n  tar -xzf "$stage/$repo.tgz" -C "$stage/$repo" --strip-components=1\ndone\nexport PATH="$stage/go/bin:$PATH"\nexport GOTOOLCHAIN=local\nexport GOCACHE="$stage/go-cache" GOPATH="$stage/go-path"\n(cd "$stage/amneziawg-go" && GOMAXPROCS=2 go build -p 1 -trimpath -o "$stage/amneziawg-go.bin" .)\nmake -C "$stage/amneziawg-tools/src" -j2\ninstall -d -m 700 "$base/bin" /etc/amnezia/amneziawg "$data"\ninstall -m 755 "$stage/amneziawg-go.bin" "$base/bin/amneziawg-go"\ninstall -m 755 "$stage/amneziawg-tools/src/wg" "$base/bin/awg"\n# Force the pinned Go engine; an older installed kernel module must not silently\n# consume a newer 3.1 configuration. Preserve upstream license/copyright headers.\npython3 - "$stage/amneziawg-tools/src/wg-quick/linux.bash" <<\'PY\'\nimport sys\nfrom pathlib import Path\np=Path(sys.argv[1]); source=p.read_text()\na=source.index(\'add_if() {\'); b=source.index(\'\\ndel_if() {\',a)\nsource=source[:a]+\'add_if() {\\n    cmd "${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}" "$INTERFACE"\\n}\\n\'+source[b:]\np.write_text(source)\nPY\ninstall -m 755 "$stage/amneziawg-tools/src/wg-quick/linux.bash" "$base/bin/awg-quick"\nprintf \'amneziawg-go %s\\namneziawg-tools %s\\n\' "$go_sha" "$tools_sha" > "$base/SOURCES"\n# Generate an unused /24 and UDP port without changing the original WireGuard.\nexport AWG_INSTALL_CONFIG="$config"\ncreated=1\npython3 - <<\'PY\'\nimport ipaddress,json,os,secrets,subprocess\nfrom pathlib import Path\ndef run(*args, data=None):\n    return subprocess.run(args,input=data,text=True,capture_output=True,check=True).stdout.strip()\nroutes=json.loads(run(\'ip\',\'-j\',\'-4\',\'route\',\'show\',\'table\',\'all\'))\nnets=[ipaddress.ip_network(r[\'dst\'],strict=False) for r in routes if r.get(\'dst\') not in (None,\'default\')]\nnet=next((ipaddress.ip_network(f\'10.204.{i}.0/24\') for i in range(240,255)\n          if not any(ipaddress.ip_network(f\'10.204.{i}.0/24\').overlaps(n) for n in nets)),None)\nif not net: raise SystemExit(\'No free AWG subnet found\')\nports={int(line.split()[3].rsplit(\':\',1)[-1]) for line in run(\'ss\',\'-H\',\'-lun\').splitlines() if line.split()[3].rsplit(\':\',1)[-1].isdigit()}\nport=next((p for p in range(51821,51922) if p not in ports),None)\nif not port: raise SystemExit(\'No free AWG UDP port found\')\nwan=json.loads(run(\'ip\',\'-j\',\'-4\',\'route\',\'get\',\'1.1.1.1\'))[0][\'dev\']\nimport re\nif not re.fullmatch(r\'[A-Za-z0-9_.:-]+\',wan): raise SystemExit(\'Invalid WAN interface\')\nawg=\'/opt/wg-auto/awg/bin/awg\'\nlines=[\'[Interface]\',f\'Address = {net.network_address+1}/24\',f\'ListenPort = {port}\',\n       \'PrivateKey = \'+run(awg,\'genkey\'),\'MTU = 1280\', \'Jc = 4\',\'Jmin = 40\',\'Jmax = 700\',\n       f\'S1 = {16+secrets.randbelow(16)}\',f\'S2 = {40+secrets.randbelow(16)}\',\'S3 = 64\',\'S4 = 16\',\n       \'HeaderProtectionKey = \'+run(awg,\'genkey\'),\'ContentPaddingAddition = 0-16\']\nheaders=secrets.SystemRandom().sample(range(100000,4294967295),4)\nlines += [f\'H{i} = {value}\' for i,value in enumerate(headers,1)]\nrules=[f\'INPUT -p udp --dport {port} -j ACCEPT\',\n       f\'FORWARD -i %i -o {wan} -s {net} -j ACCEPT\',\n       f\'FORWARD -i {wan} -o %i -d {net} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\']\nfor rule in rules:\n    lines += [\'PostUp = iptables -I \'+rule,\'PostDown = iptables -D \'+rule]\nlines += [f\'PostUp = iptables -t nat -A POSTROUTING -s {net} -o {wan} -j MASQUERADE\',\n          f\'PostDown = iptables -t nat -D POSTROUTING -s {net} -o {wan} -j MASQUERADE\']\npath=Path(os.environ[\'AWG_INSTALL_CONFIG\']);path.write_text(\'\\n\'.join(lines)+\'\\n\');path.chmod(0o600)\nPY\ncreated=1\ntouch "$data/awg-managed"\ncat > /etc/systemd/system/wg-auto-awg.service <<\'EOF\'\n[Unit]\nDescription=Diana native AmneziaWG interface\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\nEnvironment=PATH=/opt/wg-auto/awg/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nExecStart=/opt/wg-auto/awg/bin/awg-quick up /etc/amnezia/amneziawg/awgauto0.conf\nExecStop=/opt/wg-auto/awg/bin/awg-quick down /etc/amnezia/amneziawg/awgauto0.conf\nTimeoutStartSec=45\nUMask=0077\n[Install]\nWantedBy=multi-user.target\nEOF\nsysctl -w net.ipv4.ip_forward=1\nsystemctl daemon-reload\nsystemctl enable --now "$service"\n"$base/bin/awg" show awgauto0 public-key >/dev/null\n/usr/bin/python3 /opt/wg-auto/current/panel.py --initialize-awg\nsuccess=1\necho \'AmneziaWG is ready. Create an AmneziaWG device in Diana and import its config into an AmneziaWG 3.1 compatible app.\'\n'
# END EMBEDDED AWG INSTALLER


def install_awg():
    try:
        subprocess.run(['bash', '-s'], input=AWG_INSTALL_SCRIPT, text=True, check=True, timeout=1700)
        atomic(ROOT / 'awg-install.json', json.dumps(dict(status='ready', installed=True, time=time.time(),
            message='AmneziaWG is ready. Select its workspace and create a device.')))
    except Exception:
        atomic(ROOT / 'awg-install.json', json.dumps(dict(status='failed', time=time.time(),
            message='Installation failed. Inspect journalctl -u "wg-auto-awg-install-*". Existing WireGuard was not changed.')))
        raise


if __name__ == '__main__':
    os.umask(0o077)
    if sys.argv[1:] == ['--install-awg']:
        install_awg()
        sys.exit(0)
    if sys.argv[1:] == ['--initialize-awg']:
        initialize_awg()
        sys.exit(0)
    initialize()
    server = make_server()
    server.timeout = 15
    server.socket.settimeout(15)
    server.serve_forever()

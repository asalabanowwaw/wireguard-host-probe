#!/usr/bin/env python3
"""Local WireGuard tuner using isolated Xray processes, never system routes."""
import argparse
import base64
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import statistics
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

import panel

LOCK = threading.Lock()
STOP = threading.Event()
TOKEN = secrets.token_urlsafe(32)
IMPORTED = None
PROCESS = None
XRAY = None
REPORT = dict(running=False, phase='Ready', trials=[], best=None, preflight=None)
REPORT_PATH = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.local' / 'share'))) / 'WireGuardNetworkTuner' / 'last-report.json'
SIZES = [1280, 1360, 1420]
DNS_CHOICES = ['1.1.1.1', '8.8.8.8', '9.9.9.9']


def valid_key(value):
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except Exception:
        return False


def parse_config(text):
    text = text.strip()
    if len(text) > 65536:
        raise ValueError('Config is too large.')
    if text.startswith('wireguard://'):
        uri = urlsplit(text)
        query = {k: v[0] for k, v in parse_qs(uri.query).items()}
        host, port = uri.hostname, uri.port
        private = unquote(uri.username or '')
        public, psk = query.get('publickey', ''), query.get('presharedkey', '')
        address = query.get('address', '').split(',')[0]
        dns = query.get('dns', '1.1.1.1')
        mtu = int(query.get('mtu', 1280))
        keepalive = 25  # URI parsers do not retain this value.
        name = unquote(uri.fragment) or 'tuned-client'
    elif text.startswith('{'):
        data = json.loads(text)
        outbound = next((x for x in data.get('outbounds', []) if x.get('protocol') == 'wireguard'), None)
        if not outbound:
            raise ValueError('JSON needs a WireGuard outbound.')
        settings = outbound['settings']
        peer = settings['peers'][0]
        host, raw_port = peer['endpoint'].rsplit(':', 1)
        port = int(raw_port)
        private, public, psk = settings['secretKey'], peer['publicKey'], peer.get('preSharedKey', '')
        address = settings['address'][0]
        dns = ', '.join(settings.get('remoteDNS', ['1.1.1.1']))
        mtu, keepalive = int(settings.get('mtu', 1280)), int(peer.get('keepAlive', 25))
        name = 'tuned-client'
    else:
        parts = re.split(r'\[Peer\]', text, flags=re.I)
        if len(parts) != 2:
            raise ValueError('Import a config with exactly one WireGuard peer.')
        interface, peer = panel.fields(parts[0]), panel.fields(parts[1])
        host, raw_port = peer['Endpoint'].rsplit(':', 1)
        port = int(raw_port)
        private, public, psk = interface['PrivateKey'], peer['PublicKey'], peer.get('PresharedKey', '')
        address = interface['Address'].split(',')[0]
        dns = interface.get('DNS', '1.1.1.1')
        mtu, keepalive = int(interface.get('MTU', 1280)), int(peer.get('PersistentKeepalive', 25))
        name = 'tuned-client'
    if not host or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host) or not 1 <= port <= 65535:
        raise ValueError('An IPv4 or hostname endpoint and valid port are required.')
    if not valid_key(private) or not valid_key(public) or (psk and not valid_key(psk)):
        raise ValueError('Invalid WireGuard key encoding.')
    addr = ipaddress.ip_interface(address)
    if addr.version != 4:
        raise ValueError('This tuner currently supports IPv4 client addresses.')
    if not 1280 <= mtu <= 1420 or not 0 <= keepalive <= 120:
        raise ValueError('Use an MTU of 1280–1420 and keepalive of 0–120.')
    dns = panel.normalize_dns(dns, required=True)
    return dict(state=dict(host=host, port=port, serverPublic=public, dns=dns, mtu=mtu),
                client=dict(name=re.sub(r'[^A-Za-z0-9_-]', '-', name)[:40], address=str(addr.ip),
                            private=private, psk=psk, tuning=dict(profile='custom', mtu=mtu, keepalive=keepalive, dns=dns)))


def summary():
    if not IMPORTED:
        return None
    return dict(host=IMPORTED['state']['host'], port=IMPORTED['state']['port'],
                address=IMPORTED['client']['address'], mtu=IMPORTED['client']['tuning']['mtu'])


def curl_probe(url, proxy=None, timeout=10, download=False, connect_timeout=8):
    """Only hard-coded public test endpoints are passed by callers."""
    curl = shutil.which('curl.exe') or shutil.which('curl')
    if not curl:
        return dict(ok=False, error='curl is not installed')
    with tempfile.TemporaryDirectory(prefix='wg-tuner-curl-') as directory:
        body = Path(directory) / 'body'
        command = [curl, '-4', '--silent', '--show-error', '--fail', '--connect-timeout', str(min(connect_timeout, timeout)),
                   '--max-time', str(timeout), '--max-filesize', '1048576', '--output', str(body),
                   '--write-out', '%{json}', '--proxy', f'http://127.0.0.1:{proxy}' if proxy else '',
                   '--noproxy', '' if proxy else '*', url]
        result = subprocess.run(command, text=True, capture_output=True, timeout=timeout + 4,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        try:
            stats = json.loads(result.stdout)
        except ValueError:
            stats = {}
        size = body.stat().st_size if body.exists() else 0
        return dict(ok=result.returncode == 0 and stats.get('http_code') == 200,
                    code=stats.get('http_code'), ms=round(stats.get('time_total', 0) * 1000, 1),
                    ttfbMs=round(stats.get('time_starttransfer', 0) * 1000, 1),
                    bytes=size, mbps=round(stats.get('speed_download', 0) * 8 / 1000000, 3),
                    text='' if download else (body.read_text(errors='replace')[:1000] if body.exists() else ''),
                    error='' if result.returncode == 0 else (result.stderr.strip()[:350] or 'Request failed'))


def preflight():
    direct = curl_probe('https://api.ipify.org')
    proxy = curl_probe('https://api.ipify.org', proxy=10809)
    return dict(direct=direct, existingProxy=proxy,
                note='The proxy test uses v2rayN HTTP port 10809. A different local port may be configured. Direct tests bypass the system HTTP proxy but still follow any active TUN/VPN routes.')


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def pick_best(trials):
    good = [t for t in trials if t.get('successes', 0) == 2 and t.get('download', {}).get('ok')]
    if not good:
        return None
    # Rank only fully successful trials. Small downloads include connection setup,
    # so this is a comparative sample, not a full internet speed measurement.
    return max(good, key=lambda t: (t['download']['mbps'], -t['medianMs']))


def run_trial(imported, mtu, dns, dns_bypass=False):
    global PROCESS
    state, client = copy.deepcopy(imported['state']), copy.deepcopy(imported['client'])
    client['tuning'] = dict(profile='custom', mtu=mtu, keepalive=25, dns=dns)
    config = panel.xray_config(state, client)
    port = free_port()
    config['inbounds'] = [dict(tag='test-http', listen='127.0.0.1', port=port, protocol='http', settings={})]
    config['log']['loglevel'] = 'debug'
    with tempfile.TemporaryDirectory(prefix='wg-tuner-private-') as directory:
        path = Path(directory) / 'config.json'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(config, f)
        log_path = Path(directory) / 'core.log'
        log_file = log_path.open('w')
        try:
            process = subprocess.Popen([str(XRAY), 'run', '-config', str(path)], stdout=log_file,
                                       stderr=log_file, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except Exception:
            log_file.close()
            raise
        PROCESS = process
        try:
            ready = False
            for _ in range(50):
                if STOP.is_set():
                    raise InterruptedError('Scan cancelled')
                if process.poll() is not None:
                    raise RuntimeError('Xray exited before starting. Check imported keys and core version.')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.15):
                        ready = True
                        break
                except OSError:
                    STOP.wait(.1)
            if not ready:
                raise RuntimeError('Xray local listener did not start.')
            probes = []
            for _ in range(2):
                if STOP.is_set():
                    raise InterruptedError('Scan cancelled')
                url = 'https://1.1.1.1/cdn-cgi/trace' if dns_bypass else 'https://api.ipify.org'
                probes.append(curl_probe(url, proxy=port, timeout=12))
            download = dict(ok=False)
            if any(p['ok'] for p in probes) and not STOP.is_set() and not dns_bypass:
                download = curl_probe('https://speed.cloudflare.com/__down?bytes=524288', proxy=port, timeout=12, download=True)
            successful = [p['ms'] for p in probes if p['ok']]
            raw_log = log_path.read_text(errors='replace').lower()
            handshakes = dict(initiations=raw_log.count('sending handshake initiation'),
                              responses=raw_log.count('receiving handshake response'))
            return dict(mtu=mtu, dns=dns, keepalive=25, successes=len(successful), probes=probes,
                        medianMs=round(statistics.median(successful), 1) if successful else None,
                        download=download, handshakes=handshakes,
                        exitIp=next((p['text'].strip() for p in probes if p['ok']), None))
        finally:
            process.terminate()
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=4)
            PROCESS = None
            log_file.close()


def run_scan(mode):
    global REPORT
    try:
        REPORT['phase'] = 'Checking current internet and v2rayN proxy'
        REPORT['preflight'] = preflight()
        if mode == 'preflight':
            return
        combos = [(mtu, dns) for mtu in SIZES for dns in DNS_CHOICES]
        # Alternate DNS order on successive MTUs to reduce fixed order effects.
        combos[3:6] = list(reversed(combos[3:6]))
        for index, (mtu, dns) in enumerate(combos):
            if STOP.is_set():
                break
            REPORT['phase'] = f'Trial {index + 1}/{len(combos)}: MTU {mtu}, DNS {dns}'
            result = run_trial(IMPORTED, mtu, dns)
            with LOCK:
                REPORT['trials'].append(result)
                REPORT['best'] = pick_best(REPORT['trials'])
        if REPORT['trials'] and not REPORT['best'] and not STOP.is_set():
            REPORT['phase'] = 'Checking tunnel without DNS'
            REPORT['diagnostic'] = run_trial(IMPORTED, 1280, '1.1.1.1', dns_bypass=True)
            REPORT['error'] = 'No fully successful combination. MTU/DNS tuning cannot fix an unreachable endpoint, wrong keys, blocked UDP, or broken server forwarding. Use the VPS panel diagnostics.'
    except InterruptedError:
        pass
    except Exception as error:
        REPORT['error'] = str(error)
    finally:
        REPORT['running'] = False
        REPORT['phase'] = 'Cancelled' if STOP.is_set() else 'Finished'
        try:
            REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
            panel.atomic(REPORT_PATH, json.dumps(dict(report=REPORT, client=summary())))
        except OSError:
            pass


def export_data(kind):
    if not IMPORTED or not REPORT.get('best'):
        raise ValueError('Run a scan with a fully successful trial first.')
    best = REPORT['best']
    state, client = copy.deepcopy(IMPORTED['state']), copy.deepcopy(IMPORTED['client'])
    client['tuning'] = dict(profile='custom', mtu=best['mtu'], keepalive=25, dns=best['dns'])
    if kind == 'preset':
        return json.dumps(dict(format='wg-auto-tuning-v1', name='PC measured', mtu=best['mtu'], keepalive=25,
                               dns=best['dns'], measuredAt=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                               note='Best successful short trial; repeat to confirm. Keepalive was fixed at 25, not benchmarked.'), indent=2)
    if kind == 'config':
        return panel.client_config(state, client)
    if kind == 'uri':
        return panel.share_uri(state, client)
    if kind == 'xray':
        return json.dumps(panel.xray_config(state, client), indent=2)
    raise ValueError('Unknown export format.')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def send(self, status, body, content_type='application/json'):
        if not isinstance(body, (str, bytes)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def allowed(self, root=False):
        host = self.headers.get('Host', '')
        if host not in (f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'):
            self.send(403, dict(error='Invalid local hostname'))
            return False
        if not root and not secrets.compare_digest(self.headers.get('X-Local-Token', ''), TOKEN):
            self.send(403, dict(error='Open this app on localhost first'))
            return False
        return True

    def do_GET(self):
        if not self.allowed(root=self.path == '/'):
            return
        if self.path == '/':
            page = Path(__file__).with_name('local_app.html').read_text(encoding='utf-8').replace('__SESSION_TOKEN__', TOKEN)
            return self.send(200, page, 'text/html; charset=utf-8')
        if self.path == '/api/status':
            with LOCK:
                report = copy.deepcopy(REPORT)
            return self.send(200, dict(report=report, imported=summary(), coreAvailable=bool(XRAY and XRAY.exists()), core='Xray'))
        if self.path.startswith('/api/export/'):
            try:
                return self.send(200, export_data(self.path.rsplit('/', 1)[-1]), 'text/plain; charset=utf-8')
            except ValueError as error:
                return self.send(400, dict(error=str(error)))
        self.send(404, dict(error='Not found'))

    def do_POST(self):
        global IMPORTED, REPORT
        if not self.allowed():
            return
        if self.headers.get('Content-Type') != 'application/json':
            return self.send(403, dict(error='JSON required'))
        try:
            length = int(self.headers.get('Content-Length', 0))
            if not 0 < length <= 70000:
                raise ValueError('Invalid request size')
            body = json.loads(self.rfile.read(length))
            if self.path == '/api/import':
                with LOCK:
                    if REPORT['running']:
                        raise ValueError('Stop the scan before importing another client.')
                    IMPORTED = parse_config(str(body.get('text', '')))
                    REPORT = dict(running=False, phase='Configuration imported', trials=[], best=None, preflight=None)
                return self.send(200, dict(ok=True, imported=summary()))
            if self.path == '/api/stop':
                STOP.set()
                return self.send(200, dict(ok=True))
            if self.path == '/api/scan':
                mode = body.get('mode', 'preflight')
                if mode not in ('preflight', 'full'):
                    raise ValueError('Unknown scan mode')
                with LOCK:
                    if REPORT['running']:
                        raise ValueError('A scan is already running.')
                    if mode == 'full' and (not IMPORTED or not XRAY or not XRAY.exists()):
                        raise ValueError('Import a configuration and install the official Xray core first.')
                    if mode == 'full' and body.get('separateClientConfirmed') is not True:
                        raise ValueError('Stop other apps using this client or use a separate test client.')
                    STOP.clear()
                    REPORT = dict(running=True, phase='Starting', trials=[], best=None, preflight=None)
                    threading.Thread(target=run_scan, args=(mode,), daemon=True).start()
                return self.send(200, dict(ok=True))
            self.send(404, dict(error='Not found'))
        except (ValueError, KeyError, TypeError, StopIteration) as error:
            self.send(400, dict(error=str(error)))


def main():
    global XRAY, IMPORTED, REPORT
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8788)
    tool_root = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.local' / 'share'))) / 'WireGuardNetworkTuner' / 'tools'
    parser.add_argument('--xray', type=Path, default=tool_root / ('xray.exe' if os.name == 'nt' else 'xray'))
    parser.add_argument('--config', type=Path)
    args = parser.parse_args()
    XRAY = args.xray.resolve()
    if args.config:
        IMPORTED = parse_config(args.config.read_text(encoding='utf-8-sig'))
    if REPORT_PATH.exists():
        try:
            previous = json.loads(REPORT_PATH.read_text(encoding='utf-8-sig'))
            if previous.get('client') == summary():
                REPORT = previous['report']
                REPORT.update(running=False, phase='Previous scan results')
        except (ValueError, KeyError, TypeError):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    print(f'WireGuard local tuner: http://127.0.0.1:{server.server_port}', flush=True)
    try:
        server.serve_forever()
    finally:
        STOP.set()
        if PROCESS:
            PROCESS.terminate()
        server.server_close()


if __name__ == '__main__':
    main()

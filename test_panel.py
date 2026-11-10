import base64
import json
from pathlib import Path
import tempfile
import os
import shutil
import ssl
import subprocess
import http.client
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit, parse_qs, unquote

import panel


class PanelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.paths = patch.multiple(panel, ROOT=root, CONFIG=root / 'server.conf')
        self.paths.start()
        self.state = dict(header='[Interface]\nPrivateKey = server-private\nAddress = 10.203.240.1/24\nListenPort = 51820',
                          unmanaged=['PublicKey = unmanaged\nAllowedIPs = 10.203.240.3/32'],
                          clients=[dict(id='0123456789abcdef', name='phone', address='10.203.240.2',
                                        private='client-private', public='client-public', psk='shared')],
                          host='vpn.example.com', port=51820, dns='1.1.1.1', mtu=1280,
                          network='10.203.240.0/24', serverPublic='server-public')
        panel.atomic(root / 'state.json', json.dumps(self.state))
        panel.atomic(root / 'password', 'test-password\n')
        panel.atomic(panel.CONFIG, panel.render_server(self.state))
        self.commands = []

        def fake_run(*args, data=None):
            self.commands.append(args)
            if args[:2] == ('wg', 'genkey'):
                return 'new-private'
            if args[:2] == ('wg', 'genpsk'):
                return 'new-psk'
            if args[:2] == ('wg', 'pubkey'):
                return 'new-public'
            if args[:2] == ('wg-quick', 'strip'):
                return Path(args[2]).read_text()
            if args == ('wg', 'show', 'wgauto0', 'dump'):
                return 'private\tpublic\t51820\toff\nclient-public\tshared\t(none)\t10.203.240.2/32\t0\t123\t456\t25'
            return ''
        self.runner = patch.object(panel, 'run', side_effect=fake_run)
        self.runner.start()
        self.http = panel.HTTPServer(('127.0.0.1', 0), panel.Handler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.base = 'http://127.0.0.1:' + str(self.http.server_port)

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join()
        self.runner.stop()
        self.paths.stop()
        self.temp.cleanup()

    def request(self, path, body=None, auth=True, csrf=True):
        headers = {}
        if auth:
            headers['Authorization'] = 'Basic ' + base64.b64encode(b'admin:test-password').decode()
        if body is not None:
            headers['Content-Type'] = 'application/json'
            if csrf:
                headers['X-WG-Panel'] = '1'
        request = Request(self.base + path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
        try:
            return urlopen(request, timeout=3)
        except HTTPError as e:
            return e

    def test_auth_and_csrf(self):
        self.assertEqual(self.request('/api/status', auth=False).status, 401)
        self.assertEqual(self.request('/api/clients', {'name': 'laptop'}, csrf=False).status, 403)
        self.assertEqual(len(panel.load()['clients']), 1)

    def test_status_hides_secrets_and_download_is_private(self):
        response = self.request('/api/status')
        text = response.read().decode()
        self.assertNotIn('client-private', text)
        self.assertNotIn('shared', text)
        self.assertEqual(json.loads(text)['clients'][0]['received'], 123)
        self.assertEqual(self.request('/api/clients/0123456789abcdef/config', auth=False).status, 401)
        response = self.request('/api/clients/0123456789abcdef/config')
        self.assertIn('no-store', response.headers['Cache-Control'])
        self.assertIn('client-private', response.read().decode())

    def test_create_skips_unmanaged_peer_and_revoke_syncs(self):
        self.assertEqual(self.request('/api/clients', {'name': 'laptop'}).status, 200)
        state = panel.load()
        created = state['clients'][-1]
        self.assertEqual(created['address'], '10.203.240.4')
        self.assertIn('PublicKey = unmanaged', panel.CONFIG.read_text())
        self.assertEqual(self.request('/api/clients', {'name': 'laptop'}).status, 400)
        self.assertEqual(self.request('/api/revoke', {'id': created['id']}).status, 200)
        self.assertNotIn('new-public', panel.CONFIG.read_text())
        self.assertTrue(any(c[:2] == ('wg', 'syncconf') for c in self.commands))

    def test_settings_validate_and_preserve_keys(self):
        body = dict(host='new.example.com', port=443, dns='9.9.9.9, 1.1.1.1', mtu=1360)
        before = panel.CONFIG.read_text()
        self.assertEqual(self.request('/api/settings', body).status, 200)
        self.assertEqual(panel.CONFIG.read_text(), before)
        self.assertEqual(panel.load()['clients'][0]['private'], 'client-private')
        config = self.request('/api/clients/0123456789abcdef/config').read().decode()
        self.assertIn('Endpoint = new.example.com:443', config)
        body['host'] = 'x\nPrivateKey = injected'
        self.assertEqual(self.request('/api/settings', body).status, 400)

    def test_failed_sync_restores_state_and_server(self):
        old_config = panel.CONFIG.read_text()
        old_state = (panel.ROOT / 'state.json').read_text()
        state = panel.load()
        state['clients'] = []
        with patch.object(panel, 'sync', side_effect=[RuntimeError('sync failed'), None]):
            with self.assertRaises(RuntimeError):
                panel.save(state)
        self.assertEqual(panel.CONFIG.read_text(), old_config)
        self.assertEqual((panel.ROOT / 'state.json').read_text(), old_state)

    def test_update_runs_separate_systemd_job(self):
        self.assertEqual(self.request('/api/update', {}).status, 200)
        self.assertTrue(any(c[0] == 'systemd-run' and c[-1] == '/usr/local/sbin/wg-auto-update' for c in self.commands))

    def test_network_profile_updates_only_selected_client_export(self):
        self.assertEqual(self.request('/api/clients', {'name': 'laptop'}).status, 200)
        before = panel.load()
        before_config = panel.CONFIG.read_text()
        self.commands.clear()
        path = '/api/clients/0123456789abcdef/tuning'
        self.assertEqual(self.request(path, {'profile': 'balanced'}).status, 200)
        after = panel.load()
        self.assertEqual(before['clients'][0]['private'], after['clients'][0]['private'])
        self.assertEqual(before['clients'][1], after['clients'][1])
        self.assertEqual(panel.CONFIG.read_text(), before_config)
        self.assertEqual(self.commands, [])
        config = self.request('/api/clients/0123456789abcdef/config').read().decode()
        self.assertIn('MTU = 1360', config)
        self.assertIn('PersistentKeepalive = 25', config)
        self.assertEqual(self.request(path, {'profile': 'custom', 'mtu': 1380, 'keepalive': 15, 'dns': '9.9.9.9'}).status, 200)
        config = self.request('/api/clients/0123456789abcdef/config').read().decode()
        self.assertIn('MTU = 1380', config)
        self.assertIn('PersistentKeepalive = 15', config)
        self.assertIn('DNS = 9.9.9.9', config)
        self.assertEqual(self.request(path, {'profile': 'default'}).status, 200)
        self.assertNotIn('tuning', panel.load()['clients'][0])

    def test_network_profiles_validate_and_require_auth(self):
        path = '/api/clients/0123456789abcdef/tuning'
        old = (panel.ROOT / 'state.json').read_text()
        self.assertEqual(self.request(path, {'profile': 'idle'}, auth=False).status, 401)
        self.assertEqual(self.request(path, {'profile': 'idle'}, csrf=False).status, 403)
        for body in [dict(profile='invalid'), dict(profile='custom', mtu=9000, keepalive=25),
                     dict(profile='custom', mtu=1280, keepalive=-1), dict(profile='balanced', dns='invalid'),
                     dict(profile='custom', mtu='invalid', keepalive=25)]:
            self.assertEqual(self.request(path, body).status, 400)
            self.assertEqual((panel.ROOT / 'state.json').read_text(), old)
        self.assertEqual(self.request(path, {'profile': 'idle'}).status, 200)
        config = self.request('/api/clients/0123456789abcdef/config').read().decode()
        self.assertIn('PersistentKeepalive = 0', config)

    def test_saved_presets_apply_as_snapshots_and_survive_delete(self):
        connection = dict(kind='connection', action='save', name='My LTE', mtu=1320, keepalive=15)
        self.assertEqual(self.request('/api/presets', connection).status, 200)
        key = next(iter(panel.load()['connectionPresets']))
        dns = dict(kind='dns', action='save', name='My DNS', dns='9.9.9.9,1.1.1.1')
        self.assertEqual(self.request('/api/presets', dns).status, 200)
        normalized = next(iter(panel.load()['dnsPresets'].values()))['dns']
        self.assertEqual(normalized, '9.9.9.9, 1.1.1.1')
        path = '/api/clients/0123456789abcdef/tuning'
        self.assertEqual(self.request(path, dict(profile=key, dns=normalized)).status, 200)
        original = self.request('/api/clients/0123456789abcdef/config').read()
        connection['mtu'] = 1400
        self.assertEqual(self.request('/api/presets', connection).status, 200)
        self.assertEqual(len(panel.load()['connectionPresets']), 1)
        self.assertEqual(self.request('/api/clients/0123456789abcdef/config').read(), original)
        self.assertEqual(self.request('/api/presets', dict(kind='connection', action='delete', id=key)).status, 200)
        self.assertEqual(self.request('/api/clients/0123456789abcdef/config').read(), original)
        status = json.load(self.request('/api/status'))
        self.assertEqual(status['clients'][0]['tuning']['profile'], 'custom')
        self.assertIn('quad9', status['dnsPresets'])

    def test_default_connection_can_have_independent_dns(self):
        self.assertEqual(self.request('/api/clients/0123456789abcdef/tuning', dict(profile='default', dns='9.9.9.9')).status, 200)
        state = panel.load()
        state['mtu'] = 1390
        config = panel.client_config(state, state['clients'][0])
        self.assertIn('MTU = 1390', config)
        self.assertIn('DNS = 9.9.9.9', config)

    def test_presets_validate_and_require_auth(self):
        body = dict(kind='dns', action='save', name='test', dns='1.1.1.1')
        self.assertEqual(self.request('/api/presets', body, auth=False).status, 401)
        self.assertEqual(self.request('/api/presets', body, csrf=False).status, 403)
        for bad in [dict(body, dns='not-an-ip'), dict(body, name='bad\nname'), dict(body, kind='invalid'),
                    dict(kind='connection', action='save', name='bad', mtu=9000, keepalive=25)]:
            self.assertEqual(self.request('/api/presets', bad).status, 400)

    def test_v2ray_uri_and_xray_exports_use_tuned_settings(self):
        state = panel.load()
        c = state['clients'][0]
        c['private'] = base64.b64encode(bytes([251]) * 32).decode()
        c['psk'] = base64.b64encode(bytes([255]) * 32).decode()
        panel.atomic(panel.ROOT / 'state.json', json.dumps(state))
        path = '/api/clients/0123456789abcdef/'
        self.assertEqual(self.request(path + 'uri', auth=False).status, 401)
        self.assertEqual(self.request(path + 'xray', auth=False).status, 401)
        self.assertEqual(self.request(path + 'tuning', dict(profile='custom', mtu=1320, keepalive=15, dns='9.9.9.9')).status, 200)
        uri_response = self.request(path + 'uri')
        self.assertEqual(uri_response.headers['Cache-Control'], 'no-store')
        uri = urlsplit(uri_response.read().decode().strip())
        self.assertEqual(uri.scheme, 'wireguard')
        self.assertEqual(unquote(uri.username), c['private'])
        self.assertEqual(uri.hostname, state['host'])
        self.assertEqual(uri.port, state['port'])
        query = parse_qs(uri.query)
        self.assertEqual(query['presharedkey'], [c['psk']])
        self.assertEqual(query['publickey'], [state['serverPublic']])
        self.assertEqual(query['mtu'], ['1320'])
        self.assertEqual(query['dns'], ['9.9.9.9'])
        config = json.load(self.request(path + 'xray'))
        settings = config['outbounds'][0]['settings']
        self.assertEqual(settings['secretKey'], c['private'])
        self.assertEqual(settings['mtu'], 1320)
        self.assertEqual(settings['remoteDNS'], ['9.9.9.9'])
        self.assertEqual(settings['peers'][0]['keepAlive'], 15)
        self.assertEqual(settings['peers'][0]['preSharedKey'], c['psk'])
        self.assertEqual(config['inbounds'][0]['listen'], '127.0.0.1')
        self.assertEqual(config['routing']['rules'][0]['outboundTag'], 'block')
        self.assertEqual(config['inbounds'][0]['protocol'], 'mixed')

    def test_compatibility_export_does_not_modify_saved_client(self):
        before = (panel.ROOT / 'state.json').read_text()
        self.assertEqual(self.request('/api/clients/0123456789abcdef/compatible', auth=False).status, 401)
        exported = json.load(self.request('/api/clients/0123456789abcdef/compatible'))
        self.assertEqual(exported['outbounds'][0]['settings']['mtu'], 1280)
        self.assertEqual(exported['outbounds'][0]['settings']['remoteDNS'], ['1.1.1.1', '1.0.0.1'])
        self.assertEqual(exported['inbounds'][0]['protocol'], 'mixed')
        self.assertEqual((panel.ROOT / 'state.json').read_text(), before)

    def test_diagnostics_are_authenticated_and_read_only(self):
        self.assertEqual(self.request('/api/diagnostics', auth=False).status, 401)
        def checked(*args, data=None):
            if args == ('ip', '-j', '-4', 'route', 'get', '1.1.1.1'):
                return '[{"dev":"eth0"}]'
            if args[0] == 'systemctl':
                return 'active'
            if args[0] == 'sysctl':
                return '1'
            if args[0] == 'curl':
                return '192.0.2.1'
            self.assertIn('-C', args)
            self.assertNotIn('-A', args)
            self.assertNotIn('-I', args)
            return ''
        with patch.object(panel, 'run', side_effect=checked):
            response = json.load(self.request('/api/diagnostics'))
        self.assertTrue(all(c['ok'] for c in response['checks']))

    def test_upgrade_imports_original_client_without_losing_other_peers(self):
        (panel.ROOT / 'state.json').unlink()
        original = panel.ROOT / 'original-client.conf'
        original.write_text('[Interface]\nPrivateKey = original-private\nAddress = 10.203.240.2/32\nDNS = 1.1.1.1\n[Peer]\nEndpoint = vpn.example.com:51820\n')
        text = panel.CONFIG.read_text().replace('client-public', 'new-public')
        panel.CONFIG.write_text(text)
        with patch.object(panel, 'ORIGINAL_CLIENT', original):
            panel.initialize()
        state = panel.load()
        self.assertEqual(state['clients'][0]['private'], 'original-private')
        self.assertEqual(state['clients'][0]['name'], 'original-client')
        self.assertEqual(len(state['unmanaged']), 1)
        self.assertEqual(panel.CONFIG.read_text(), text)
        # Later updates must not re-import a revoked original client.
        state['clients'] = []
        panel.atomic(panel.ROOT / 'state.json', json.dumps(state))
        panel.initialize()
        self.assertEqual(panel.load()['clients'], [])

    def test_public_https_with_generated_certificate(self):
        openssl = os.environ.get('OPENSSL_BINARY') or shutil.which('openssl')
        if not openssl:
            self.skipTest('OpenSSL is required for the TLS integration test')
        def generate(*args, data=None):
            self.assertEqual(args[0], 'openssl')
            return subprocess.run([openssl, *args[1:]], check=True, capture_output=True, text=True).stdout
        with patch.object(panel, 'run', side_effect=generate):
            https = panel.make_server(host='127.0.0.1', port=0)
        worker = threading.Thread(target=https.serve_forever, daemon=True)
        worker.start()
        try:
            plain = http.client.HTTPConnection('127.0.0.1', https.server_port, timeout=5)
            plain.request('GET', '/')
            redirected = plain.getresponse()
            self.assertEqual(redirected.status, 308)
            self.assertEqual(redirected.getheader('Location'), 'https://vpn.example.com:' + str(https.server_port) + '/')
            self.assertIsNone(redirected.getheader('WWW-Authenticate'))
            redirected.read()
            plain.close()
            context = ssl.create_default_context(cafile=str(panel.ROOT / 'tls.crt'))
            url = 'https://127.0.0.1:' + str(https.server_port) + '/api/status'
            request = Request(url, headers={'Authorization': 'Basic ' + base64.b64encode(b'admin:test-password').decode()})
            with urlopen(request, context=context, timeout=5) as r:
                self.assertEqual(r.status, 200)
                self.assertEqual(json.load(r)['host'], 'vpn.example.com')
            first_key = (panel.ROOT / 'tls.key').read_bytes()
        finally:
            https.shutdown()
            https.server_close()
            worker.join()
        with patch.object(panel, 'run', side_effect=AssertionError('Should reuse certificate')):
            reused = panel.make_server(host='127.0.0.1', port=0)
            reused.server_close()
        self.assertEqual((panel.ROOT / 'tls.key').read_bytes(), first_key)


if __name__ == '__main__':
    unittest.main()

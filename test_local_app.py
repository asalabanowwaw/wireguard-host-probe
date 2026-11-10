import base64
import copy
import json
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import local_app
import panel


def fixture():
    key = base64.b64encode(bytes([251]) * 32).decode()
    return dict(state=dict(host='192.0.2.1', port=51820, serverPublic=key, dns='1.1.1.1', mtu=1280),
                client=dict(name='test-device', address='10.203.240.3', private=key, psk=key,
                            tuning=dict(profile='custom', mtu=1360, keepalive=25, dns='9.9.9.9')))


class LocalTests(unittest.TestCase):
    def test_config_formats_round_trip_without_key_corruption(self):
        source = fixture()
        for text in [panel.client_config(source['state'], source['client']),
                     panel.share_uri(source['state'], source['client']),
                     json.dumps(panel.xray_config(source['state'], source['client']))]:
            result = local_app.parse_config(text)
            self.assertEqual(result['client']['private'], source['client']['private'])
            self.assertEqual(result['state']['serverPublic'], source['state']['serverPublic'])
            self.assertEqual(result['state']['host'], '192.0.2.1')
            self.assertEqual(result['client']['tuning']['mtu'], 1360)

    def test_bad_keys_and_endpoints_rejected(self):
        source = fixture()
        text = panel.client_config(source['state'], source['client'])
        for bad in [text.replace('PrivateKey = ' + source['client']['private'], 'PrivateKey = not-a-key'),
                    text.replace('192.0.2.1:51820', 'bad;command:51820'), text + '\n[Peer]\n',
                    text.replace('MTU = 1360', 'MTU = 9000')]:
            with self.assertRaises(ValueError):
                local_app.parse_config(bad)

    def test_low_mtu_config_import(self):
        source = fixture()
        source['client']['tuning']['mtu'] = 1200
        text = panel.client_config(source['state'], source['client'])
        self.assertEqual(local_app.parse_config(text)['client']['tuning']['mtu'], 1200)
        with self.assertRaises(ValueError):
            local_app.parse_config(text.replace('MTU = 1200', 'MTU = 575'))

    def test_best_requires_both_connectivity_requests_and_download(self):
        partial = dict(successes=1, medianMs=1, download=dict(ok=True, mbps=100))
        failed_download = dict(successes=2, medianMs=1, download=dict(ok=False, mbps=100))
        good = dict(successes=2, medianMs=200, download=dict(ok=True, mbps=2))
        faster = dict(successes=2, medianMs=210, download=dict(ok=True, mbps=3))
        self.assertIsNone(local_app.pick_best([partial, failed_download]))
        self.assertEqual(local_app.pick_best([partial, good, faster]), faster)

    def test_preset_export_contains_no_credentials(self):
        report = dict(best=dict(mtu=1360, dns='9.9.9.9'))
        with patch.multiple(local_app, IMPORTED=fixture(), REPORT=report):
            preset = local_app.export_data('preset')
            self.assertNotIn(fixture()['client']['private'], preset)
            self.assertEqual(json.loads(preset)['format'], 'wg-auto-tuning-v1')
            self.assertIn('MTU = 1360', local_app.export_data('config'))
        with patch.object(local_app, 'REPORT', dict(best=None)):
            with self.assertRaises(ValueError):
                local_app.export_data('config')

    def test_changed_keys_have_different_report_identity(self):
        imported = fixture()
        with patch.object(local_app, 'IMPORTED', imported):
            before = local_app.summary()
            imported['client']['private'] = base64.b64encode(bytes([250]) * 32).decode()
            after = local_app.summary()
        self.assertNotEqual(before['profileId'], after['profileId'])
        self.assertEqual(before['address'], after['address'])
        self.assertEqual(before['host'], after['host'])

    def test_baseline_is_not_claimed_as_imported_tunnel_success(self):
        with patch.object(local_app, 'IMPORTED', fixture()), patch.object(local_app, 'curl_probe', return_value=dict(ok=True, text='198.51.100.2')):
            report = local_app.preflight()
        self.assertFalse(report['proxyExitMatchesEndpoint'])
        self.assertIn('do not test the imported', report['note'])


class LocalHttpTests(unittest.TestCase):
    def setUp(self):
        self.state = patch.multiple(local_app, IMPORTED=fixture(), REPORT=dict(running=False, phase='Ready', trials=[], best=None, preflight=None), XRAY=None)
        self.state.start()
        self.server = local_app.ThreadingHTTPServer(('127.0.0.1', 0), local_app.Handler)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.base = 'http://127.0.0.1:' + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join()
        self.state.stop()

    def request(self, path, body=None, token=True, host=None):
        headers = {'X-Local-Token': local_app.TOKEN} if token else {}
        if host:
            headers['Host'] = host
        if body is not None:
            headers['Content-Type'] = 'application/json'
        try:
            return urlopen(Request(self.base + path, data=json.dumps(body).encode() if body is not None else None, headers=headers), timeout=3)
        except HTTPError as e:
            return e

    def test_root_and_api_protection_and_secret_free_reports(self):
        self.assertEqual(self.request('/', token=False).status, 200)
        self.assertEqual(self.request('/api/status', token=False).status, 403)
        self.assertEqual(self.request('/', host='untrusted.example').status, 403)
        status = self.request('/api/status').read().decode()
        self.assertNotIn(fixture()['client']['private'], status)
        self.assertIn('192.0.2.1', status)

    def test_full_scan_requires_core_and_isolation_confirmation(self):
        self.assertEqual(self.request('/api/scan', dict(mode='full', separateClientConfirmed=True)).status, 400)
        with patch.object(local_app, 'XRAY', local_app.Path(__file__)):
            self.assertEqual(self.request('/api/scan', dict(mode='full')).status, 400)

    def test_reimport_clears_previous_best(self):
        source = fixture()
        local_app.REPORT['best'] = dict(mtu=1360, dns='9.9.9.9')
        result = self.request('/api/import', dict(text=panel.client_config(source['state'], source['client'])))
        self.assertEqual(result.status, 200)
        self.assertIsNone(local_app.REPORT['best'])


if __name__ == '__main__':
    unittest.main()

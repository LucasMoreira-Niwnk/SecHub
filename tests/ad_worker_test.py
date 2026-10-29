import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ad_worker', Path(__file__).parents[1] / 'worker' / 'ad_collector.py')
ad = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ad)


class WorkerTests(unittest.TestCase):
    def test_malformed_json_reports_config_error_without_echoing_secret(self):
        class ConfigPath:
            @staticmethod
            def stat():
                return type('Info', (), {'st_uid': 0, 'st_mode': 0o640})()
            @staticmethod
            def read_text(**_):
                return '{"password": PRIVATE_VALUE_NOT_JSON}'
        with self.assertRaisesRegex(ValueError, '^CONFIG_INVALID$'):
            ad.configuration(ConfigPath(), '10.20.0.6')

    def test_transport_always_encrypts_and_validates_certificate(self):
        class WinRM:
            @staticmethod
            def Session(endpoint, **options):
                return endpoint, options
        with patch.dict('sys.modules', {'winrm': WinRM}):
            endpoint, options = ad.new_session({'endpoint': 'http://10.20.0.6:5985/wsman', 'username': 'corp\\svc', 'password': 'not-a-real-secret'})
        self.assertEqual(options['message_encryption'], 'always')
        self.assertEqual(options['server_cert_validation'], 'validate')
        self.assertEqual(options['transport'], 'ntlm')

    def test_query_is_fixed_and_response_bounded(self):
        class Session:
            def run_ps(self, script):
                self.script = script
                return type('Response', (), {'status_code': 0, 'std_out': json.dumps({'events': [], 'cursor': 120, 'backlog': False, 'warning': ''}).encode()})()
        session = Session()
        result = ad.query(session, 100, 'fixed __PARAMS__')
        self.assertEqual(result['cursor'], 120)
        self.assertNotIn('__PARAMS__', session.script)
        with self.assertRaises(ValueError):
            ad.query(session, "'; malicious", 'fixed')

    def test_invalid_and_denied_response_do_not_advance_cursor(self):
        class Session:
            def run_ps(self, _):
                return type('Response', (), {'status_code': 1, 'std_out': b'{"error":"ACCESS_DENIED"}'})()
        with self.assertRaisesRegex(ValueError, 'ACCESS_DENIED'):
            ad.query(Session(), 1, 'fixed')

    def test_atomic_cursor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cursor.json'
            ad.save_cursor(path, {'cursor': 30})
            self.assertEqual(json.loads(path.read_text())['cursor'], 30)
            self.assertFalse(path.with_suffix('.tmp').exists())


if __name__ == '__main__':
    unittest.main()

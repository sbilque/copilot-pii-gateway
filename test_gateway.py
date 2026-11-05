"""gateway.py with a real mitmproxy in child processes: startup refusals and no hot reload."""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import importlib.util
import unittest
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
CODE = ('gateway.py', 'copilot_pii.py', 'pii_core.py', 'pii_config.py', 'pii_detector.py', 'pii_worker.py')


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@unittest.skipUnless(importlib.util.find_spec('mitmproxy'), 'mitmproxy not installed')
class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        for name in CODE:
            shutil.copy(HERE / name, self.dir)
        self.policy = json.loads((HERE / 'policy.json').read_text())
        self.port = free_port()
        self.config = ['listen_host: 127.0.0.1', f'listen_port: {self.port}',
                       'mode:', '  - upstream:http://127.0.0.1:9', 'flow_detail: 0']

    def start(self, *args):
        (self.dir / 'config.yaml').write_text('\n'.join(self.config) + '\n')
        (self.dir / 'policy.json').write_text(json.dumps(self.policy))
        env = dict(os.environ, COPILOT_PII_CONFIG=str(self.dir / 'policy.json'))
        return subprocess.Popen([sys.executable, str(self.dir / 'gateway.py'), '--set', f'confdir={self.dir}', *args],
                                cwd=self.dir, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def refused(self, *args):
        proc = self.start(*args)
        try:
            output, _ = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.communicate()
            self.fail('gateway started instead of refusing')
        self.assertNotEqual(proc.returncode, 0)
        return output

    def health(self):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': f'http://127.0.0.1:{self.port}'}))
        try:
            with opener.open('http://pii-gate.invalid/health', timeout=5) as response:
                return json.load(response)
        except (urllib.error.URLError, ConnectionError, OSError):
            return None

    def running(self):
        proc = self.start()
        self.addCleanup(lambda: (proc.terminate(), proc.communicate(timeout=10)))
        deadline = time.monotonic() + 30
        while (status := self.health()) is None:
            self.assertIsNone(proc.poll(), 'gateway exited')
            self.assertLess(time.monotonic(), deadline, 'gateway not ready')
            time.sleep(0.2)
        return status

    def test_scripts_in_config_refused(self):
        self.config += ['scripts:', f'  - {self.dir / "copilot_pii.py"}']
        self.assertIn('scripts is not allowed', self.refused())

    def test_script_option_refused(self):
        self.assertIn('scripts is not allowed', self.refused('-s', str(self.dir / 'copilot_pii.py')))

    def test_invalid_policy_refused(self):
        self.policy['exact_hosts'] = 'x'
        self.assertIn('policy', self.refused())

    def test_missing_policy_refused(self):
        (self.dir / 'config.yaml').write_text('\n'.join(self.config) + '\n')
        env = dict(os.environ, COPILOT_PII_CONFIG=str(self.dir / 'absent.json'))
        proc = subprocess.run([sys.executable, str(self.dir / 'gateway.py'), '--set', f'confdir={self.dir}'],
                              cwd=self.dir, env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(proc.returncode, 0)

    def test_check_config_refuses_scripts(self):
        self.config += ['scripts:', '  - ./copilot_pii.py']
        (self.dir / 'config.yaml').write_text('\n'.join(self.config) + '\n')
        proc = subprocess.run([sys.executable, str(HERE / 'check_config.py'), str(self.dir / 'config.yaml')],
                              capture_output=True, text=True, timeout=30)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('scripts is not allowed', proc.stderr)

    def test_ready_and_no_hot_reload(self):
        self.assertTrue(self.running()['ready'])
        for name in ('copilot_pii.py', 'pii_core.py'):
            with open(self.dir / name, 'a') as source:
                source.write('\nthis is not python(\n')
        time.sleep(3)  # mitmproxy polls loaded scripts about once per second
        status = self.health()
        self.assertIsNotNone(status)
        self.assertTrue(status['ready'])


if __name__ == '__main__':
    unittest.main()

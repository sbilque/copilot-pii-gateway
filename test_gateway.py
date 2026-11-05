"""gateway.py with a real mitmproxy in child processes: startup refusals and no hot reload."""
import base64
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
CODE = ('gateway.py', 'check_proxy.py', 'watch_proxy.py', 'fake_worker.py', 'copilot_pii.py', 'pii_core.py', 'pii_config.py', 'pii_detector.py', 'pii_worker.py', 'pii_mapping.py')


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


needs_mitmproxy = unittest.skipUnless(importlib.util.find_spec('mitmproxy'), 'mitmproxy not installed')


class GatewayCase(unittest.TestCase):
    """Starts gateway.py from a private copy of the code, on a free loopback port."""
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        for name in CODE:
            shutil.copy(HERE / name, self.dir)
        self.policy = json.loads((HERE / 'policy.json').read_text())
        self.port = free_port()
        self.config = ['listen_host: 127.0.0.1', f'listen_port: {self.port}',
                       'mode:', '  - upstream:http://127.0.0.1:9', 'flow_detail: 0']

    def start(self, *args, **env):
        (self.dir / 'config.yaml').write_text('\n'.join(self.config) + '\n')
        (self.dir / 'policy.json').write_text(json.dumps(self.policy))
        env = {**os.environ, 'COPILOT_PII_CONFIG': str(self.dir / 'policy.json'),
               'COPILOT_PII_PROXY_AUTH': str(self.dir / 'proxy-auth'), **env}
        return subprocess.Popen([sys.executable, str(self.dir / 'gateway.py'), '--set', f'confdir={self.dir}', *args],
                                cwd=self.dir, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def refused(self, *args, **env):
        proc = self.start(*args, **env)
        try:
            output, _ = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.communicate()
            self.fail('gateway started instead of refusing')
        self.assertNotEqual(proc.returncode, 0)
        return output

    def health(self, credentials=None):
        """Canary status, the HTTP error code (int), or None if the port does not answer."""
        request = urllib.request.Request('http://pii-gate.invalid/health')
        if credentials:
            request.add_header('Proxy-Authorization', 'Basic ' + base64.b64encode(credentials.encode()).decode())
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': f'http://127.0.0.1:{self.port}'}))
        try:
            with opener.open(request, timeout=5) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            error.close()
            return error.code
        except (urllib.error.URLError, ConnectionError, OSError):
            return None

    def running(self, *args, credentials=None, **env):
        proc = self.start(*args, **env)
        self.addCleanup(self.stop, proc)
        deadline = time.monotonic() + 30
        while (status := self.health(credentials)) is None:
            self.assertIsNone(proc.poll(), 'gateway exited')
            self.assertLess(time.monotonic(), deadline, 'gateway not ready')
            time.sleep(0.2)
        self.proc = proc
        return status

    @staticmethod
    def stop(proc):
        if proc.poll() is None:
            proc.terminate()
        proc.communicate(timeout=10)


@needs_mitmproxy
class GatewayTests(GatewayCase):

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

    def test_listen_port_option_overrides_config(self):
        # make run passes --listen-port: --set would be overridden by config.yaml.
        configured, self.port = self.port, free_port()
        status = self.running('--listen-port', str(self.port))
        self.assertTrue(status['ready'])
        self.assertEqual(status['mapping']['aliases'], 0)
        self.assertNotEqual(configured, self.port)

    def test_ready_and_no_hot_reload(self):
        self.assertTrue(self.running()['ready'])
        for name in ('copilot_pii.py', 'pii_core.py'):
            with open(self.dir / name, 'a') as source:
                source.write('\nthis is not python(\n')
        time.sleep(3)  # mitmproxy polls loaded scripts about once per second
        status = self.health()
        self.assertIsNotNone(status)
        self.assertTrue(status['ready'])


SECRET = 'copilot:' + 'S' * 32


@needs_mitmproxy
class ProxyAuthTests(GatewayCase):
    def secret(self, content=SECRET, mode=0o600):
        path = self.dir / 'proxy-auth'
        path.write_text(content + '\n')
        path.chmod(mode)
        return path

    def test_without_secret_file_no_auth(self):
        self.assertTrue(self.running()['ready'])

    def test_secret_required_before_analysis(self):
        self.secret()
        self.assertTrue(self.running(credentials=SECRET)['ready'])
        self.assertEqual(self.health(), 407)
        self.assertEqual(self.health('copilot:' + 'X' * 32), 407)
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as conn:
            conn.sendall(b'CONNECT api.business.githubcopilot.com:443 HTTP/1.1\r\nHost: api.business.githubcopilot.com:443\r\n\r\n')
            self.assertIn(b' 407 ', conn.recv(200))

    def test_secret_not_on_command_line(self):
        self.secret()
        self.running(credentials=SECRET)
        if Path('/proc').is_dir():
            cmdline = Path(f'/proc/{self.proc.pid}/cmdline').read_bytes()
            self.assertNotIn(b'SSSS', cmdline)

    def test_canary_scripts_send_secret(self):
        self.secret()
        self.running(credentials=SECRET)
        env = dict(os.environ, CANARY_PROXY=f'http://127.0.0.1:{self.port}', COPILOT_PII_PROXY_AUTH=str(self.dir / 'proxy-auth'))
        ok = subprocess.run([sys.executable, 'check_proxy.py'], cwd=self.dir, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        env['COPILOT_PII_PROXY_AUTH'] = str(self.dir / 'absent')
        ko = subprocess.run([sys.executable, 'check_proxy.py'], cwd=self.dir, env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(ko.returncode, 0)
        self.assertIn('407', ko.stderr)

    @unittest.skipUnless(hasattr(os, 'getuid'), 'POSIX permissions')
    def test_readable_secret_refused(self):
        self.secret(mode=0o640)
        self.assertIn('mode 600', self.refused())

    def test_weak_or_special_secret_refused(self):
        for content in ('copilot:short', 'any', 'nopassword', '@htpasswd:' + 'x' * 20, 'copilot:with space' + 'x' * 16):
            self.secret(content)
            self.assertIn('user:password', self.refused(), content)

    def test_symlink_secret_refused(self):
        target = self.secret()
        link = self.dir / 'link-auth'
        link.symlink_to(target)
        self.assertIn('regular file', self.refused(COPILOT_PII_PROXY_AUTH=str(link)))

    def test_proxyauth_option_refused(self):
        self.assertIn('proxyauth is not allowed', self.refused('--set', 'proxyauth=any'))
        self.secret()
        self.assertIn('proxyauth is not allowed', self.refused('--proxyauth', 'other:' + 'y' * 20))
        self.config.append('proxyauth: any')
        self.assertIn('proxyauth is not allowed', self.refused())


@needs_mitmproxy
class SupervisionTests(GatewayCase):
    def watch(self, *args, timeout=30):
        env = dict(os.environ, CANARY_PROXY=f'http://127.0.0.1:{self.port}', COPILOT_PII_PROXY_AUTH=str(self.dir / 'absent'))
        return subprocess.run([sys.executable, 'watch_proxy.py', *args], cwd=self.dir, env=env,
                              capture_output=True, text=True, timeout=timeout)

    def test_once(self):
        self.assertEqual(self.watch('--once').returncode, 1)  # nothing listening
        self.running()
        self.assertEqual(self.watch('--once').returncode, 0)

    def test_failing_canary_stops_gateway(self):
        # Detector that never starts: the canary answers 503, the gateway refuses traffic.
        worker = self.dir / 'broken_python.sh'
        worker.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{self.dir / "fake_worker.py"}" initfail\n')
        worker.chmod(0o700)
        self.policy.update(presidio_language='en', presidio_model='fake', presidio_python=str(worker))
        pidfile = self.dir / 'gateway.pid'
        self.assertEqual(self.running(COPILOT_PII_PIDFILE=str(pidfile)), 503)
        self.assertEqual(pidfile.read_text().strip(), str(self.proc.pid))
        result = self.watch('--pidfile', str(pidfile), '--interval', '0.2', '--failures', '2')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('stopped', result.stderr)
        self.proc.wait(timeout=15)
        self.assertFalse(pidfile.exists(), 'pid file left behind')

    def test_ready_gateway_not_stopped(self):
        pidfile = self.dir / 'gateway.pid'
        self.running(COPILOT_PII_PIDFILE=str(pidfile))
        with self.assertRaises(subprocess.TimeoutExpired):
            self.watch('--pidfile', str(pidfile), '--interval', '0.2', '--failures', '1', timeout=2)
        self.assertIsNone(self.proc.poll())

    def test_stop_refuses_bad_pidfiles(self):
        sys.path.insert(0, str(self.dir))
        self.addCleanup(sys.path.remove, str(self.dir))
        import watch_proxy
        for content in ('', 'abc', '1', '0'):
            path = self.dir / 'bad.pid'
            path.write_text(content)
            self.assertFalse(watch_proxy.stop(path), content)


if __name__ == '__main__':
    unittest.main()

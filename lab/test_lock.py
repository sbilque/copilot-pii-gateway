"""Network lock check (milestone 7): network-lock/linux.nft applied in a real network namespace.

Runs as root in the lab `lock` container (NET_ADMIN only, own namespace). A gateway runs as
the `gateway` user; the client user `lab` and root must not reach the corporate proxy
directly, but a request through the gateway must still succeed. Synthetic data only.
Without nftables support in the kernel the test fails, unless LAB_LOCK_OPTIONAL=1 (skip).
"""
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import time
import unittest

RULES = '/app/network-lock/linux.nft'
PROXY_PORT = 3128
CLIENT, GATEWAY = 10001, 10002
OK, REFUSED, TIMEOUT = 0, 3, 4

CONNECT = '''
import socket, sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5).close()
except ConnectionRefusedError:
    sys.exit(3)
except (socket.timeout, TimeoutError):
    sys.exit(4)
'''
THROUGH_GATEWAY = '''
import sys
sys.path.insert(0, '/app/lab')
from test_lab import post
_, status, _, data = post(sys.argv[1], {'messages': [{'role': 'user', 'content': 'neutral lock check'}]})
print(status)
sys.exit(0 if status == 200 else 1)
'''


def identity(uid):
    """user, group and no supplementary groups, so children never keep root's groups."""
    return {'user': uid, 'group': pwd.getpwuid(uid).pw_gid, 'extra_groups': []}


def as_user(uid, *args):
    return subprocess.run([sys.executable, *args], **identity(uid),
                          capture_output=True, text=True, timeout=60, cwd='/tmp',
                          env={'PATH': os.environ['PATH'], 'HOME': '/tmp'})


def connect(uid, host, port=PROXY_PORT):
    return as_user(uid, '-c', CONNECT, host, str(port)).returncode


def nft(*args):
    return subprocess.run(['nft', *args], capture_output=True, text=True)


class NetworkLock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        probe = nft('list', 'ruleset')
        if probe.returncode != 0:
            message = 'nftables unavailable: ' + probe.stderr.strip()
            if os.environ.get('LAB_LOCK_OPTIONAL') == '1':
                raise unittest.SkipTest(message)
            raise RuntimeError(message)
        cls.proxy = socket.gethostbyname('corp-proxy')
        if connect(CLIENT, cls.proxy) != OK:
            raise RuntimeError('control failed: client cannot reach the proxy before the lock')
        rules = open(RULES).read()
        for name, value in (('PROXY', cls.proxy), ('PROXY_PORT', PROXY_PORT), ('GATEWAY_UID', GATEWAY)):
            rules, count = re.subn(rf'^define {name} = .*$', f'define {name} = {value}', rules, flags=re.M)
            assert count == 1, name
        with open('/tmp/lock.nft', 'w') as handle:
            handle.write(rules)
        loaded = nft('-f', '/tmp/lock.nft')
        if loaded.returncode != 0:
            raise RuntimeError('nft -f failed: ' + loaded.stderr)
        pki = '/tmp/gateway-pki'
        os.makedirs(pki, mode=0o700)
        shutil.copy('/pki/mitmproxy-ca.pem', pki)
        for path in (pki, pki + '/mitmproxy-ca.pem'):
            os.chown(path, GATEWAY, pwd.getpwuid(GATEWAY).pw_gid)
        os.chmod(pki + '/mitmproxy-ca.pem', 0o600)
        cls.gateway = subprocess.Popen(['/app/lab/gateway.sh'], **identity(GATEWAY), cwd='/tmp',
                                       env={'PATH': os.environ['PATH'], 'HOME': '/tmp',
                                            'LAB_PKI': pki, 'LAB_MODE': 'block'})
        deadline = time.monotonic() + 60
        while as_user(CLIENT, '/app/check_proxy.py').returncode != 0:
            if cls.gateway.poll() is not None or time.monotonic() > deadline:
                cls.tearDownClass()
                raise RuntimeError('gateway not ready behind the lock')
            time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        gateway = getattr(cls, 'gateway', None)
        if gateway and gateway.poll() is None:
            gateway.terminate()
            gateway.wait(10)
        nft('delete', 'table', 'inet', 'copilot_pii_lock')

    def test_client_user_cannot_reach_proxy_directly(self):
        self.assertEqual(connect(CLIENT, self.proxy), REFUSED)

    def test_root_cannot_reach_proxy_directly(self):
        self.assertEqual(connect(0, self.proxy), REFUSED)

    def test_gateway_user_reaches_proxy(self):
        self.assertEqual(connect(GATEWAY, self.proxy), OK)

    def test_request_through_gateway_succeeds(self):
        result = as_user(CLIENT, '-c', THROUGH_GATEWAY, 'http://127.0.0.1:8080')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_direct_request_through_proxy_fails(self):
        result = as_user(CLIENT, '-c', THROUGH_GATEWAY, f'http://{self.proxy}:{PROXY_PORT}')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('refused', result.stderr.lower())

    def test_rule_counted_rejections(self):
        listing = nft('list', 'table', 'inet', 'copilot_pii_lock').stdout
        packets = re.search(r'counter packets (\d+)', listing)
        self.assertIsNotNone(packets, listing)
        self.assertGreater(int(packets.group(1)), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)

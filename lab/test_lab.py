"""Lab integration tests: real mitmproxy, real Squid, fake Copilot upstream.

Run inside the lab `tests` container (make lab-test). Each test checks what the upstream
actually received, not only the HTTP status. Synthetic data only.
"""
import base64
import json
import os
import re
import socket
import ssl
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path

UPSTREAM = 'https://api.business.githubcopilot.com/chat/completions'
GATEWAY_BLOCK = os.environ.get('LAB_GATEWAY_BLOCK', 'http://gateway-block:8080')
GATEWAY_REDACT = os.environ.get('LAB_GATEWAY_REDACT', 'http://gateway-redact:8080')
MITM_CA = os.environ.get('LAB_MITM_CA', '/pki/mitmproxy-ca-cert.pem')
RECORDINGS = Path(os.environ.get('LAB_RECORDINGS', '/recordings'))
TOKEN = re.compile(r'__PII_[0-9a-f]{12}_[0-9]{6}__')

EMAIL = 'alice.martin@example.test'
HOST = 'db01.corp'
IP = '10.20.30.40'


def post(gateway, payload, scenario='echo'):
    """POST through a gateway; returns (lab id, status, sent bytes, response bytes)."""
    lab_id = uuid.uuid4().hex
    body = json.dumps(payload).encode()
    context = ssl.create_default_context(cafile=MITM_CA)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({'https': gateway}),
                                         urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(UPSTREAM, data=body, method='POST', headers={
        'content-type': 'application/json', 'x-lab-id': lab_id, 'x-lab-scenario': scenario})
    try:
        with opener.open(request, timeout=20) as response:
            return lab_id, response.status, body, response.read()
    except urllib.error.HTTPError as error:
        return lab_id, error.code, body, error.read()


def recorded(lab_id, wait=1.0):
    path = RECORDINGS / (lab_id + '.json')
    deadline = time.monotonic() + wait
    while not path.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    if not path.exists():
        return None
    return base64.b64decode(json.loads(path.read_text())['body_b64'])


def chat(*contents):
    return {'model': 'lab-model', 'stream': False,
            'messages': [{'role': 'user', 'content': c} for c in contents]}


class Nominal(unittest.TestCase):
    def test_n1_neutral_prompt_bytes_unchanged(self):
        lab_id, status, sent, reply = post(GATEWAY_BLOCK, chat('Explique la difference entre une liste et un tuple.'))
        self.assertEqual(status, 200, reply)
        self.assertEqual(recorded(lab_id), sent)
        self.assertEqual(json.loads(reply)['choices'][0]['message']['content'],
                         'Explique la difference entre une liste et un tuple.')

    def test_n2_block_mode_refuses_before_upstream(self):
        lab_id, status, _, reply = post(GATEWAY_BLOCK, chat('Ecris a ' + EMAIL))
        self.assertEqual(status, 403, reply)
        self.assertIn(b'Local PII policy refused', reply)
        self.assertIsNone(recorded(lab_id, wait=1.5), 'blocked body reached the upstream')

    def test_n3_redact_mode_pseudonymises_and_restores(self):
        prompt = 'Le serveur %s (%s) envoie ses alertes a %s.' % (HOST, IP, EMAIL)
        lab_id, status, _, reply = post(GATEWAY_REDACT, chat(prompt, 'Rappel : ' + EMAIL))
        self.assertEqual(status, 200, reply)
        upstream = recorded(lab_id)
        self.assertIsNotNone(upstream)
        for value in (EMAIL, HOST, IP):
            self.assertNotIn(value.encode(), upstream)
        aliases = TOKEN.findall(upstream.decode())
        self.assertEqual(len(set(aliases)), 3, upstream)
        self.assertEqual(len(aliases), 4, 'the repeated email must reuse its alias')
        content = json.loads(reply)['choices'][0]['message']['content']
        self.assertEqual(content, prompt + ' | Rappel : ' + EMAIL)
        self.assertIsNone(TOKEN.search(content))


class Isolation(unittest.TestCase):
    """The client network only reaches the gateways: no bypass path in the lab."""

    def assert_unreachable(self, host, port):
        try:
            socket.create_connection((host, port), timeout=3).close()
        except OSError:
            return
        self.fail('%s:%d reachable from the client network' % (host, port))

    def test_corporate_proxy_not_reachable_from_client(self):
        self.assert_unreachable('corp-proxy', 3128)

    def test_upstream_not_reachable_from_client(self):
        self.assert_unreachable('api.business.githubcopilot.com', 443)


if __name__ == '__main__':
    unittest.main(verbosity=2)

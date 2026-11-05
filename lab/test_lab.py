"""Lab integration tests: real mitmproxy, real Squid, fake Copilot upstream.

Run inside the lab `tests` container (make lab-test). Each test checks what the upstream
actually received, not only the HTTP status. Synthetic data only.
"""
import base64
import gzip
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
UPSTREAM_DOWN = 'https://down.business.githubcopilot.com/chat/completions'
GATEWAY_BLOCK = os.environ.get('LAB_GATEWAY_BLOCK', 'http://gateway-block:8080')
GATEWAY_REDACT = os.environ.get('LAB_GATEWAY_REDACT', 'http://gateway-redact:8080')
GATEWAY_FRESH = os.environ.get('LAB_GATEWAY_FRESH', 'http://gateway-fresh:8080')
GATEWAY_NOPROXY = os.environ.get('LAB_GATEWAY_NOPROXY', 'http://gateway-noproxy:8080')
GATEWAY_PRESIDIO = os.environ.get('LAB_GATEWAY_PRESIDIO', 'http://gateway-presidio:8080')
GATEWAY_HOT = os.environ.get('LAB_GATEWAY_HOT', 'http://gateway-hot:8080')
HOT_DIR = Path(os.environ.get('LAB_HOT_DIR', '/hot'))
MITM_CA = os.environ.get('LAB_MITM_CA', '/pki/mitmproxy-ca-cert.pem')
RECORDINGS = Path(os.environ.get('LAB_RECORDINGS', '/recordings'))
TOKEN = re.compile(r'__PII_[0-9a-f]{12}_[0-9]{6}__')

EMAIL = 'alice.martin@example.test'
HOST = 'db01.corp'
IP = '10.20.30.40'
PROJECT = 'Projet "Alpha\\Beta"'  # literal of gateway-redact, with a quote and a backslash
SECRET = 'ghp_' + 'L' * 36  # synthetic, matches the policy SECRET pattern


def opener(gateway):
    context = ssl.create_default_context(cafile=MITM_CA)
    return urllib.request.build_opener(urllib.request.ProxyHandler({'https': gateway, 'http': gateway}),
                                       urllib.request.HTTPSHandler(context=context))


def post(gateway, payload, scenario='echo', url=UPSTREAM, raw=None, headers=None):
    """POST through a gateway; returns (lab id, status, sent bytes, response bytes)."""
    lab_id = uuid.uuid4().hex
    body = raw if raw is not None else json.dumps(payload).encode()
    request = urllib.request.Request(url, data=body, method='POST', headers={
        'content-type': 'application/json', 'x-lab-id': lab_id, 'x-lab-scenario': scenario, **(headers or {})})
    try:
        with opener(gateway).open(request, timeout=30) as response:
            data = response.read()
            if response.headers.get('content-encoding') == 'gzip':
                data = gzip.decompress(data)
            return lab_id, response.status, body, data
    except urllib.error.HTTPError as error:
        return lab_id, error.code, body, error.read()


def health(gateway, headers=None):
    request = urllib.request.Request('http://pii-gate.invalid/health', headers=headers or {})
    try:
        with opener(gateway).open(request, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except urllib.error.URLError:
        return None


def events(data):
    """Parsed JSON payloads of an SSE body."""
    out = []
    for block in data.decode().split('\n\n'):
        payload = '\n'.join(l[5:].lstrip() for l in block.splitlines() if l.startswith('data:'))
        if payload and payload != '[DONE]':
            out.append(json.loads(payload))
    return out


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


SENSITIVE = 'Mail %s, hote %s, %s.' % (EMAIL, HOST, PROJECT)
EXPECTED_TEXT = 'Contact : %s / %s / %s' % (EMAIL, HOST, PROJECT)
EXPECTED_ARGS = [{'email': EMAIL}, {'host': HOST}, {'projet': PROJECT}]


class Streaming(unittest.TestCase):
    """N4: SSE restoration, aliases split across events and parallel tool calls."""

    def stream(self, scenario):
        lab_id, status, _, reply = post(GATEWAY_REDACT, chat(SENSITIVE), scenario)
        self.assertEqual(status, 200, reply)
        upstream = recorded(lab_id)
        for value in (EMAIL, HOST, 'Alpha'):
            self.assertNotIn(value.encode(), upstream)
        self.assertIsNone(TOKEN.search(reply.decode()), 'alias leaked to the client')
        return events(reply)

    def check(self, text, arguments):
        self.assertEqual(text, EXPECTED_TEXT)
        self.assertEqual([json.loads(a) for a in arguments], EXPECTED_ARGS)

    def test_n4_chat_completions(self):
        text, args = '', {}
        for event in self.stream('sse-chat'):
            delta = event['choices'][0]['delta']
            text += delta.get('content') or ''
            for call in delta.get('tool_calls', []):
                args[call['index']] = args.get(call['index'], '') + call['function'].get('arguments', '')
        self.check(text, [args[i] for i in sorted(args)])

    def test_n4_responses(self):
        text, args = '', {}
        for event in self.stream('sse-responses'):
            if event['type'] == 'response.output_text.delta':
                text += event['delta']
            elif event['type'] == 'response.function_call_arguments.delta':
                args[event['item_id']] = args.get(event['item_id'], '') + event['delta']
        self.check(text, [args[k] for k in sorted(args)])

    def test_n4_anthropic(self):
        blocks = {}
        for event in self.stream('sse-anthropic'):
            if event['type'] == 'content_block_delta':
                delta = event['delta']
                blocks[event['index']] = blocks.get(event['index'], '') + delta.get('text', delta.get('partial_json', ''))
        self.check(blocks[0], [blocks[i] for i in sorted(blocks) if i])


class Policy(unittest.TestCase):
    def test_n5_secret_in_tool_name_refused_in_both_modes(self):
        payload = chat('Liste les jobs.')
        payload['tools'] = [{'type': 'function', 'function': {'name': SECRET, 'parameters': {'type': 'object'}}}]
        for gateway in (GATEWAY_BLOCK, GATEWAY_REDACT):
            lab_id, status, _, reply = post(gateway, payload)
            self.assertEqual(status, 403, (gateway, reply))
            self.assertIsNone(recorded(lab_id, wait=1.0))

    def test_n6_oversized_body_refused(self):
        filler = 'x' * (4 * 1024 * 1024 + 1)
        lab_id, status, _, _ = post(GATEWAY_BLOCK, chat(filler))
        self.assertEqual(status, 413)
        self.assertIsNone(recorded(lab_id, wait=1.0))

    def test_n7_canary_refused_from_client_network(self):
        # The healthcheck runs check_proxy.py on loopback: healthy means ready=true.
        self.assertEqual(health(GATEWAY_BLOCK), 403)
        self.assertEqual(health(GATEWAY_BLOCK, {'origin': 'https://evil.example'}), 403)


class Faults(unittest.TestCase):
    def test_f1_upstream_unreachable(self):
        lab_id, status, _, _ = post(GATEWAY_BLOCK, chat('Bonjour'), url=UPSTREAM_DOWN)
        self.assertEqual(status, 502)
        self.assertIsNone(recorded(lab_id, wait=0.5))

    def test_f2_corporate_proxy_down_no_direct_fallback(self):
        lab_id, status, _, _ = post(GATEWAY_NOPROXY, chat('Bonjour'))
        self.assertEqual(status, 502)
        self.assertIsNone(recorded(lab_id, wait=1.0), 'request bypassed the corporate proxy')

    def test_f5_detector_timeout_crash_and_recovery(self):
        def ask(text):
            lab_id, status, _, _ = post(GATEWAY_PRESIDIO, chat(text))
            return status, recorded(lab_id, wait=0.5)

        self.assertEqual(ask('Bonjour')[0], 200)
        status, upstream = ask('Bonjour Bob')  # PERSON for the fake detector, block mode
        self.assertEqual((status, upstream), (403, None))
        status, upstream = ask('SLEEP')
        self.assertEqual((status, upstream), (503, None))
        deadline = time.monotonic() + 20
        while ask('Bonjour')[0] != 200:
            self.assertLess(time.monotonic(), deadline, 'detector did not restart')
            time.sleep(0.5)
        status, upstream = ask('CRASH')
        self.assertEqual((status, upstream), (503, None))

    def test_f6_unknown_alias_refused(self):
        _, status, _, reply = post(GATEWAY_REDACT, chat('Ecris a ' + EMAIL), 'unknown-alias')
        self.assertEqual(status, 502, reply)
        self.assertNotIn(b'__PII_', reply)

    def test_f7_gzip_response_restored(self):
        _, status, _, reply = post(GATEWAY_REDACT, chat('Ecris a ' + EMAIL), 'gzip-echo')
        self.assertIn(status, (200, 502), reply)
        self.assertNotIn(b'__PII_', reply)
        if status == 200:
            self.assertEqual(json.loads(reply)['choices'][0]['message']['content'], 'Ecris a ' + EMAIL)


class Mapping(unittest.TestCase):
    """C1: gateway-fresh never sees sensitive data, so its mapping stays empty."""

    def test_c1_alias_from_another_instance_refused(self):
        lab_id, status, _, _ = post(GATEWAY_REDACT, chat('Ecris a ' + EMAIL))
        self.assertEqual(status, 200)
        alias = TOKEN.search(recorded(lab_id).decode()).group()
        lab_id, status, _, reply = post(GATEWAY_FRESH, chat('Rappel ' + alias))
        self.assertIn(alias.encode(), recorded(lab_id))  # an alias is not sensitive by itself
        self.assertEqual(status, 502, reply)
        self.assertNotIn(b'__PII_', reply)

    def test_c1_unknown_alias_on_empty_mapping_refused(self):
        _, status, _, reply = post(GATEWAY_FRESH, chat('Bonjour'), 'unknown-alias')
        self.assertEqual(status, 502, reply)
        self.assertNotIn(b'__PII_', reply)

    def test_c1_neutral_reply_on_empty_mapping_passes(self):
        _, status, _, reply = post(GATEWAY_FRESH, chat('Bonjour'))
        self.assertEqual(status, 200, reply)
        self.assertEqual(json.loads(reply)['choices'][0]['message']['content'], 'Bonjour')


class HotReload(unittest.TestCase):
    """F3: a script broken while mitmproxy runs. Runs last; leaves gateway-hot broken."""

    def test_f3a_filter_active_before_break(self):
        lab_id, status, _, _ = post(GATEWAY_HOT, chat('Ecris a ' + EMAIL))
        self.assertEqual((status, recorded(lab_id, wait=1.0)), (403, None))

    @unittest.expectedFailure  # Known gap, fixed by the launcher of milestone 4.
    def test_f3b_filter_still_active_after_runtime_break(self):
        with open(HOT_DIR / 'copilot_pii.py', 'a') as script:
            script.write('\nthis is not python(\n')
        deadline = time.monotonic() + 15
        while health(GATEWAY_HOT) == 403 and time.monotonic() < deadline:
            time.sleep(0.5)  # 403 while the addon answers the canary
        lab_id, status, _, _ = post(GATEWAY_HOT, chat('Ecris a ' + EMAIL))
        self.assertIsNone(recorded(lab_id, wait=1.0), 'sensitive body reached the upstream in clear')


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


def load_tests(loader, tests, pattern):
    """HotReload last: it breaks gateway-hot on purpose."""
    suite = unittest.TestSuite()
    for case in (Isolation, Nominal, Policy, Streaming, Faults, Mapping, HotReload):
        suite.addTests(loader.loadTestsFromTestCase(case))
    return suite


if __name__ == '__main__':
    unittest.main(verbosity=2)

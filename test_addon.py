import asyncio
import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from test_core import guard, request
import pii_detector  # noqa: F401  imported before the patch so sys.modules keeps one copy


class Response:
    @staticmethod
    def make(status, content, headers):
        return types.SimpleNamespace(status_code=status, content=content, headers=headers, stream=False)


fake = types.ModuleType('mitmproxy')
fake.http = types.SimpleNamespace(Response=Response)
with patch.dict(sys.modules, {'mitmproxy': fake}):
    spec = importlib.util.spec_from_file_location('addon_under_test', Path(__file__).with_name('copilot_pii.py'))
    addon = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(addon)


def run(coroutine):
    return asyncio.run(coroutine)


def flow(body=b'', host='api.enterprise.githubcopilot.com', scheme='https', method='POST'):
    req = types.SimpleNamespace(host=host, scheme=scheme, method=method, query={},
        headers={'content-type': 'application/json'}, raw_content=body, content=body, stream=False)
    return types.SimpleNamespace(request=req, response=None, metadata={},
        client_conn=types.SimpleNamespace(peername=('127.0.0.1', 1)))


class AddonTests(unittest.TestCase):
    def setUp(self):
        self.addon = addon.CopilotPII()
        self.addon.guard = guard()

    def test_request_redacted(self):
        f = flow(request('a@example.test'))
        run(self.addon.request(f))
        self.assertIsNone(f.response)
        self.assertNotIn(b'a@example.test', f.request.content)

    def test_routes_blocked(self):
        for host, scheme in [('api.individual.githubcopilot.com', 'https'), ('api.enterprise.githubcopilot.com', 'http')]:
            f = flow(request('hello'), host, scheme)
            run(self.addon.request(f))
            self.assertEqual(f.response.status_code, 403)

    def test_bad_body_blocked(self):
        f = flow(b'not json')
        run(self.addon.request(f))
        self.assertEqual(f.response.status_code, 403)

    def test_declared_size(self):
        f = flow(); f.request.headers['content-length'] = '999999999'
        self.addon.requestheaders(f)
        self.assertEqual(f.response.status_code, 413)

    def test_response_roundtrip(self):
        f = flow(request('a@example.test'))
        run(self.addon.request(f))
        token = next(iter(self.addon.guard.reverse))
        f.response = Response.make(200, json.dumps({'text': token}).encode(), {'content-type': 'application/json'})
        self.addon.responseheaders(f); self.addon.response(f)
        self.assertFalse(f.response.stream)
        self.assertEqual(json.loads(f.response.content)['text'], 'a@example.test')

    def test_unknown_response_alias_blocked(self):
        self.addon.guard.request(request('a@example.test'))
        f = flow(); f.response = Response.make(200, b'{"text":"__PII_aaaaaaaaaaaa_999999__"}', {'content-type': 'application/json'})
        self.addon.response(f)
        self.assertEqual(f.response.status_code, 502)

    def test_selftest(self):
        f = flow(host='pii-gate.invalid', scheme='http', method='GET')
        run(self.addon.request(f))
        self.assertEqual(f.response.status_code, 200)
        self.assertTrue(json.loads(f.response.content)['ready'])

    def test_browser_selftest_rejected(self):
        f = flow(host='pii-gate.invalid'); f.request.headers['origin'] = 'https://example.test'
        run(self.addon.request(f))
        self.assertEqual(f.response.status_code, 403)


if __name__ == '__main__':
    unittest.main()

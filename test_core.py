import json
import random
import unittest
from pathlib import Path
from pii_core import Guard, PolicyError, loads


def guard(mode='redact', **options):
    config = json.loads(Path(__file__).with_name('policy.json').read_text())
    config.update(mode=mode, **options)
    return Guard(config)


def request(text, **extra):
    return json.dumps({'messages': [{'role': 'user', 'content': text}], **extra}).encode()


class CoreTests(unittest.TestCase):
    def test_redaction_and_roundtrip(self):
        g = guard()
        original = 'a@example.test srv01.corp 10.0.0.8 CLIENT_DEMO_CONFIDENTIEL'
        out = g.request(request(original))
        for value in original.split():
            self.assertNotIn(value.encode(), out)
        self.assertEqual(g.restore(loads(out))['messages'][0]['content'], original)

    def test_block_mode(self):
        with self.assertRaises(PolicyError): guard('block').request(request('a@example.test'))

    def test_secrets_blocked(self):
        for text in ('ghp_' + 'x' * 30, '-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----'):
            with self.subTest(text=text), self.assertRaises(PolicyError): guard().request(request(text))

    def test_unchanged_bytes_preserved(self):
        body = b'{ "messages" : [ { "role": "user", "content": "hello" } ] }'
        self.assertEqual(guard().request(body), body)

    def test_stable_aliases(self):
        g = guard()
        self.assertEqual(g.request(request('a@example.test')), g.request(request('a@example.test')))

    def test_propagation(self):
        g = guard()
        g.detector = lambda t: [(0, 3, 'PERSON')] if t == 'Bob' else []
        g.request(request('Bob'))
        g.detector = None
        out = loads(g.request(request('Bob and Bobcat')))['messages'][0]['content']
        self.assertNotIn('Bob and', out)
        self.assertIn('Bobcat', out)

    def test_cache(self):
        g, calls = guard(cache_size=2), []
        g.detector = lambda t: calls.append(t) or []
        g.request(request('hello')); g.request(request('hello'))
        self.assertEqual(calls.count('hello'), 1)
        self.assertLessEqual(len(g.cache), 2)
        self.assertTrue(all(isinstance(k, bytes) for k in g.cache))

    def test_invalid_detector(self):
        g = guard(); g.detector = lambda t: [(5, 2, 'X')]
        with self.assertRaises(PolicyError): g.request(request('hello'))

    def test_structural_detection_blocks(self):
        for key in ('model', 'stop', 'previous_response_id'):
            with self.subTest(key=key), self.assertRaises(PolicyError):
                guard().request(request('hello', **{key: 'a@example.test'}))

    def test_tool_names_preserved(self):
        body = {'messages': [{'role': 'assistant', 'tool_calls': [{'type': 'function', 'function': {
            'name': 'lookup.corp', 'arguments': '{"email":"a@example.test"}'}}]}]}
        out = loads(guard().request(json.dumps(body).encode()))
        function = out['messages'][0]['tool_calls'][0]['function']
        self.assertEqual(function['name'], 'lookup.corp')
        self.assertNotIn('a@example.test', function['arguments'])

    def test_tool_schema_not_rewritten(self):
        with self.assertRaises(PolicyError):
            guard().request(request('hello', tools=[{'description': 'a@example.test'}]))

    def test_unknown_fields_scanned(self):
        out = guard().request(request('hello', metadata={'owner': 'a@example.test'}))
        self.assertNotIn(b'a@example.test', out)

    def test_multimodal_and_signed_rejected(self):
        for kind in ('image', 'thinking', 'redacted_thinking'):
            with self.subTest(kind=kind), self.assertRaises(PolicyError):
                guard().request(request([{'type': kind, 'text': 'x'}]))

    def test_encoded_content_rejected(self):
        with self.assertRaises(PolicyError): guard().request(request('data:text/plain;base64,' + 'a' * 300))

    def test_invalid_json_rejected(self):
        for body in (b'{"messages":[],"messages":[]}', b'{"messages":NaN}', b'{}'):
            with self.subTest(body=body), self.assertRaises(ValueError): guard().request(body)

    def test_limits(self):
        with self.assertRaises(PolicyError): guard(max_body_bytes=2).request(request('hello'))
        with self.assertRaises(PolicyError): guard(max_aliases=1).request(request('a@example.test b@example.test'))
        with self.assertRaises(PolicyError): guard(max_depth=1).request(request('hello'))

    def test_public_ip_unchanged(self):
        body = request('8.8.8.8')
        self.assertEqual(guard().request(body), body)

    def test_unknown_alias_rejected(self):
        with self.assertRaises(PolicyError): guard().text('__PII_aaaaaaaaaaaa_000001__')
        with self.assertRaises(PolicyError): guard().text('__PII_broken')

    def test_nested_arguments_escaping(self):
        g = guard()
        token = '__PII_aaaaaaaaaaaa_000001__'
        value = 'host"with\\slashes\nand newline'
        g.reverse[token] = value
        out = g.restore({'arguments': json.dumps({'host': token})})
        self.assertEqual(json.loads(out['arguments']), {'host': value})

    def test_sse_fragmented_alias_and_parallel_items(self):
        g = guard()
        g.request(request('a@example.test b@example.test'))
        aliases = {v: k for k, v in g.reverse.items()}
        a, b = aliases['a@example.test'], aliases['b@example.test']
        events = [
            {'type': 'response.output_text.delta', 'item_id': 'a', 'delta': a[:10]},
            {'type': 'response.output_text.delta', 'item_id': 'b', 'delta': b[:7]},
            {'type': 'response.output_text.delta', 'item_id': 'a', 'delta': a[10:]},
            {'type': 'response.output_text.delta', 'item_id': 'b', 'delta': b[7:]},
        ]
        body = b''.join(('data: ' + json.dumps(e) + '\n\n').encode() for e in events) + b'data: [DONE]\n\n'
        out = g.response(body, 'text/event-stream').decode()
        values = {}
        for line in out.splitlines():
            if line.startswith('data: ') and line[6:] != '[DONE]':
                event = json.loads(line[6:]); values[event['item_id']] = values.get(event['item_id'], '') + event['delta']
        self.assertEqual(values, {'a': 'a@example.test', 'b': 'b@example.test'})

    def test_sse_tool_arguments(self):
        g = guard(); token = '__PII_aaaaaaaaaaaa_000001__'; value = 'a"b\\c'
        g.reverse[token] = value
        args = json.dumps({'host': token})
        events = [{'choices': [{'index': 0, 'delta': {'tool_calls': [{'index': 0, 'function': {'arguments': part}}]}}]} for part in (args[:15], args[15:])]
        body = b''.join(('data: ' + json.dumps(e) + '\n\n').encode() for e in events)
        out = g.response(body, 'text/event-stream').decode()
        args = ''.join(json.loads(l[6:])['choices'][0]['delta']['tool_calls'][0]['function']['arguments'] for l in out.splitlines() if l.startswith('data: '))
        self.assertEqual(json.loads(args), {'host': value})

    def test_unicode_and_surrogate(self):
        body = request('Bonjour, ete \ud800')
        self.assertEqual(guard().request(body), body)

    def test_response_limits_and_types(self):
        with self.assertRaises(PolicyError): guard(max_response_bytes=1).response(b'{}', 'application/json')
        with self.assertRaises(PolicyError): guard().response(b'hello', 'text/plain')


if __name__ == '__main__':
    unittest.main()

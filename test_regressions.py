"""Synthetic regressions; no real Copilot, mitmproxy or Presidio integration."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from pii_config import ConfigurationError, validate_config
from pii_core import Guard, PolicyError, SensitiveDataError, dumps, loads
from test_core import guard, request
from test_addon import addon, flow, run


class ConfigurationTests(unittest.TestCase):
    def config(self, **options):
        config = json.loads(Path(__file__).with_name('policy.json').read_text())
        config.update(options)
        return config

    def test_invalid_policy_types(self):
        for value in (None, [], 'policy', 1):
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                Guard(value)

    def test_invalid_limits(self):
        for key in ('max_body_bytes', 'max_response_bytes', 'max_aliases', 'max_depth', 'cache_size'):
            for value in (-1, True, 1.5, '2', None):
                with self.subTest(key=key, value=value), self.assertRaises(ConfigurationError):
                    Guard(self.config(**{key: value}))
        for key in ('max_body_bytes', 'max_response_bytes', 'max_aliases', 'max_depth'):
            with self.subTest(key=key), self.assertRaises(ConfigurationError):
                Guard(self.config(**{key: 0}))
        with self.assertRaises(ConfigurationError):
            Guard(self.config(max_aliases=1000000))
        self.assertEqual(Guard(self.config(cache_size=0)).config['cache_size'], 0)

    def test_host_lists_required(self):
        for key in ('exact_hosts', 'host_suffixes'):
            config = self.config()
            del config[key]
            with self.subTest(key=key), self.assertRaises(ConfigurationError):
                Guard(config)
        with self.assertRaises(ConfigurationError):
            Guard(self.config(exact_hosts=[], host_suffixes=[]))

    def test_invalid_hosts(self):
        for key in ('exact_hosts', 'host_suffixes'):
            for value in ('example.test', None, [1], [''], ['*.example.test'],
                          ['https://example.test'], ['example.test:443'], ['Example.test'],
                          ['example.test.'], ['a..test'], ['-bad.test']):
                with self.subTest(key=key, value=value), self.assertRaises(ConfigurationError):
                    Guard(self.config(**{key: value}))

    def test_invalid_patterns(self):
        for rules in (None, {}, [None], [{}], [{'entity': 'X', 'pattern': ''}],
                      [{'entity': 1, 'pattern': 'x'}], [{'entity': 'X', 'pattern': '['}]):
            with self.subTest(rules=rules), self.assertRaises(ConfigurationError):
                Guard(self.config(patterns=rules))

    def test_invalid_lists_and_secret_category(self):
        for key in ('literals', 'block_entities'):
            for value in ('value', None, [1], ['']):
                with self.subTest(key=key, value=value), self.assertRaises(ConfigurationError):
                    Guard(self.config(**{key: value}))
        with self.assertRaises(ConfigurationError):
            Guard(self.config(block_entities=[]))

    def test_presidio_options_validated_before_import(self):
        for options in ({'presidio_language': ''}, {'presidio_language': True},
                        {'presidio_language': 'fr'}, {'presidio_language': 'fr', 'presidio_model': ''},
                        *({'presidio_score': v} for v in (True, -0.1, 1.1, float('nan'), float('inf'), '0.7'))):
            with self.subTest(options=options), self.assertRaises(ConfigurationError):
                Guard(self.config(**options))

    def test_policy_is_copied(self):
        config = self.config()
        g = Guard(config)
        config['exact_hosts'].clear()
        config['patterns'][0]['pattern'] = 'changed'
        self.assertTrue(g.config['exact_hosts'])
        self.assertNotEqual(g.config['patterns'][0]['pattern'], 'changed')
        self.assertEqual(validate_config(self.config())['max_aliases'], 10000)


class RestorationRegressions(unittest.TestCase):
    def events(self, g, events, event_name=None):
        body = b''.join(((('event: ' + event_name + '\n') if event_name else '') +
                         'data: ' + json.dumps(e) + '\n\n').encode() for e in events)
        body += b'data: [DONE]\n\n'
        result = g.response(body, 'text/event-stream')
        self.assertTrue(result.endswith(b'data: [DONE]\n\n'))
        return [loads(line[6:]) for line in result.splitlines()
                if line.startswith(b'data: ') and line[6:] != b'[DONE]']

    def test_responses_arguments_all_split_positions(self):
        token = '__PII_aaaaaaaaaaaa_000001__'
        value = 'host"with\\slashes\nand newline'
        arguments = json.dumps({'host': token})
        for split in range(len(arguments) + 1):
            with self.subTest(split=split):
                g = guard()
                g.reverse[token] = value
                events = [{'type': 'response.function_call_arguments.delta', 'item_id': 'a',
                           'output_index': 0, 'delta': part}
                          for part in (arguments[:split], arguments[split:])]
                out = self.events(g, events)
                self.assertEqual(loads(''.join(e['delta'] for e in out)), {'host': value})

    def test_responses_parallel_arguments(self):
        g = guard()
        tokens = ['__PII_aaaaaaaaaaaa_000001__', '__PII_aaaaaaaaaaaa_000002__']
        values = ['a"b\\c', 'second\nvalue']
        g.reverse.update(zip(tokens, values))
        args = [json.dumps({'host': t}) for t in tokens]
        events = [{'type': 'response.function_call_arguments.delta', 'item_id': str(i),
                   'output_index': i, 'delta': args[i][a:b]}
                  for a, b in ((0, 20), (20, None)) for i in (0, 1)]
        out = self.events(g, events)
        for i, value in enumerate(values):
            text = ''.join(e['delta'] for e in out if e['item_id'] == str(i))
            self.assertEqual(loads(text), {'host': value})

    def test_responses_event_name_without_type(self):
        g = guard()
        token = '__PII_aaaaaaaaaaaa_000001__'
        g.reverse[token] = 'a"b\\c'
        out = self.events(g, [{'output_index': 0, 'delta': json.dumps({'host': token})}],
                          'response.function_call_arguments.delta')
        self.assertEqual(loads(out[0]['delta']), {'host': 'a"b\\c'})

    def test_responses_arguments_missing_channel_rejected(self):
        with self.assertRaises(PolicyError):
            self.events(guard(), [{'type': 'response.function_call_arguments.delta', 'delta': '{}'}])

    def test_responses_unknown_malformed_and_non_json_alias_rejected(self):
        for text in ('{"host":"__PII_aaaaaaaaaaaa_999999__"}',
                     '{"host":"__PII_broken"}', 'not JSON __PII_broken'):
            with self.subTest(text=text), self.assertRaises(PolicyError):
                self.events(guard(), [{'type': 'response.function_call_arguments.delta',
                                      'item_id': 'a', 'delta': text}])

    def test_anthropic_partial_json(self):
        g = guard()
        token = '__PII_aaaaaaaaaaaa_000001__'
        g.reverse[token] = 'a"b\\c'
        arguments = json.dumps({'host': token})
        events = [{'type': 'content_block_delta', 'index': 0,
                   'delta': {'type': 'input_json_delta', 'partial_json': part}}
                  for part in (arguments[:15], arguments[15:])]
        out = self.events(g, events)
        self.assertEqual(loads(''.join(e['delta']['partial_json'] for e in out)), {'host': 'a"b\\c'})


class ToolNameRegressions(unittest.TestCase):
    def test_secret_blocked_in_exempt_tool_names(self):
        secret = 'ghp_' + 'x' * 30
        payloads = [
            {'messages': [{'role': 'assistant', 'tool_calls': [{'type': 'function', 'function': {'name': secret, 'arguments': '{}'}}]}]},
            {'messages': [{'role': 'tool', 'name': secret, 'content': 'hello'}]},
            {'messages': [{'type': 'tool_use', 'name': secret, 'input': {}}]},
            {'messages': [], 'tool_choice': {'type': 'function', 'function': {'name': secret}}},
            {'messages': [], 'function_call': {'name': secret}},
            {'messages': [], 'tools': [{'type': 'function', 'function': {'name': secret}}]},
        ]
        for mode in ('block', 'redact'):
            for body in payloads:
                with self.subTest(mode=mode, body=body), self.assertRaises(SensitiveDataError):
                    guard(mode).request(dumps(body))

    def test_non_secret_names_preserved_in_both_modes(self):
        body = dumps({'messages': [{'role': 'tool', 'name': 'lookup.corp', 'content': 'hello'}]})
        for mode in ('block', 'redact'):
            self.assertEqual(guard(mode).request(body), body)

    def test_custom_block_entity_in_tool_name(self):
        g = guard(block_entities=['SECRET', 'CUSTOM'], patterns=[{'entity': 'CUSTOM', 'pattern': 'blocked_name'}])
        with self.assertRaises(SensitiveDataError):
            g.request(dumps({'messages': [{'role': 'tool', 'name': 'blocked_name', 'content': ''}]}))


class ReadinessRegressions(unittest.TestCase):
    def health(self, g):
        instance = addon.CopilotPII()
        instance.guard = g
        f = flow(host='pii-gate.invalid', scheme='http', method='GET')
        run(instance.request(f))
        return f.response

    def test_success_in_both_modes(self):
        for mode in ('block', 'redact'):
            response = self.health(guard(mode))
            self.assertEqual(response.status_code, 200)
            self.assertTrue(loads(response.content)['ready'])

    def test_size_errors_are_not_ready(self):
        for mode in ('block', 'redact'):
            self.assertEqual(self.health(guard(mode, max_body_bytes=1)).status_code, 503)

    def test_generic_policy_error_is_not_ready(self):
        for mode in ('block', 'redact'):
            with patch.object(Guard, 'request', side_effect=PolicyError('synthetic failure')):
                self.assertEqual(self.health(guard(mode)).status_code, 503)

    def test_missing_canary_detection_is_not_ready(self):
        for mode in ('block', 'redact'):
            self.assertEqual(self.health(guard(mode, patterns=[])).status_code, 503)

    def test_broken_restoration_is_not_ready(self):
        with patch.object(Guard, 'response', return_value=b'{"text":"wrong"}'):
            self.assertEqual(self.health(guard()).status_code, 503)

    def test_alias_capacity_failure_is_not_ready(self):
        g = guard(max_aliases=1)
        g.request(request('other@example.test'))
        self.assertEqual(self.health(g).status_code, 503)

    def test_mapping_and_cache_unchanged(self):
        g = guard()
        g.detector = lambda text: []
        g.request(request('other@example.test'))
        before = {name: getattr(g, name).copy() for name in ('aliases', 'reverse', 'known', 'cache')}
        self.assertEqual(self.health(g).status_code, 200)
        self.assertEqual(before, {name: getattr(g, name) for name in before})

    def test_non_loopback_rejected(self):
        instance = addon.CopilotPII()
        instance.guard = guard()
        f = flow(host='pii-gate.invalid')
        f.client_conn.peername = ('192.0.2.1', 1)
        run(instance.request(f))
        self.assertEqual(f.response.status_code, 403)

    def test_load_rejects_duplicate_policy_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            path.write_text('{"mode":"block","mode":"redact"}')
            with patch.dict(os.environ, {'COPILOT_PII_CONFIG': str(path)}):
                with self.assertRaises(PolicyError):
                    addon.CopilotPII().load(None)

    def test_load_validates_hosts_before_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            path.write_text('{"mode":"block"}')
            with patch.dict(os.environ, {'COPILOT_PII_CONFIG': str(path)}):
                with self.assertRaises(ConfigurationError):
                    addon.CopilotPII().load(None)


if __name__ == '__main__':
    unittest.main()

"""Out-of-process detector: real child processes, fake analyser (fake_worker.py).

The optional RealPresidioTests class runs the real pii_worker.py when presidio_analyzer and
the spaCy model en_core_web_sm are installed; it is skipped otherwise.
"""
import asyncio
import importlib.util
import json
import sys
import time
import unittest
from pathlib import Path
from pii_config import ConfigurationError, validate_config
from pii_core import Guard, PolicyError, loads
from pii_detector import DetectorTimeout, DetectorUnavailable, PresidioWorker
from test_addon import addon, flow
from test_core import request

HERE = Path(__file__).parent


def config(**options):
    data = json.loads((HERE / 'policy.json').read_text())
    data.update(mode='redact', presidio_language='en', presidio_model='fake', presidio_timeout_ms=1000)
    data.update(options)
    return validate_config(data)


def worker(behaviour='', **options):
    w = PresidioWorker(config(**options), command=[sys.executable, str(HERE / 'fake_worker.py'), behaviour])
    w.start()
    return w


def gateway(behaviour='', **options):
    instance = addon.CopilotPII()
    instance.guard = Guard(config(**options))
    instance.worker = worker(behaviour, **options)
    assert instance.worker.wait_ready(10)
    return instance


def content(f):
    return loads(f.request.content)['messages'][0]['content']


class WorkerTestCase(unittest.TestCase):
    def tearDown(self):
        for item in getattr(self, 'cleanup', []):
            item.stop()

    def gateway(self, behaviour='', **options):
        instance = gateway(behaviour, **options)
        self.cleanup = getattr(self, 'cleanup', []) + [instance.worker]
        return instance

    def send(self, instance, text):
        f = flow(request(text))
        asyncio.run(instance.request(f))
        return f


class NominalTests(WorkerTestCase):
    def test_spans_applied_and_cached(self):
        g = self.gateway()
        f = self.send(g, 'Bob a@example.test')
        self.assertIsNone(f.response)
        self.assertNotIn('Bob', content(f))
        self.assertIn('Bob', g.guard.reverse.values())
        calls = []
        original = g.worker.analyze_many
        async def counted(texts):
            calls.append(texts)
            return await original(texts)
        g.worker.analyze_many = counted
        self.send(g, 'Bob a@example.test')
        self.assertEqual(calls, [])

    def test_stdout_noise_does_not_corrupt_protocol(self):
        g = self.gateway()
        self.assertIsNone(self.send(g, 'NOISE Bob').response)

    def test_health_reports_detector(self):
        g = self.gateway()
        f = flow(host='pii-gate.invalid', scheme='http', method='GET')
        asyncio.run(g.request(f))
        self.assertEqual(f.response.status_code, 200)
        self.assertEqual(json.loads(f.response.content)['detector'], 'ready')


class FailureTests(WorkerTestCase):
    def assert_restarts(self, g, text, status=503):
        old = g.worker.proc
        start = time.monotonic()
        f = self.send(g, text)
        self.assertEqual(f.response.status_code, status)
        self.assertLess(time.monotonic() - start, 3)
        self.assertIsNotNone(old.poll(), 'old worker must be terminated')
        self.assertTrue(g.worker.wait_ready(10))
        self.assertIsNone(self.send(g, 'Bob').response)

    def test_timeout_kills_and_restarts(self):
        self.assert_restarts(self.gateway(), 'SLEEP')

    def test_crash_restarts(self):
        self.assert_restarts(self.gateway(), 'CRASH')

    def test_corrupt_reply_restarts(self):
        self.assert_restarts(self.gateway(), 'BADREPLY')

    def test_invalid_spans_refused_and_not_cached(self):
        g = self.gateway()
        self.assertEqual(self.send(g, 'BADSPAN').response.status_code, 403)
        self.assertEqual(len(g.guard.cache), 0)

    def test_text_too_long_refused_before_worker(self):
        g = self.gateway(presidio_max_chars=10)
        self.assertEqual(self.send(g, 'x' * 11).response.status_code, 403)

    def test_not_ready_refused(self):
        instance = addon.CopilotPII()
        instance.guard = Guard(config())
        instance.worker = worker('slowstart')
        self.cleanup = [instance.worker]
        self.assertEqual(self.send(instance, 'hello').response.status_code, 503)

    def test_missing_worker_refused(self):
        instance = addon.CopilotPII()
        instance.guard = Guard(config())
        self.assertEqual(self.send(instance, 'hello').response.status_code, 503)

    def test_circuit_breaker(self):
        instance = addon.CopilotPII()
        instance.guard = Guard(config(presidio_max_restarts=1))
        instance.worker = worker('initfail', presidio_max_restarts=1)
        self.cleanup = [instance.worker]
        deadline = time.monotonic() + 10
        while instance.worker.status() != 'failed' and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(instance.worker.state, 'failed')
        self.assertIsNone(instance.worker.proc)
        f = flow(host='pii-gate.invalid', scheme='http', method='GET')
        asyncio.run(instance.request(f))
        self.assertEqual(f.response.status_code, 503)
        self.assertEqual(json.loads(f.response.content)['detector'], 'failed')

    def test_reload_during_analysis_refused(self):
        g = self.gateway()
        original = g.worker.analyze_many
        async def reload(texts):
            result = await original(texts)
            g.guard = Guard(config())
            return result
        g.worker.analyze_many = reload
        self.assertEqual(self.send(g, 'hello').response.status_code, 503)


class ConcurrencyTests(WorkerTestCase):
    def test_event_loop_not_blocked(self):
        g = self.gateway()
        async def scenario():
            loop = asyncio.get_running_loop()
            slow = asyncio.create_task(g.request(flow(request('SLEEP'))))
            gaps, last = [], loop.time()
            other = flow(request('hello'), host='example.test')
            while not slow.done():
                await asyncio.sleep(0.01)
                now = loop.time(); gaps.append(now - last); last = now
            await g.request(other)
            return max(gaps), other
        gap, other = asyncio.run(scenario())
        self.assertLess(gap, 0.25)
        self.assertIsNone(other.response)

    def test_queue_full_refused_immediately(self):
        g = self.gateway(presidio_queue=1)
        async def scenario():
            first = flow(request('SLEEP'))
            second = flow(request('hello'))
            third = flow(request('other'))
            t1 = asyncio.create_task(g.request(first))
            await asyncio.sleep(0.1)
            t2 = asyncio.create_task(g.request(second))
            await asyncio.sleep(0.1)
            start = time.monotonic()
            await g.request(third)
            elapsed = time.monotonic() - start
            await asyncio.gather(t1, t2)
            return first, second, third, elapsed
        first, second, third, elapsed = asyncio.run(scenario())
        self.assertEqual(third.response.status_code, 503)
        self.assertLess(elapsed, 0.1)
        self.assertEqual(first.response.status_code, 503)
        self.assertEqual(second.response.status_code, 503)

    def test_concurrent_aliases_consistent(self):
        g = self.gateway()
        texts = [f'Bob user{i}@example.test' for i in range(8)]
        flows = [flow(request(t)) for t in texts]
        async def scenario():
            await asyncio.gather(*(g.request(f) for f in flows))
        asyncio.run(scenario())
        tokens = list(g.guard.reverse)
        self.assertEqual(len(tokens), len(set(tokens)))
        self.assertEqual(sorted(g.guard.reverse.values()), sorted(['Bob'] + [t.split()[1] for t in texts]))
        for f, text in zip(flows, texts):
            self.assertEqual(g.guard.restore(loads(f.request.content))['messages'][0]['content'], text)

    def test_done_stops_worker(self):
        g = gateway()
        proc = g.worker.proc
        g.done()
        self.assertIsNotNone(proc.poll())
        self.assertEqual(g.worker.state, 'stopped')


class CoreContractTests(unittest.TestCase):
    BODIES = [
        request('Bob a@example.test', model='gpt'),
        json.dumps({'messages': [{'role': 'assistant', 'tool_calls': [{'type': 'function', 'function': {
            'name': 'lookup', 'arguments': '{"who":"Bob"}'}}]}],
            'tools': [{'type': 'function', 'function': {'name': 'lookup', 'description': 'find people'}}]}).encode(),
        json.dumps({'input': [{'role': 'user', 'content': [{'type': 'input_text', 'text': 'hi Bob'}]}],
                    'instructions': 'be brief'}).encode(),
    ]

    def test_collect_matches_request_walk(self):
        for body in self.BODIES:
            seen = []
            sync = Guard(config(presidio_language=None))
            sync.detector = lambda text: seen.append(text) or []
            sync.request(body)
            texts, cached = Guard(config()).collect(body)
            with self.subTest(body=body):
                self.assertEqual(sorted(set(seen)), sorted(texts))
                self.assertEqual(cached, {})

    def test_missing_result_is_refused(self):
        g = Guard(config())
        with self.assertRaises(PolicyError):
            g.request(request('hello'))
        texts, _ = g.collect(request('hello'))
        with self.assertRaises(PolicyError):
            g.request(request('hello'), {Guard.key(t): [] for t in texts[:-1]})

    def test_cached_results_are_pinned(self):
        g = Guard(config(cache_size=1))
        g.request(request('hello'), {Guard.key('hello'): []})
        texts, cached = g.collect(request('hello'))
        self.assertEqual(texts, [])
        g.cache.clear()
        self.assertEqual(g.request(request('hello'), cached), request('hello'))

    def test_block_mode_refuses_before_worker(self):
        g = Guard(config(mode='block'))
        with self.assertRaises(PolicyError):
            g.collect(request('a@example.test'))

    def test_worker_options_validated(self):
        for key, value in [('presidio_timeout_ms', 99), ('presidio_timeout_ms', 60001), ('presidio_timeout_ms', 1.5),
                           ('presidio_max_chars', 0), ('presidio_queue', 0), ('presidio_queue', True),
                           ('presidio_max_restarts', 0), ('presidio_restart_window_s', 0), ('presidio_python', '')]:
            with self.subTest(key=key, value=value), self.assertRaises(ConfigurationError):
                config(**{key: value})


def real_presidio():
    return all(importlib.util.find_spec(name) for name in ('presidio_analyzer', 'en_core_web_sm'))


@unittest.skipUnless(real_presidio(), 'presidio_analyzer and en_core_web_sm not installed')
class RealPresidioTests(unittest.TestCase):
    def test_real_worker_detects_person_within_deadline(self):
        w = PresidioWorker(config(presidio_model='en_core_web_sm', presidio_timeout_ms=10000, presidio_score=0.5))
        w.start()
        try:
            self.assertTrue(w.wait_ready(120))
            text = 'My colleague John Smith will call tomorrow.'
            start = time.monotonic()
            result = asyncio.run(w.analyze_many([text]))
            self.assertLess(time.monotonic() - start, 10)
            found = {text[a:b] for a, b, kind in result[Guard.key(text)] if kind == 'PERSON'}
            self.assertIn('John Smith', found)
        finally:
            w.stop()


if __name__ == '__main__':
    unittest.main()

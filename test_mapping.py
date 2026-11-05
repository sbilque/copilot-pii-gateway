"""MappingStore: inactivity TTL, aliases never reused, capacity, isolation of copies."""
import json
import unittest
from pathlib import Path

from pii_config import ConfigurationError, validate_config
from pii_core import Guard, PolicyError
from pii_mapping import CapacityError, MappingStore


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def policy(**options):
    config = json.loads(Path(__file__).with_name('policy.json').read_text())
    config.update(mode='redact', **options)
    return config


def body(text):
    return json.dumps({'messages': [{'role': 'user', 'content': text}]}).encode()


class MappingStoreTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.store = MappingStore(capacity=3, ttl_s=60, clock=self.clock)

    def test_same_value_same_alias(self):
        a = self.store.alias('EMAIL', 'a@example.test')
        self.assertEqual(self.store.alias('EMAIL', 'a@example.test'), a)
        self.assertNotEqual(self.store.alias('EMAIL', 'b@example.test'), a)
        self.assertEqual(self.store.lookup(a), 'a@example.test')

    def test_inactivity_purges_and_alias_never_reused(self):
        old = self.store.alias('EMAIL', 'a@example.test')
        self.clock.now += 61
        self.assertIsNone(self.store.lookup(old))
        self.assertEqual(self.store.stats()['purges'], 1)
        self.assertFalse(self.store.known)
        new = self.store.alias('EMAIL', 'b@example.test')
        self.assertNotEqual(new, old)
        self.assertIsNone(self.store.lookup(old))

    def test_activity_extends_ttl(self):
        token = self.store.alias('EMAIL', 'a@example.test')
        for _ in range(3):
            self.clock.now += 50
            self.assertEqual(self.store.lookup(token), 'a@example.test')
        self.clock.now += 50
        self.store.alias('EMAIL', 'b@example.test')
        self.assertEqual(self.store.lookup(token), 'a@example.test')

    def test_unknown_lookup_does_not_extend_ttl(self):
        token = self.store.alias('EMAIL', 'a@example.test')
        self.clock.now += 50
        self.assertIsNone(self.store.lookup('__PII_000000000000_000001__'))
        self.clock.now += 11
        self.assertIsNone(self.store.lookup(token))

    def test_capacity(self):
        for i in range(3):
            self.store.alias('EMAIL', f'{i}@example.test')
        with self.assertRaises(CapacityError):
            self.store.alias('EMAIL', 'x@example.test')

    def test_counter_exhaustion_rotates_prefix(self):
        first = self.store.alias('EMAIL', 'a@example.test')
        prefix = self.store.prefix
        self.store.counter = MappingStore.LAST_COUNTER
        token = self.store.alias('EMAIL', 'b@example.test')
        self.assertNotEqual(self.store.prefix, prefix)
        self.assertTrue(token.endswith('_000001__'))
        self.assertNotEqual(token, first)
        self.assertEqual(self.store.lookup(first), 'a@example.test')

    def test_copy_is_isolated(self):
        self.store.alias('EMAIL', 'a@example.test')
        clone = self.store.copy()
        token = clone.alias('EMAIL', 'b@example.test')
        self.assertIsNone(self.store.lookup(token))
        self.assertEqual(len(self.store.reverse), 1)

    def test_purge_and_stats_hold_no_values(self):
        self.store.alias('EMAIL', 'a@example.test')
        self.assertNotIn('example', json.dumps(self.store.stats()))
        self.store.purge()
        self.assertEqual((self.store.reverse, self.store.aliases, self.store.known), ({}, {}, {}))

    def test_separate_stores_never_share_aliases(self):
        other = MappingStore(capacity=3, ttl_s=60)
        token = self.store.alias('EMAIL', 'a@example.test')
        self.assertNotEqual(other.alias('EMAIL', 'a@example.test'), token)
        self.assertIsNone(other.lookup(token))


class GuardMappingTests(unittest.TestCase):
    def test_expired_alias_refused_in_response(self):
        guard, clock = Guard(policy(mapping_ttl_s=60)), Clock()
        guard.store.clock = clock
        guard.store.last_used = clock()
        out = guard.request(body('ecrire a a@example.test'))
        token = guard.TOKEN.search(out.decode()).group()
        self.assertEqual(json.loads(guard.response(json.dumps({'t': token}).encode(), 'application/json'))['t'], 'a@example.test')
        clock.now += 61
        with self.assertRaises(PolicyError):
            guard.response(json.dumps({'t': token}).encode(), 'application/json')

    def test_request_after_expiry_forgets_known_values(self):
        guard, clock = Guard(policy(mapping_ttl_s=60)), Clock()
        guard.store.clock = clock
        guard.request(body('ecrire a a@example.test'))
        self.assertIn('a@example.test', guard.known)
        clock.now += 61
        guard.request(body('bonjour'))
        self.assertFalse(guard.known)

    def test_capacity_is_policy_error(self):
        guard = Guard(policy(max_aliases=1))
        with self.assertRaises(PolicyError):
            guard.request(body('a@example.test b@example.test'))

    def test_config_validation(self):
        self.assertEqual(validate_config(policy())['mapping_ttl_s'], 28800)
        for bad in (0, -1, 604801, 1.5, '60', True):
            with self.assertRaises(ConfigurationError):
                validate_config(policy(mapping_ttl_s=bad))
        for bad in ('', 'a b', 'x' * 65, 3):
            with self.assertRaises(ConfigurationError):
                validate_config(policy(mapping_scope=bad))


if __name__ == '__main__':
    unittest.main()

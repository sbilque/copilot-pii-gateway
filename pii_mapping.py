"""Alias <-> value mapping of one scope, in memory only (no persistence)."""
import secrets
import time


class CapacityError(ValueError):
    pass


class MappingStore:
    """Mapping for one scope (one gateway process per operating system user).

    - Aliases are __PII_<prefix>_<counter>__. The counter only grows, and the prefix is new
      for each store and after counter exhaustion: an alias is never given to another value.
    - Inactivity TTL: when no alias was issued or resolved for ttl_s seconds, the mapping is
      purged. Responses that still reference purged aliases are refused by the caller.
    - capacity bounds the live aliases of the scope.
    """

    LAST_COUNTER = 999999  # six digits in the alias format

    def __init__(self, capacity, ttl_s, scope='process', clock=time.monotonic):
        self.capacity, self.ttl_s, self.scope, self.clock = capacity, ttl_s, scope, clock
        self.prefix, self.counter = secrets.token_hex(6), 0
        self.aliases, self.reverse, self.known = {}, {}, {}
        self.last_used = clock()
        self.purges = 0

    def expire(self):
        """Purge the mapping if it has been inactive for longer than the TTL."""
        if self.reverse and self.clock() - self.last_used > self.ttl_s:
            self.purge()

    def purge(self):
        """Forget every value. The counter and prefix are kept, so no alias is reused."""
        if self.reverse:
            self.purges += 1
        self.aliases.clear(); self.reverse.clear(); self.known.clear()

    def alias(self, kind, value):
        self.expire()
        key = (kind, value)
        if key not in self.aliases:
            if len(self.aliases) >= self.capacity:
                raise CapacityError('alias capacity exceeded')
            if self.counter >= self.LAST_COUNTER:
                self.prefix, self.counter = secrets.token_hex(6), 0
            self.counter += 1
            token = f'__PII_{self.prefix}_{self.counter:06d}__'
            self.aliases[key], self.reverse[token] = token, value
            if len(value) >= 3:
                self.known.setdefault(value, kind)
        self.last_used = self.clock()
        return self.aliases[key]

    def lookup(self, token):
        """Original value of a live alias, or None (unknown, expired or from another store)."""
        self.expire()
        value = self.reverse.get(token)
        if value is not None:
            self.last_used = self.clock()
        return value

    def copy(self):
        clone = object.__new__(MappingStore)
        clone.__dict__.update(self.__dict__)
        clone.aliases, clone.reverse, clone.known = self.aliases.copy(), self.reverse.copy(), self.known.copy()
        return clone

    def stats(self):
        """Counts only, never values: safe for the health endpoint and logs."""
        return {'scope': self.scope, 'aliases': len(self.reverse), 'ttl_s': self.ttl_s, 'purges': self.purges}

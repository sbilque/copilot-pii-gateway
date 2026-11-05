"""Validate policy configuration before detectors or HTTP hooks are used."""
import copy
import math
import re


class ConfigurationError(ValueError):
    pass


def validate_config(config):
    if not isinstance(config, dict):
        raise ConfigurationError('policy must be a JSON object')
    config = copy.deepcopy(config)
    if config.get('mode', 'block') not in ('block', 'redact'):
        raise ConfigurationError('mode must be block or redact')
    limits = {'max_body_bytes': 4194304, 'max_response_bytes': 8388608,
              'max_aliases': 10000, 'max_depth': 64, 'cache_size': 2000}
    for key, default in limits.items():
        value = config.get(key, default)
        minimum = 0 if key == 'cache_size' else 1
        if type(value) is not int or value < minimum:
            raise ConfigurationError(key + ' must be an integer within its allowed range')
        if key == 'max_aliases' and value > 999999:
            raise ConfigurationError('max_aliases exceeds the six-digit token capacity')
        config[key] = value
    for key in ('exact_hosts', 'host_suffixes'):
        hosts = config.get(key)
        if not isinstance(hosts, list):
            raise ConfigurationError(key + ' must be an explicit list of DNS names')
        for host in hosts:
            if not isinstance(host, str) or not 1 <= len(host) <= 253:
                raise ConfigurationError(key + ' contains an invalid DNS name')
            if host != host.lower() or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                                          for label in host.split('.')):
                raise ConfigurationError(key + ' requires lowercase DNS names without ports or trailing dots')
    if not config['exact_hosts'] and not config['host_suffixes']:
        raise ConfigurationError('at least one allowed host or suffix is required')
    for key in ('block_entities', 'literals'):
        values = config.get(key, ['SECRET'] if key == 'block_entities' else [])
        if not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values):
            raise ConfigurationError(key + ' must be a list of non-empty strings')
        config[key] = values
    if 'SECRET' not in config['block_entities']:
        raise ConfigurationError('block_entities must include SECRET')
    patterns = config.get('patterns', [])
    if not isinstance(patterns, list):
        raise ConfigurationError('patterns must be a list')
    for rule in patterns:
        if not isinstance(rule, dict) or any(not isinstance(rule.get(k), str) or not rule[k]
                                             for k in ('entity', 'pattern')):
            raise ConfigurationError('each pattern requires non-empty entity and pattern strings')
        try:
            re.compile(rule['pattern'])
        except re.error:
            raise ConfigurationError('patterns contains an invalid regular expression') from None
    ttl = config.get('mapping_ttl_s', 28800)
    if type(ttl) is not int or not 1 <= ttl <= 604800:
        raise ConfigurationError('mapping_ttl_s must be an integer between 1 and 604800')
    config['mapping_ttl_s'] = ttl
    scope = config.get('mapping_scope', 'process')
    if not isinstance(scope, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', scope):
        raise ConfigurationError('mapping_scope must be a short label')
    language = config.get('presidio_language')
    if language is not None and (not isinstance(language, str) or not language.strip()):
        raise ConfigurationError('presidio_language must be null or a non-empty string')
    if language and (not isinstance(config.get('presidio_model'), str) or not config['presidio_model'].strip()):
        raise ConfigurationError('presidio_model is required when Presidio is enabled')
    worker = {'presidio_timeout_ms': (3000, 100, 60000), 'presidio_max_chars': (200000, 1, 4194304),
              'presidio_queue': (8, 1, 1000), 'presidio_max_restarts': (3, 1, 100),
              'presidio_restart_window_s': (60, 1, 86400)}
    for key, (default, minimum, maximum) in worker.items():
        value = config.get(key, default)
        if type(value) is not int or not minimum <= value <= maximum:
            raise ConfigurationError(f'{key} must be an integer between {minimum} and {maximum}')
        config[key] = value
    python = config.get('presidio_python')
    if python is not None and (not isinstance(python, str) or not python.strip()):
        raise ConfigurationError('presidio_python must be null or a non-empty path')
    score = config.get('presidio_score', 0.7)
    if type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 1:
        raise ConfigurationError('presidio_score must be a finite number between zero and one')
    return config

"""Experimental request PII filter; responses are fully buffered, including SSE."""
import copy
import hashlib
import ipaddress
import json
import re
import secrets
from collections import OrderedDict, defaultdict
from pii_config import validate_config


class PolicyError(ValueError):
    pass


class SensitiveDataError(PolicyError):
    pass


def loads(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise PolicyError('duplicate JSON key')
            result[key] = value
        return result
    def invalid(_):
        raise PolicyError('invalid JSON constant')
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)


def dumps(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()


class Guard:
    STRUCTURAL = {'id', 'tool_call_id', 'tool_use_id', 'call_id', 'previous_response_id',
                  'model', 'role', 'type', 'stop', 'stop_sequences'}
    ROOTS = {'messages', 'prompt', 'input', 'system', 'instructions', 'suffix'}
    MEDIA = {'image', 'image_url', 'input_image', 'audio', 'input_audio', 'file', 'input_file', 'document'}
    PRIVATE = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    TOKEN = re.compile(r'__PII_[0-9a-f]{12}_[0-9]{6}__')

    def __init__(self, config):
        config = validate_config(config)
        self.config = config
        self.mode = config.get('mode', 'block')
        if self.mode not in ('block', 'redact'):
            raise PolicyError('mode must be block or redact')
        self.rules = [(r['entity'], re.compile(r['pattern'])) for r in config.get('patterns', [])]
        self.secrets = set(config.get('block_entities', ['SECRET']))
        self.aliases, self.reverse, self.known = {}, {}, {}
        self.prefix = secrets.token_hex(6)
        self.cache = OrderedDict()
        self.detector = None
        if config.get('presidio_language'):
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            lang = config['presidio_language']
            nlp = NlpEngineProvider(nlp_configuration={'nlp_engine_name': 'spacy', 'models': [
                {'lang_code': lang, 'model_name': config['presidio_model']}]}).create_engine()
            analyzer = AnalyzerEngine(nlp_engine=nlp, supported_languages=[lang])
            self.detector = lambda text: [(r.start, r.end, r.entity_type) for r in analyzer.analyze(
                text=text, language=lang, score_threshold=config.get('presidio_score', 0.7))]

    def spans(self, text, slow=True):
        found = [(m.start(), m.end(), kind) for kind, rule in self.rules for m in rule.finditer(text) if m.end() > m.start()]
        for value in self.config.get('literals', []):
            if not value:
                raise PolicyError('empty literal')
            found += [(m.start(), m.end(), 'INTERNAL') for m in re.finditer(re.escape(value), text)]
        for value, kind in self.known.items():
            rule = r'(?<!\w)' + re.escape(value) + r'(?!\w)'
            found += [(m.start(), m.end(), kind) for m in re.finditer(rule, text)]
        for m in re.finditer(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', text):
            try:
                if any(ipaddress.ip_address(m.group()) in n for n in self.PRIVATE):
                    found.append((m.start(), m.end(), 'PRIVATE_IP'))
            except ValueError:
                pass
        if slow and self.detector:
            key = hashlib.blake2b(text.encode('utf-8', 'surrogatepass'), digest_size=16).digest()
            if key not in self.cache:
                spans = list(self.detector(text))
                if any(not (isinstance(a, int) and isinstance(b, int) and 0 <= a < b <= len(text)) for a, b, _ in spans):
                    raise PolicyError('invalid detector span')
                self.cache[key] = spans
            self.cache.move_to_end(key)
            found += self.cache[key]
            while len(self.cache) > self.config.get('cache_size', 2000):
                self.cache.popitem(last=False)
        merged = []
        for a, b, kind in sorted(found, key=lambda x: (x[0], -x[1])):
            if merged and a < merged[-1][1]:
                p, q, old = merged[-1]
                merged[-1] = (p, max(q, b), kind if kind in self.secrets else old)
            else:
                merged.append((a, b, kind))
        return merged

    def redact(self, text, writable=True, slow=True):
        if text.startswith('data:') and len(text) > 256:
            raise PolicyError('encoded content unsupported')
        found = self.spans(text, slow)
        if found and (self.mode == 'block' or not writable or any(k in self.secrets for _, _, k in found)):
            raise SensitiveDataError('sensitive data blocked')
        for a, b, kind in reversed(found):
            value = text[a:b]
            key = (kind, value)
            if key not in self.aliases:
                if len(self.aliases) >= self.config.get('max_aliases', 10000):
                    raise PolicyError('alias capacity exceeded')
                token = f'__PII_{self.prefix}_{len(self.aliases) + 1:06d}__'
                self.aliases[key], self.reverse[token] = token, value
                if len(value) >= 3:
                    self.known.setdefault(value, kind)
            text = text[:a] + self.aliases[key] + text[b:]
        return text

    def walk(self, node, key='', root=False, tool_name=False, writable=True, depth=0):
        if depth > self.config.get('max_depth', 64):
            raise PolicyError('JSON depth exceeded')
        if isinstance(node, str):
            if key == 'name' and tool_name:
                if any(kind in self.secrets for _, _, kind in self.spans(node)):
                    raise SensitiveDataError('secret in tool name')
                return node
            return self.redact(node, writable and key not in self.STRUCTURAL, key not in self.STRUCTURAL)
        if isinstance(node, list):
            return [self.walk(v, key, False, False, writable, depth + 1) for v in node]
        if isinstance(node, dict):
            if node.get('type') in self.MEDIA | {'thinking', 'redacted_thinking'} or 'signature' in node:
                raise PolicyError('multimodal or signed block unsupported')
            named = tool_name or node.get('role') == 'tool' or node.get('type') in ('tool_use', 'function_call') or (node.get('type') == 'function' and 'function' in node)
            result = {}
            for k, v in node.items():
                if self.spans(k, slow=False):
                    raise PolicyError('sensitive JSON key')
                can_edit = writable and not (root and k == 'tools')
                exempt_name = (root and k in ('tool_choice', 'function_call')) or (named and k == 'function') or (named and k == 'name')
                result[k] = self.walk(v, k, False, exempt_name, can_edit, depth + 1)
            return result
        return node

    def request(self, body):
        if len(body) > self.config.get('max_body_bytes', 4194304):
            raise PolicyError('request size exceeded')
        obj = loads(body)
        if not isinstance(obj, dict) or not self.ROOTS.intersection(obj):
            raise PolicyError('unknown request schema')
        changed = self.walk(obj, root=True)
        return body if changed == obj else dumps(changed)

    def check(self):
        """Exercise the active policy without consuming its mapping or cache."""
        probe = copy.copy(self)
        for name in ('aliases', 'reverse', 'known', 'cache'):
            setattr(probe, name, getattr(self, name).copy())
        neutral = dumps({'messages': [{'role': 'user', 'content': ''}]})
        sample = dumps({'messages': [{'role': 'user', 'content': 'canary@example.test'}]})
        if probe.request(neutral) != neutral:
            return False
        try:
            result = probe.request(sample)
        except SensitiveDataError:
            return self.mode == 'block'
        if self.mode != 'redact' or result == sample:
            return False
        masked = loads(result)['messages'][0]['content']
        if 'canary@example.test' in masked or not self.TOKEN.search(masked):
            return False
        restored = probe.response(dumps({'text': masked}), 'application/json')
        return loads(restored) == {'text': 'canary@example.test'}

    def text(self, value):
        def replace(match):
            if match.group() not in self.reverse:
                raise PolicyError('unknown alias in response')
            return self.reverse[match.group()]
        value = self.TOKEN.sub(replace, value)
        if '__PII_' in value:
            raise PolicyError('malformed alias in response')
        return value

    def restore(self, node, key=''):
        if isinstance(node, str):
            if key in ('arguments', 'partial_json'):
                try:
                    inner = loads(node)
                except ValueError:
                    if '__PII_' in node:
                        raise PolicyError('non-JSON tool arguments')
                    return node
                return dumps(self.restore(inner)).decode()
            return self.text(node)
        if isinstance(node, list):
            return [self.restore(v, key) for v in node]
        if isinstance(node, dict):
            return {k: self.restore(v, k) for k, v in node.items()}
        return node

    def response(self, body, content_type):
        if len(body) > self.config.get('max_response_bytes', 8388608):
            raise PolicyError('response size exceeded')
        if content_type.split(';')[0].strip().endswith('json'):
            return dumps(self.restore(loads(body)))
        if not content_type.startswith('text/event-stream'):
            raise PolicyError('unsupported response format')
        events, channels = [], defaultdict(list)
        def visit(node, event, path, channel, arguments_delta=False):
            if isinstance(node, dict):
                tags = tuple((k, node[k]) for k in ('index', 'item_id', 'output_index', 'content_index', 'type') if isinstance(node.get(k), (str, int)))
                for k, v in node.items():
                    visit(v, event, path + (k,), channel + tags, arguments_delta)
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    visit(v, event, path + (i,), channel, arguments_delta)
            elif isinstance(node, str) and 'delta' in path and path[-1] != 'type':
                restore_key = 'arguments' if arguments_delta and path == ('delta',) else path[-1]
                channels[(channel, path, restore_key)].append((event, path, node))
        for raw in re.split(r'\r?\n\r?\n', body.decode('utf-8')):
            if not raw:
                continue
            lines = raw.splitlines()
            data = '\n'.join(l[5:].lstrip(' ') for l in lines if l.startswith('data:'))
            obj = None
            if data and data != '[DONE]':
                obj = loads(data)
            idx = len(events)
            events.append((lines, obj))
            if obj is not None:
                event_name = next((l[6:].strip() for l in lines if l.startswith('event:')), '')
                event_type = obj.get('type', event_name) if isinstance(obj, dict) else event_name
                arguments_delta = event_type == 'response.function_call_arguments.delta'
                if arguments_delta and not (obj.get('item_id') or type(obj.get('output_index')) is int):
                    raise PolicyError('argument delta requires a channel identifier')
                visit(obj, idx, (), (), arguments_delta)
        def set_path(obj, path, value):
            for p in path[:-1]:
                obj = obj[p]
            obj[path[-1]] = value
        for (_, _, final_key), refs in channels.items():
            full = ''.join(v for _, _, v in refs)
            restored = self.restore(full, final_key) if final_key in ('arguments', 'partial_json') else self.text(full)
            for i, (event, path, _) in enumerate(refs):
                set_path(events[event][1], path, restored if i == 0 else '')
        output = []
        for lines, obj in events:
            if obj is not None:
                data = 'data: ' + dumps(self.restore(obj)).decode()
                positions = [i for i, l in enumerate(lines) if l.startswith('data:')]
                lines = [data if i == positions[0] else l for i, l in enumerate(lines) if i not in positions[1:]]
            output.append('\n'.join(lines) + '\n\n')
        return ''.join(output).encode()

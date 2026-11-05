"""Fake Copilot upstream for the lab. Synthetic data only.

Every POST is recorded in RECORDINGS/<x-lab-id>.json (raw body in base64, header names
only), so tests can check exactly what left the gateway. Responses are scripted by the
x-lab-scenario header: echo, gzip-echo, unknown-alias, sse-chat, sse-responses and
sse-anthropic. Streams reuse the aliases found in the request, split across events.
"""
import base64
import gzip
import json
import os
import re
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RECORDINGS = Path(os.environ.get('LAB_RECORDINGS', '/recordings'))
CERT = os.environ.get('LAB_CERT', '/pki/upstream.pem')
PORT = int(os.environ.get('LAB_PORT', '443'))
TOKEN = re.compile(r'__PII_[0-9a-f]{12}_[0-9]{6}__')
UNKNOWN_ALIAS = '__PII_0123456789ab_999999__'


def aliases(body):
    """Distinct aliases of the request body, in order of appearance."""
    seen = []
    for token in TOKEN.findall(body.decode('utf-8', 'replace')):
        if token not in seen:
            seen.append(token)
    return seen


def chunks(text, size):
    return [text[i:i + size] for i in range(0, len(text), size)] or ['']


def sse(events):
    out = []
    for event in events:
        name = event.get('type') if 'type' in event and str(event['type']).startswith('response.') else None
        out.append(('event: %s\n' % name if name else '') + 'data: ' + json.dumps(event) + '\n\n')
    return ''.join(out).encode()


def tool_args(values):
    """Tool-call argument strings built from the aliases (a0 email, a1 host, a2 project)."""
    keys = ['email', 'host', 'projet']
    return [json.dumps({keys[i]: v}) for i, v in enumerate(values[:3])]


def sse_chat(found):
    text = 'Contact : ' + ' / '.join(found)
    events = [{'choices': [{'index': 0, 'delta': {'role': 'assistant', 'content': ''}}]}]
    events += [{'choices': [{'index': 0, 'delta': {'content': c}}]} for c in chunks(text, 7)]
    args = tool_args(found)
    events.append({'choices': [{'index': 0, 'delta': {'tool_calls': [
        {'index': i, 'id': 'call_%d' % i, 'type': 'function', 'function': {'name': 'lookup', 'arguments': ''}}
        for i in range(len(args))]}}]})
    parts = [chunks(a, 5) for a in args]
    for step in range(max(len(p) for p in parts)):
        for i, p in enumerate(parts):
            if step < len(p):
                events.append({'choices': [{'index': 0, 'delta': {'tool_calls': [
                    {'index': i, 'function': {'arguments': p[step]}}]}}]})
    events.append({'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'tool_calls'}]})
    return sse(events) + b'data: [DONE]\n\n'


def sse_responses(found):
    text = 'Contact : ' + ' / '.join(found)
    events = [{'type': 'response.created', 'response': {'id': 'resp_lab'}}]
    events += [{'type': 'response.output_text.delta', 'item_id': 'msg_1', 'output_index': 0,
                'content_index': 0, 'delta': c} for c in chunks(text, 6)]
    args = tool_args(found)
    parts = [chunks(a, 4) for a in args]
    for step in range(max(len(p) for p in parts)):
        for i, p in enumerate(parts):
            if step < len(p):
                events.append({'type': 'response.function_call_arguments.delta', 'item_id': 'fc_%d' % i,
                               'output_index': i + 1, 'delta': p[step]})
    events.append({'type': 'response.completed', 'response': {'id': 'resp_lab', 'status': 'completed'}})
    return sse(events)


def sse_anthropic(found):
    text = 'Contact : ' + ' / '.join(found)
    events = [{'type': 'message_start', 'message': {'id': 'msg_lab', 'role': 'assistant'}},
              {'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'text', 'text': ''}}]
    events += [{'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': c}}
               for c in chunks(text, 8)]
    events.append({'type': 'content_block_stop', 'index': 0})
    for i, arg in enumerate(tool_args(found)):
        events.append({'type': 'content_block_start', 'index': i + 1,
                       'content_block': {'type': 'tool_use', 'id': 'tu_%d' % i, 'name': 'lookup', 'input': {}}})
        events += [{'type': 'content_block_delta', 'index': i + 1,
                    'delta': {'type': 'input_json_delta', 'partial_json': c}} for c in chunks(arg, 3)]
        events.append({'type': 'content_block_stop', 'index': i + 1})
    events.append({'type': 'message_stop'})
    return sse(events)


def texts(node):
    """All string values of the request messages, in order."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for item in node:
            yield from texts(item)
    elif isinstance(node, dict):
        for key, value in node.items():
            if key not in ('role', 'model', 'type'):
                yield from texts(value)


def chat_completion(content):
    return {'id': 'chatcmpl-lab', 'object': 'chat.completion', 'model': 'lab-model',
            'choices': [{'index': 0, 'finish_reason': 'stop',
                         'message': {'role': 'assistant', 'content': content}}]}


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        sys.stderr.write('fake-copilot %s %s\n' % (self.command, self.path))

    def send_body(self, status, data, content_type='application/json', encoding=None):
        self.send_response(status)
        self.send_header('content-type', content_type)
        if encoding:
            self.send_header('content-encoding', encoding)
        self.send_header('content-length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, status, obj):
        self.send_body(status, json.dumps(obj).encode())

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('content-length', '0')))
        lab_id = self.headers.get('x-lab-id', '')
        if lab_id and lab_id.replace('-', '').isalnum():
            record = {'method': self.command, 'path': self.path, 'headers': sorted(self.headers.keys()),
                      'body_b64': base64.b64encode(body).decode()}
            tmp = RECORDINGS / (lab_id + '.tmp')
            tmp.write_text(json.dumps(record))
            tmp.replace(RECORDINGS / (lab_id + '.json'))
        scenario = self.headers.get('x-lab-scenario', 'echo')
        try:
            messages = json.loads(body).get('messages', [])
        except ValueError:
            return self.send_json(400, {'error': 'invalid json'})
        echo = ' | '.join(texts(messages))
        found = aliases(body)
        if scenario == 'echo':
            return self.send_json(200, chat_completion(echo))
        if scenario == 'gzip-echo':
            data = gzip.compress(json.dumps(chat_completion(echo)).encode())
            return self.send_body(200, data, encoding='gzip')
        if scenario == 'unknown-alias':
            return self.send_json(200, chat_completion(echo + ' ' + UNKNOWN_ALIAS))
        streams = {'sse-chat': sse_chat, 'sse-responses': sse_responses, 'sse-anthropic': sse_anthropic}
        if scenario in streams and found:
            return self.send_body(200, streams[scenario](found), 'text/event-stream')
        self.send_json(400, {'error': 'unknown scenario or no alias'})


def main():
    RECORDINGS.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(('0.0.0.0', PORT), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print('fake-copilot listening on', PORT, flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()

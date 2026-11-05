"""Fake Copilot upstream for the lab. Synthetic data only.

Every POST is recorded in RECORDINGS/<x-lab-id>.json (raw body in base64, header names
only), so tests can check exactly what left the gateway. Responses are scripted by the
x-lab-scenario header.
"""
import base64
import json
import os
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RECORDINGS = Path(os.environ.get('LAB_RECORDINGS', '/recordings'))
CERT = os.environ.get('LAB_CERT', '/pki/upstream.pem')
PORT = int(os.environ.get('LAB_PORT', '443'))


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

    def send_json(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

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
        if scenario == 'echo':
            try:
                messages = json.loads(body).get('messages', [])
            except ValueError:
                return self.send_json(400, {'error': 'invalid json'})
            return self.send_json(200, chat_completion(' | '.join(texts(messages))))
        self.send_json(400, {'error': 'unknown scenario'})


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

"""Run from this directory with mitmdump -s copilot_pii.py (see docs/prototype.md)."""
import ipaddress
import json
import os
from pathlib import Path
from mitmproxy import http
from pii_core import Guard


class CopilotPII:
    def load(self, loader):
        self.guard = Guard(json.loads(Path(os.environ.get('COPILOT_PII_CONFIG', 'policy.json')).read_text()))

    def target(self, host):
        host = host.lower().rstrip('.')
        return host == 'githubcopilot.com' or host.endswith('.githubcopilot.com') or host == 'copilot-proxy.githubusercontent.com'

    def allowed(self, host):
        host = host.lower().rstrip('.')
        return host in self.guard.config['exact_hosts'] or any(host == h or host.endswith('.' + h) for h in self.guard.config['host_suffixes'])

    def error(self, flow, status):
        flow.metadata['pii_blocked'] = True
        flow.response = http.Response.make(status, b'{"error":{"message":"Local PII policy refused this exchange"}}',
                                          {'content-type': 'application/json', 'cache-control': 'no-store'})

    def requestheaders(self, flow):
        if self.target(flow.request.host):
            flow.request.stream = False
            length = flow.request.headers.get('content-length')
            try:
                if length and int(length) > self.guard.config.get('max_body_bytes', 4194304):
                    self.error(flow, 413)
            except ValueError:
                self.error(flow, 400)

    def request(self, flow):
        if flow.request.host == 'pii-gate.invalid':
            try:
                peer = flow.client_conn.peername[0]
                if not ipaddress.ip_address(peer).is_loopback or flow.request.headers.get('origin'):
                    return self.error(flow, 403)
                sample = b'{"messages":[{"role":"user","content":"canary@example.test"}]}'
                try:
                    result = self.guard.request(sample)
                    ok = self.guard.mode == 'redact' and result != sample
                except ValueError:
                    ok = self.guard.mode == 'block'
                flow.metadata['pii_blocked'] = True
                flow.response = http.Response.make(200 if ok else 503, json.dumps({'ready': ok, 'mode': self.guard.mode}).encode(),
                                                  {'content-type': 'application/json'})
            except Exception:
                self.error(flow, 503)
            return
        if not self.target(flow.request.host) or flow.response is not None:
            return
        try:
            r = flow.request
            if not self.allowed(r.host) or r.scheme != 'https' or r.query or r.headers.get('upgrade'):
                raise ValueError('unsupported route')
            if r.method in ('GET', 'HEAD', 'OPTIONS') and not r.raw_content:
                return
            if r.headers.get('content-type', '').split(';')[0].strip() != 'application/json':
                raise ValueError('unsupported body')
            r.content = self.guard.request(r.content)
            r.headers['accept-encoding'] = 'identity'
        except Exception:
            self.error(flow, 403)

    def responseheaders(self, flow):
        if self.target(flow.request.host) and flow.response is not None:
            flow.response.stream = False

    def response(self, flow):
        if not self.target(flow.request.host) or flow.metadata.get('pii_blocked') or flow.response is None:
            return
        if self.guard.mode != 'redact' or not self.guard.reverse:
            return
        try:
            flow.response.content = self.guard.response(flow.response.content, flow.response.headers.get('content-type', ''))
        except Exception:
            self.error(flow, 502)


addons = [CopilotPII()]

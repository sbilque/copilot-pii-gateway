"""mitmproxy addon. Started by gateway.py, which builds it in; never load it with scripts or -s."""
import ipaddress
import json
import os
from pathlib import Path
from mitmproxy import http
from pii_core import Guard, loads
from pii_detector import DetectorUnavailable, PresidioWorker


class CopilotPII:
    def __init__(self):
        self.guard, self.worker = None, None

    def load(self, loader):
        config = loads(Path(os.environ.get('COPILOT_PII_CONFIG', 'policy.json')).read_bytes())
        if isinstance(config, dict) and hasattr(os, 'getuid'):
            # One gateway per operating system user: the mapping scope is that user.
            config.setdefault('mapping_scope', f'uid-{os.getuid()}')
        guard = Guard(config)
        worker = PresidioWorker(guard.config) if guard.external else None
        if self.worker:
            self.worker.stop()
        self.guard, self.worker = guard, worker
        if worker:
            worker.start()

    def done(self):
        if self.guard:
            self.guard.store.purge()  # values never outlive the process
        if self.worker:
            self.worker.stop()

    async def prefetch(self, guard, body, ignore_policy=False):
        """Run slow detection out of process; None when the guard has no external detector."""
        if not guard.external:
            return None
        texts, results = guard.collect(body, ignore_policy)
        if texts:
            if self.worker is None:
                raise DetectorUnavailable('detector missing')
            results.update(await self.worker.analyze_many(texts))
        return results

    def detector_state(self, guard):
        if not guard.external:
            return 'disabled'
        return self.worker.status() if self.worker else 'missing'

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

    async def request(self, flow):
        if flow.request.host == 'pii-gate.invalid':
            try:
                peer = flow.client_conn.peername[0]
                if not ipaddress.ip_address(peer).is_loopback or flow.request.headers.get('origin'):
                    return self.error(flow, 403)
                guard = self.guard
                state = self.detector_state(guard)
                ok = state in ('disabled', 'ready')
                if ok:
                    prefetched = None
                    if guard.external:
                        prefetched = {}
                        for body in guard.CHECK_BODIES:
                            prefetched.update(await self.prefetch(guard, body, ignore_policy=True))
                    ok = guard is self.guard and guard.check(prefetched)
                flow.metadata['pii_blocked'] = True
                flow.response = http.Response.make(200 if ok else 503, json.dumps(
                    {'ready': ok, 'mode': guard.mode, 'detector': state, 'mapping': guard.store.stats()}).encode(), {'content-type': 'application/json'})
            except Exception:
                self.error(flow, 503)
            return
        if not self.target(flow.request.host) or flow.response is not None:
            return
        try:
            r, guard = flow.request, self.guard
            if not self.allowed(r.host) or r.scheme != 'https' or r.query or r.headers.get('upgrade'):
                raise ValueError('unsupported route')
            if r.method in ('GET', 'HEAD', 'OPTIONS') and not r.raw_content:
                return
            if r.headers.get('content-type', '').split(';')[0].strip() != 'application/json':
                raise ValueError('unsupported body')
            body = r.content
            prefetched = await self.prefetch(guard, body)
            if guard is not self.guard:
                raise DetectorUnavailable('policy reloaded during analysis')
            r.content = guard.request(body, prefetched)
            r.headers['accept-encoding'] = 'identity'
        except DetectorUnavailable:
            self.error(flow, 503)
        except Exception:
            self.error(flow, 403)

    def responseheaders(self, flow):
        if self.target(flow.request.host) and flow.response is not None:
            flow.response.stream = False

    def response(self, flow):
        if not self.target(flow.request.host) or flow.metadata.get('pii_blocked') or flow.response is None:
            return
        if self.guard.mode != 'redact':
            return
        # Always checked, even with an empty mapping: an alias unknown to this instance
        # (restart, lost mapping, another instance) must never reach the client raw.
        try:
            self.guard.store.expire()
            body, content_type = flow.response.content, flow.response.headers.get('content-type', '')
            if not self.guard.reverse and not self.guard.may_hold_alias(body, content_type):
                return  # nothing to restore and no alias marker: bytes unchanged
            flow.response.content = self.guard.response(body, content_type)
        except Exception:
            self.error(flow, 502)


addons = [CopilotPII()]

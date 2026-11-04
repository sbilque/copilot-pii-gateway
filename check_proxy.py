"""Synthetic addon readiness check. Does not prove Copilot routing or upstream access."""
import json
import urllib.request

opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': 'http://127.0.0.1:8080'}))
with opener.open('http://pii-gate.invalid/health', timeout=5) as response:
    status = json.load(response)
if status.get('ready') is not True:
    raise SystemExit('PII filter not ready')
print('PII canary OK:', status['mode'])

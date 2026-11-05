"""Synthetic addon readiness check. Does not prove Copilot routing or upstream access.

CANARY_PROXY (default http://127.0.0.1:8080) is the gateway. If the local proxy secret file
exists (COPILOT_PII_PROXY_AUTH, default ./proxy-auth), it is sent as proxy credentials.
"""
import base64
import json
import os
import urllib.error
import urllib.request
from pathlib import Path


def health(proxy=None, secret_path=None, timeout=5):
    """Return the canary status of the gateway, or raise OSError / ValueError."""
    proxy = proxy or os.environ.get('CANARY_PROXY', 'http://127.0.0.1:8080')
    secret_path = Path(secret_path or os.environ.get('COPILOT_PII_PROXY_AUTH', 'proxy-auth'))
    request = urllib.request.Request('http://pii-gate.invalid/health')
    if secret_path.is_file():
        token = base64.b64encode(secret_path.read_text(encoding='ascii').strip().encode()).decode()
        request.add_header('Proxy-Authorization', 'Basic ' + token)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy}))
    try:
        with opener.open(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        error.close()
        raise OSError(f'canary HTTP {error.code}') from None


def ready(**kwargs):
    try:
        return health(**kwargs).get('ready') is True
    except (OSError, ValueError):
        return False


if __name__ == '__main__':
    try:
        status = health()
    except (OSError, ValueError) as error:
        raise SystemExit(f'PII filter not ready: {error}')
    if status.get('ready') is not True:
        raise SystemExit('PII filter not ready')
    print('PII canary OK:', status['mode'])

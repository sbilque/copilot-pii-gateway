#!/bin/sh
# Prepare un confdir prive puis lance la passerelle. LAB_MODE=block|redact.
set -eu
conf=$(mktemp -d)
cp /pki/mitmproxy-ca.pem "$conf/"
cp /app/lab/mitmproxy.yaml "$conf/config.yaml"
python - "$conf/policy.json" <<'PY'
import json, os, sys
policy = json.load(open('/app/policy.json'))
policy['mode'] = os.environ.get('LAB_MODE', 'block')
json.dump(policy, open(sys.argv[1], 'w'))
PY
export COPILOT_PII_CONFIG="$conf/policy.json"
exec mitmdump --set confdir="$conf"

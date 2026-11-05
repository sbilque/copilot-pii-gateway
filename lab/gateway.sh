#!/bin/sh
# Prepare un confdir prive puis lance la passerelle du lab.
#   LAB_MODE          block (defaut) ou redact
#   LAB_POLICY_PATCH  objet JSON fusionne dans policy.json (ex. Presidio factice, literaux)
#   LAB_UPSTREAM      proxy amont (defaut http://corp-proxy:3128)
#   LAB_HOT_DIR       copie le code dans ce dossier et le charge depuis la (test de rechargement)
set -eu
conf=$(mktemp -d)
cp /pki/mitmproxy-ca.pem "$conf/"
script=/app/copilot_pii.py
if [ -n "${LAB_HOT_DIR:-}" ]; then
    cp /app/*.py "$LAB_HOT_DIR/"
    script="$LAB_HOT_DIR/copilot_pii.py"
fi
sed -e "s#/app/copilot_pii.py#$script#" \
    -e "s#upstream:http://corp-proxy:3128#upstream:${LAB_UPSTREAM:-http://corp-proxy:3128}#" \
    /app/lab/mitmproxy.yaml > "$conf/config.yaml"
python - "$conf/policy.json" <<'PY'
import json, os, sys
policy = json.load(open('/app/policy.json'))
policy['mode'] = os.environ.get('LAB_MODE', 'block')
policy.update(json.loads(os.environ.get('LAB_POLICY_PATCH') or '{}'))
json.dump(policy, open(sys.argv[1], 'w'))
PY
export COPILOT_PII_CONFIG="$conf/policy.json"
exec mitmdump --set confdir="$conf"

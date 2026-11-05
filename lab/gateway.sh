#!/bin/sh
# Prepare un confdir prive puis lance la passerelle du lab avec gateway.py (addon integre).
#   LAB_MODE          block (defaut) ou redact
#   LAB_POLICY_PATCH  objet JSON fusionne dans policy.json (ex. Presidio factice, literaux)
#   LAB_UPSTREAM      proxy amont (defaut http://corp-proxy:3128)
#   LAB_HOT_DIR       copie le code dans ce dossier et le lance depuis la (test F3)
#   LAB_ADD_SCRIPTS   1 : ajoute scripts a la configuration (doit etre refuse, test F4)
#   LAB_PROXY_AUTH    user:password du proxy local, ecrit dans COPILOT_PII_PROXY_AUTH (J6)
#   LAB_PKI           dossier de la CA mitmproxy (defaut /pki)
set -eu
conf=$(mktemp -d)
cp "${LAB_PKI:-/pki}/mitmproxy-ca.pem" "$conf/"
code=/app
if [ -n "${LAB_HOT_DIR:-}" ]; then
    cp /app/*.py "$LAB_HOT_DIR/"
    code=$LAB_HOT_DIR
fi
sed -e "s#upstream:http://corp-proxy:3128#upstream:${LAB_UPSTREAM:-http://corp-proxy:3128}#" \
    /app/lab/mitmproxy.yaml > "$conf/config.yaml"
if [ "${LAB_ADD_SCRIPTS:-}" = 1 ]; then
    printf 'scripts:\n  - %s/copilot_pii.py\n' "$code" >> "$conf/config.yaml"
fi
python - "$conf/policy.json" <<'PY'
import json, os, sys
policy = json.load(open('/app/policy.json'))
policy['mode'] = os.environ.get('LAB_MODE', 'block')
policy.update(json.loads(os.environ.get('LAB_POLICY_PATCH') or '{}'))
json.dump(policy, open(sys.argv[1], 'w'))
PY
export COPILOT_PII_CONFIG="$conf/policy.json"
if [ -n "${LAB_PROXY_AUTH:-}" ]; then
    (umask 077; printf '%s\n' "$LAB_PROXY_AUTH" > "$COPILOT_PII_PROXY_AUTH")
fi
exec python "$code/gateway.py" --set confdir="$conf"

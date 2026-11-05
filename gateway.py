"""Launch mitmproxy with the PII addon built in: no script loading, no hot reload.

Usage (same options as mitmdump): python gateway.py --set confdir=.
The policy is read once at start (COPILOT_PII_CONFIG, default policy.json). To apply a new
policy, restart the process: the alias mapping is lost on purpose.
"""
import os
import sys
from pathlib import Path

from mitmproxy import ctx, exceptions
from mitmproxy.tools import cmdline, dump, main

from copilot_pii import CopilotPII
from pii_config import ConfigurationError
from pii_core import Guard, PolicyError, loads


class NoScripts:
    """Refuse the scripts option: the filter must not be replaced, doubled or reloaded."""

    def configure(self, updated):
        if 'scripts' in updated and ctx.options.scripts:
            raise exceptions.OptionsError(
                'scripts is not allowed with gateway.py: the PII addon is built in; '
                'remove scripts from config.yaml and do not pass -s')


class GatewayMaster(dump.DumpMaster):
    def __init__(self, options, **kwargs):
        super().__init__(options, **kwargs)
        loader = self.addons.get('scriptloader')
        if loader is None:
            raise RuntimeError('mitmproxy script loader not found: unsupported mitmproxy version')
        # Without the script loader nothing watches files: no hot reload is possible.
        self.addons.remove(loader)
        self.addons.add(NoScripts(), CopilotPII())


def check_policy():
    """Fail before mitmproxy starts, with a short message, if the policy cannot be loaded."""
    path = os.environ.get('COPILOT_PII_CONFIG', 'policy.json')
    try:
        Guard(loads(Path(path).read_bytes()))
    except (OSError, ValueError, ConfigurationError, PolicyError) as error:
        sys.exit(f'gateway.py: policy {path} refused: {error}')


def run(arguments):
    check_policy()
    main.run(GatewayMaster, cmdline.mitmdump, arguments)


if __name__ == '__main__':
    run(sys.argv[1:])

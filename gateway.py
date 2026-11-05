"""Launch mitmproxy with the PII addon built in: no script loading, no hot reload.

Usage (same options as mitmdump): python gateway.py --set confdir=.
The policy is read once at start (COPILOT_PII_CONFIG, default policy.json). To apply a new
policy, restart the process: the alias mapping is lost on purpose.

Optional local proxy password: if the file COPILOT_PII_PROXY_AUTH (default ./proxy-auth,
created by make proxy-secret) exists, clients must send it as proxy credentials (407
otherwise). The secret is applied in process, never on the command line.

COPILOT_PII_PIDFILE: if set, the pid is written there for watch_proxy.py and removed at exit.
"""
import atexit
import stat
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


def read_proxy_secret(path):
    """Return 'user:password' from a private file, None if absent; exit if unsafe."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        sys.exit(f'gateway.py: {path} must be a regular file')
    if hasattr(os, 'getuid') and (info.st_uid != os.getuid() or info.st_mode & 0o077):
        sys.exit(f'gateway.py: {path} must belong to the current user with mode 600 (chmod 600 {path})')
    secret = Path(path).read_text(encoding='ascii').strip()
    user, _, password = secret.partition(':')
    if not user or len(password) < 16 or any(c.isspace() for c in secret) or user.startswith(('@', 'ldap')) or secret == 'any':
        sys.exit(f'gateway.py: {path} must hold one line user:password (password of 16 characters or more)')
    return secret


class LocalAuth:
    """Apply the local proxy secret; refuse a proxyauth option that would replace it."""

    def __init__(self, secret):
        self.secret = secret

    def configure(self, updated):
        if 'proxyauth' in updated and (ctx.options.proxyauth or None) != self.secret:
            raise exceptions.OptionsError('proxyauth is not allowed in options: use make proxy-secret '
                                          '(file COPILOT_PII_PROXY_AUTH, default ./proxy-auth)')


class GatewayMaster(dump.DumpMaster):
    proxy_secret = None

    def __init__(self, options, **kwargs):
        super().__init__(options, **kwargs)
        loader = self.addons.get('scriptloader')
        if loader is None:
            raise RuntimeError('mitmproxy script loader not found: unsupported mitmproxy version')
        # Without the script loader nothing watches files: no hot reload is possible.
        self.addons.remove(loader)
        self.addons.add(NoScripts(), LocalAuth(self.proxy_secret), CopilotPII())
        if self.proxy_secret:
            options.update(proxyauth=self.proxy_secret)


def check_policy():
    """Fail before mitmproxy starts, with a short message, if the policy cannot be loaded."""
    path = os.environ.get('COPILOT_PII_CONFIG', 'policy.json')
    try:
        Guard(loads(Path(path).read_bytes()))
    except (OSError, ValueError, ConfigurationError, PolicyError) as error:
        sys.exit(f'gateway.py: policy {path} refused: {error}')


def write_pidfile(path):
    pid = str(os.getpid())
    path.write_text(pid + '\n')

    def remove():
        try:
            if path.read_text().strip() == pid:
                path.unlink()
        except OSError:
            pass
    atexit.register(remove)


def run(arguments):
    check_policy()
    GatewayMaster.proxy_secret = read_proxy_secret(os.environ.get('COPILOT_PII_PROXY_AUTH', 'proxy-auth'))
    pidfile = os.environ.get('COPILOT_PII_PIDFILE')
    if pidfile:
        write_pidfile(Path(pidfile))
    main.run(GatewayMaster, cmdline.mitmdump, arguments)


if __name__ == '__main__':
    run(sys.argv[1:])

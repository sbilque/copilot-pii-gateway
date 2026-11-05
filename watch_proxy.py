"""Periodic canary: alert, then stop the gateway after consecutive failures.

A stopped gateway is closed (clients get no proxy); a gateway without a working filter is
not. Run it beside the gateway (launchd, systemd timer or service, Task Scheduler).

    python watch_proxy.py --pidfile gateway.pid [--interval 60] [--failures 3]
    python watch_proxy.py --once            # one check, exit 0 if ready

The gateway writes its pid when started with COPILOT_PII_PIDFILE set. CANARY_PROXY and
COPILOT_PII_PROXY_AUTH are read as in check_proxy.py.
"""
import argparse
import os
import signal
import sys
import time
from pathlib import Path

from check_proxy import ready


def log(message):
    print(time.strftime('%Y-%m-%dT%H:%M:%S'), message, file=sys.stderr, flush=True)


def stop(pidfile):
    """SIGTERM the pid in pidfile. Returns True if a signal was sent."""
    try:
        pid = int(Path(pidfile).read_text().strip())
    except (OSError, ValueError):
        log(f'ALERT: no valid pid in {pidfile}, gateway not stopped')
        return False
    if pid <= 1:
        log(f'ALERT: refusing pid {pid} from {pidfile}')
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        log(f'gateway pid {pid} already gone')
        return False
    except PermissionError:
        log(f'ALERT: pid {pid} does not belong to this user, not stopped')
        return False
    log(f'ALERT: gateway pid {pid} stopped (SIGTERM)')
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--interval', type=float, default=60.0, help='seconds between checks')
    parser.add_argument('--failures', type=int, default=3, help='consecutive failures before stopping')
    parser.add_argument('--pidfile', help='gateway pid file (COPILOT_PII_PIDFILE); without it, alert only')
    parser.add_argument('--once', action='store_true', help='single check, exit 0 if ready, 1 otherwise')
    args = parser.parse_args(argv)
    if args.interval <= 0 or args.failures < 1:
        parser.error('--interval must be positive and --failures at least 1')
    if args.once:
        return 0 if ready() else 1
    failed = 0
    while True:
        time.sleep(args.interval)  # first check after one interval: the gateway may be starting
        if ready():
            if failed:
                log('canary ready again')
            failed = 0
        else:
            failed += 1
            log(f'ALERT: PII canary failed ({failed}/{args.failures})')
            if failed >= args.failures:
                if args.pidfile:
                    stop(args.pidfile)
                return 2


if __name__ == '__main__':
    sys.exit(main())

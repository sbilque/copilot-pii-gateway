"""Validate config.yaml with mitmproxy's own option manager. Does not start the proxy."""
import asyncio
import sys

from mitmproxy import optmanager, options
from mitmproxy.tools.dump import DumpMaster


async def main(path):
    opts = options.Options()
    DumpMaster(opts, with_termlog=False, with_dumper=True)
    optmanager.load_paths(opts, path)
    if opts.deferred:
        sys.exit('Unknown options in ' + path + ': ' + ', '.join(sorted(opts.deferred)))
    if opts.scripts:
        sys.exit('scripts is not allowed in ' + path + ': gateway.py builds the PII addon in')
    print('mitmproxy configuration OK:', path, '- mode', ', '.join(opts.mode))


asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else 'config.yaml'))

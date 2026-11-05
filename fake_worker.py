"""Test double for pii_worker.py: same line protocol, behaviour driven by keywords.

Options (argv[1]): initfail, slowstart. Texts: SLEEP hangs, CRASH exits, BADSPAN returns an
invalid span, BADREPLY corrupts the channel, NOISE prints to stdout; every 'Bob' is a PERSON.
"""
import json
import os
import re
import sys
import time

from pii_worker import write

sink = os.fdopen(os.dup(sys.stdout.fileno()), 'w', encoding='ascii')
sys.stdout = sys.stderr
options = sys.argv[1] if len(sys.argv) > 1 else ''
if 'slowstart' in options:
    time.sleep(0.5)
if 'initfail' in options:
    write(sink, {'ready': False, 'error': 'OSError'})
    sys.exit(1)
write(sink, {'ready': True})
for line in sys.stdin:
    message = json.loads(line)
    spans, corrupt = [], False
    for text in message['texts']:
        if 'SLEEP' in text:
            time.sleep(60)
        if 'CRASH' in text:
            os._exit(3)
        if 'NOISE' in text:
            print('library noise')
        corrupt = corrupt or 'BADREPLY' in text
        if 'BADSPAN' in text:
            spans.append([[5, 2, 'X']])
        else:
            spans.append([[m.start(), m.end(), 'PERSON'] for m in re.finditer(r'\bBob\b', text)])
    if corrupt:
        sink.write('not json\n'); sink.flush()
    else:
        write(sink, {'id': message['id'], 'spans': spans})

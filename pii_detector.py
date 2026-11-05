"""Bounded-time client for the Presidio worker process (pii_worker.py).

The analysis runs in a child process. A batch that exceeds its deadline makes the parent kill
the process and start a new one; the request is refused (fail-closed). Waiting happens in
executor threads with a bounded timeout, so the mitmproxy event loop is never blocked by
Presidio itself.
"""
import asyncio
import json
import queue
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from pii_core import Guard, PolicyError

MAX_LINE = 16 * 1024 * 1024
EOF = object()


class DetectorUnavailable(PolicyError):
    """Detector not ready, busy, crashed or failed: refuse with 503."""


class DetectorTimeout(DetectorUnavailable):
    pass


class PresidioWorker:
    def __init__(self, config, command=None, stderr=subprocess.DEVNULL):
        options = {'language': config['presidio_language'], 'model': config['presidio_model'],
                   'score': config.get('presidio_score', 0.7)}
        python = config.get('presidio_python') or sys.executable
        self.command = command or [python, str(Path(__file__).with_name('pii_worker.py')), json.dumps(options)]
        self.stderr = stderr
        self.timeout = config.get('presidio_timeout_ms', 3000) / 1000
        self.max_chars = config.get('presidio_max_chars', 200000)
        self.queue_limit = config.get('presidio_queue', 8)
        self.max_restarts = config.get('presidio_max_restarts', 3)
        self.window = config.get('presidio_restart_window_s', 60)
        self.proc, self.inbox, self.state = None, None, 'stopped'
        self.restarts = deque()
        self.lock = asyncio.Lock()
        self.waiting = 0
        self.next_id = 0

    # Process lifecycle -------------------------------------------------------------

    def start(self):
        if self.state in ('stopped',):
            self.restarts.clear()
            self._spawn()

    def _spawn(self):
        self.proc = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=self.stderr)
        self.inbox = queue.Queue()
        threading.Thread(target=self._read, args=(self.proc, self.inbox), daemon=True).start()
        self.state = 'starting'

    @staticmethod
    def _read(proc, inbox):
        try:
            for line in iter(lambda: proc.stdout.readline(MAX_LINE + 1), b''):
                if len(line) > MAX_LINE or not line.endswith(b'\n'):
                    break
                try:
                    inbox.put(json.loads(line))
                except ValueError:
                    break
        except (OSError, ValueError):
            pass
        inbox.put(EOF)

    def _kill(self):
        proc, self.proc = self.proc, None
        if proc is None:
            return
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        for stream in (proc.stdin, proc.stdout):
            try:
                stream.close()
            except OSError:
                pass

    def _restart(self):
        self._kill()
        now = time.monotonic()
        self.restarts.append(now)
        while self.restarts and now - self.restarts[0] > self.window:
            self.restarts.popleft()
        if len(self.restarts) > self.max_restarts:
            self.state = 'failed'
        else:
            self._spawn()

    def stop(self):
        self._kill()
        self.state = 'stopped'

    def status(self):
        """Refresh and return starting, ready, failed or stopped; never blocks."""
        if self.state == 'starting':
            try:
                message = self.inbox.get_nowait()
            except queue.Empty:
                if self.proc.poll() is not None:
                    self._restart()
                return self.state
            if isinstance(message, dict) and message.get('ready') is True:
                self.state = 'ready'
            else:
                self._restart()
        elif self.state == 'ready' and self.proc.poll() is not None:
            self._restart()
        return self.state

    def wait_ready(self, timeout):
        """Blocking helper for start-up scripts and tests, not for request hooks."""
        deadline = time.monotonic() + timeout
        while self.status() in ('starting',) and time.monotonic() < deadline:
            time.sleep(0.02)
        return self.state == 'ready'

    # Analysis ----------------------------------------------------------------------

    async def analyze_many(self, texts):
        """Return {Guard.key(text): spans} for all texts within one deadline, or raise."""
        if not texts:
            return {}
        if any(len(text) > self.max_chars for text in texts):
            raise PolicyError('text too long for detector')
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.timeout
        if self.status() != 'ready':
            raise DetectorUnavailable('detector ' + self.state)
        if self.waiting >= self.queue_limit:
            raise DetectorUnavailable('detector busy')
        self.waiting += 1
        try:
            try:
                await asyncio.wait_for(self.lock.acquire(), max(deadline - loop.time(), 0))
            except TimeoutError:
                raise DetectorTimeout('detector queue timeout') from None
        finally:
            self.waiting -= 1
        try:
            if self.status() != 'ready':
                raise DetectorUnavailable('detector ' + self.state)
            self.next_id += 1
            ident, proc, inbox = self.next_id, self.proc, self.inbox
            line = (json.dumps({'id': ident, 'texts': texts}, ensure_ascii=True) + '\n').encode('ascii')
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise DetectorTimeout('detector queue timeout')
            try:
                message = await asyncio.wait_for(
                    loop.run_in_executor(None, self._exchange, proc, inbox, line, remaining), remaining)
            except (TimeoutError, queue.Empty):
                self._restart()
                raise DetectorTimeout('detector timeout') from None
            except OSError:
                self._restart()
                raise DetectorUnavailable('detector pipe failure') from None
            spans = message.get('spans') if isinstance(message, dict) and message.get('id') == ident else None
            if not isinstance(spans, list) or len(spans) != len(texts) or not all(isinstance(s, list) for s in spans):
                self._restart()
                raise DetectorUnavailable('invalid detector reply')
            results = {}
            for text, found in zip(texts, spans):
                results[Guard.key(text)] = Guard.validate_spans(text, found)
            return results
        finally:
            self.lock.release()

    @staticmethod
    def _exchange(proc, inbox, line, timeout):
        proc.stdin.write(line)
        proc.stdin.flush()
        message = inbox.get(timeout=timeout)
        if message is EOF:
            raise OSError('worker closed')
        return message

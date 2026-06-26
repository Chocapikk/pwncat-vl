"""
Regression tests for ``Linux._sync_shell`` (shell-bootstrap sync handshake).

The Linux platform bootstrap used to clear shell startup output (the
``bash: no job control in this shell`` banner, MOTD, prompts) with a fixed
``time.sleep(); channel.drain()`` pair. Because the channel socket is
non-blocking, ``drain()`` only clears bytes that have *already* arrived, so
on higher-latency links the banner could land after the sleep window, bleed
into the first framed command, and desync the command parser -- causing an
intermittent "session dies immediately" that ``nc`` never exhibits.

``_sync_shell`` replaces that with a deterministic marker handshake. These
tests exercise it over a real loopback socket wrapped in the actual
``Socket`` channel (so the non-blocking ``recv`` and real ``recvuntil`` code
paths run), with a fake shell thread that emits its banner *late*.
"""

import time
import socket
import threading
import types

from pwncat.channel.socket import Socket
from pwncat.platform.linux import Linux

# A realistic non-PTY ``bash -i`` startup burst: job-control complaint plus a
# colorized prompt. Delivered late, this is exactly what desynced the parser.
BANNER = (
    b"bash: cannot set terminal process group (1234): "
    b"Inappropriate ioctl for device\r\n"
    b"bash: no job control in this shell\r\n"
    b"\x1b[01;32mnagios@monitored\x1b[00m:\x1b[01;34m~\x1b[00m$ "
)


def _tcp_pair():
    """A connected TCP socket pair over loopback.

    A real ``AF_INET`` pair is used (rather than ``socket.socketpair``, which
    is ``AF_UNIX``) because ``Socket`` calls ``getpeername()`` and expects a
    ``(host, port)`` tuple.
    """

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    attacker = socket.create_connection(listener.getsockname())
    victim, _ = listener.accept()
    listener.close()
    return attacker, victim


def _platform_with(channel):
    """Minimal stand-in exposing ``.channel`` for ``_sync_shell``.

    ``_sync_shell`` only touches ``self.channel``, so a full ``Linux``
    instance (which would talk to a live shell in ``__init__``) is not
    required.
    """

    return types.SimpleNamespace(channel=channel)


def _echoing_shell(victim, *, banner_delay, echo_command=False, stop=None):
    """Fake shell loop: emit BANNER after ``banner_delay`` seconds, then
    answer ``echo`` commands the way a real shell would.

    With ``echo_command=True`` the command line is echoed back before its
    output, emulating a PTY-backed shell, to verify the marker cannot
    false-match on the echoed command.
    """

    def run():
        time.sleep(banner_delay)
        victim.sendall(BANNER)
        victim.setblocking(True)
        buf = b""
        while True:
            if stop is not None and stop.is_set():
                return
            try:
                victim.settimeout(0.2)
                chunk = victim.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if echo_command:
                    victim.sendall(line + b"\r\n")  # PTY-style command echo
                line = line.strip()
                if line.startswith(b"echo "):
                    # Shell concatenates adjacent quoted literals and strips
                    # the quotes: `echo "PWNCAT""<tok>"` -> `PWNCAT<tok>`.
                    out = line[len(b"echo "):].replace(b'"', b"")
                    victim.sendall(out + b"\n")

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


class TestSyncShellConsumesStartupOutput:
    """The handshake must absorb late startup output so the next framed
    command reads cleanly -- this is the core regression."""

    def test_late_banner_is_fully_consumed(self):
        attacker, victim = _tcp_pair()
        # Banner arrives at 0.3s -- after the old 0.2s sleep window.
        _echoing_shell(victim, banner_delay=0.3)
        channel = Socket(client=attacker, host="victim", port=4444)

        Linux._sync_shell(_platform_with(channel))

        # Stream is now in sync: a fresh command returns ONLY its output,
        # with none of the banner leaking ahead of it.
        channel.send(b'echo "RE""ADY"\n')
        leaked = channel.recvuntil(b"READY", timeout=3)
        assert b"no job control" not in leaked
        assert b"nagios@monitored" not in leaked
        assert leaked == b"READY"

    def test_legacy_drain_would_have_leaked(self):
        """Documents the bug: a bare ``sleep(0.2) + drain()`` against the
        same late banner leaves the banner sitting in the stream."""

        attacker, victim = _tcp_pair()
        _echoing_shell(victim, banner_delay=0.3)
        channel = Socket(client=attacker, host="victim", port=4444)

        time.sleep(0.2)
        channel.drain()

        channel.send(b'echo "RE""ADY"\n')
        leaked = channel.recvuntil(b"READY", timeout=3)
        assert b"no job control" in leaked  # the race, reproduced


class TestSyncShellRobustness:
    def test_pty_command_echo_does_not_false_match(self):
        """On a PTY-backed shell the command line is echoed before its
        output. The split marker literal (``"PWNCAT""<tok>"``) must ensure
        the handshake only matches the real output, not the echo."""

        attacker, victim = _tcp_pair()
        _echoing_shell(victim, banner_delay=0.05, echo_command=True)
        channel = Socket(client=attacker, host="victim", port=4444)

        Linux._sync_shell(_platform_with(channel))

        channel.send(b'echo "RE""ADY"\n')
        leaked = channel.recvuntil(b"READY", timeout=3)
        # The follow-up command's own echo precedes its output, but no
        # bootstrap banner survives the handshake.
        assert b"no job control" not in leaked

    def test_falls_back_without_raising_when_marker_never_returns(self):
        """A shell that never echoes the marker must degrade to the legacy
        best-effort drain rather than raising out of bootstrap."""

        attacker, victim = _tcp_pair()
        victim.sendall(b"bash: no job control in this shell\r\n")
        channel = Socket(client=attacker, host="victim", port=4444)

        start = time.time()
        # Short timeout so the fallback path is reached quickly.
        Linux._sync_shell(_platform_with(channel), timeout=1.0)
        elapsed = time.time() - start

        assert elapsed >= 1.0  # waited for the timeout, then fell back
        assert elapsed < 5.0  # but did not hang

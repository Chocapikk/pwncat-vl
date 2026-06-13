"""Unit tests for the platform auto-detection probe."""

from __future__ import annotations

import time

from pwncat.platform import (
    probe_platform,
    _classify_probe_output,
)


class FakeChannel:
    """Minimal channel stub: records what was sent and replays scripted
    bytes in response to ``recv`` calls. Models the half-duplex behaviour
    of pwncat's real channels closely enough for the probe."""

    def __init__(self, response: bytes, chunk_size: int = 64):
        self.response = response
        self.chunk_size = chunk_size
        self.sent = b""
        self.drained = 0
        self._cursor = 0

    def drain(self):
        self.drained += 1

    def send(self, data: bytes):
        self.sent += data

    def recv(self, n: int = 4096):
        remaining = self.response[self._cursor:]
        if not remaining:
            time.sleep(0.01)
            return b""
        size = min(n, self.chunk_size, len(remaining))
        chunk = remaining[:size]
        self._cursor += size
        return chunk


# --- _classify_probe_output ------------------------------------------------


def test_classify_linux_uname():
    assert _classify_probe_output(b"Linux\n") == "linux"


def test_classify_darwin_uname():
    assert _classify_probe_output(b"Darwin\n") == "linux"


def test_classify_powershell_error():
    sample = (
        b"Invoke-Expression : The term 'uname' is not recognized as the name "
        b"of a cmdlet, function, script file, or operable program. "
        b"CommandNotFoundException"
    )
    assert _classify_probe_output(sample) == "windows"


def test_classify_cmd_ver_output():
    assert _classify_probe_output(b"Microsoft Windows [Version 10.0.19045.4651]") == "windows"


def test_classify_windows_wins_when_both_markers_present():
    # The PowerShell error mentions the literal command name ``uname``
    # which is a Linux marker; we must not mis-classify this as Linux.
    mixed = (
        b"Invoke-Expression : The term 'Linux' is not recognized as a "
        b"cmdlet, CommandNotFoundException"
    )
    assert _classify_probe_output(mixed) == "windows"


def test_classify_returns_none_on_unknown():
    assert _classify_probe_output(b"random banner with no platform hint") is None


def test_classify_handles_empty_input():
    assert _classify_probe_output(b"") is None
    assert _classify_probe_output(None) is None


def test_classify_accepts_str():
    assert _classify_probe_output("Linux\n") == "linux"


# --- probe_platform --------------------------------------------------------


def _wrap_with_markers(sent: bytes, body: bytes) -> bytes:
    """Echo back the start/end markers that the probe injected so the probe
    can isolate the response section between them. The real PowerShell does
    not echo our markers, but a bash shell with echo enabled would; both
    cases must classify correctly."""

    # Extract the markers the probe just sent.
    start = sent.split(b"echo ", 1)[1].split(b"\n", 1)[0]
    end = sent.rsplit(b"echo ", 1)[1].split(b"\n", 1)[0]
    return start + b"\n" + body + b"\n" + end + b"\n"


def test_probe_detects_linux_with_uname_output():
    ch = FakeChannel(b"")  # response set after we see what was sent

    # Pretend a probe is happening: feed canned output that mimics bash
    # echoing the markers and uname returning ``Linux``.
    def simulate(probe_bytes):
        return _wrap_with_markers(probe_bytes, b"Linux")

    # Use a wrapper channel that lazily produces the response after send.
    class LazyLinux(FakeChannel):
        def send(self, data: bytes):
            super().send(data)
            self.response = simulate(self.sent)

    ch = LazyLinux(b"")
    assert probe_platform(ch, timeout=1.0) == "linux"
    assert b"uname" in ch.sent


def test_probe_detects_windows_with_powershell_error():
    class LazyWindows(FakeChannel):
        def send(self, data: bytes):
            super().send(data)
            # PowerShell will not echo the markers (no echo command for
            # them), but will spit out a CommandNotFoundException for
            # both ``uname`` and ``ver`` on modern PowerShell.
            self.response = (
                b"Invoke-Expression : The term 'uname' is not recognized "
                b"as the name of a cmdlet, function, script file, or "
                b"operable program. CommandNotFoundException\r\n"
                b"Invoke-Expression : The term 'ver' is not recognized "
                b"as the name of a cmdlet, function, script file, or "
                b"operable program. CommandNotFoundException\r\n"
            )

    ch = LazyWindows(b"")
    assert probe_platform(ch, timeout=1.0) == "windows"


def test_probe_detects_cmd_exe_with_ver_output():
    class LazyCmd(FakeChannel):
        def send(self, data: bytes):
            super().send(data)
            self.response = (
                b"'uname' is not recognized as an internal or external "
                b"command,\r\noperable program or batch file.\r\n"
                b"Microsoft Windows [Version 10.0.19045.4651]\r\n"
            )

    ch = LazyCmd(b"")
    assert probe_platform(ch, timeout=1.0) == "windows"


def test_probe_returns_none_when_channel_silent():
    # Channel never produces output; probe should give up at the timeout
    # rather than guess and return None.
    ch = FakeChannel(b"")
    assert probe_platform(ch, timeout=0.3) is None


def test_probe_returns_none_on_unrecognized_output():
    class LazyUnknown(FakeChannel):
        def send(self, data: bytes):
            super().send(data)
            self.response = _wrap_with_markers(self.sent, b"garbled output")

    ch = LazyUnknown(b"")
    assert probe_platform(ch, timeout=1.0) is None


def test_probe_survives_send_failure():
    class BrokenChannel:
        def drain(self):
            pass

        def send(self, data):
            raise OSError("connection reset")

        def recv(self, n=4096):
            return b""

    assert probe_platform(BrokenChannel(), timeout=0.5) is None


def test_probe_survives_recv_failure():
    class HalfBroken(FakeChannel):
        def recv(self, n=4096):
            raise OSError("connection reset")

    ch = HalfBroken(b"")
    assert probe_platform(ch, timeout=0.5) is None


def test_probe_command_includes_platform_markers():
    """Sanity check: whatever the response, the probe always sends the three
    platform-identifying commands -- uname (POSIX), ver (cmd.exe) and
    $PSVersionTable (PowerShell, which prints PSEdition on stdout)."""

    ch = FakeChannel(b"")
    probe_platform(ch, timeout=0.2)
    assert b"uname" in ch.sent
    assert b"ver" in ch.sent
    assert b"$PSVersionTable" in ch.sent


def test_classify_modern_powershell_cmdlet_wording():
    # PowerShell 6/7 says "a name of a cmdlet"; 5.1 said "the name of a cmdlet".
    sample = b"uname: The term 'uname' is not recognized as a name of a cmdlet"
    assert _classify_probe_output(sample) == "windows"


def test_classify_psversiontable_output():
    # $PSVersionTable prints PSEdition on stdout, independent of stderr.
    sample = b"Name  Value\n----  -----\nPSEdition  Core\nPlatform  Win32NT\n"
    assert _classify_probe_output(sample) == "windows"


def test_probe_detects_powershell_from_banner_only():
    # Interactive PowerShell may never run our commands (PSReadLine waits on a
    # terminal handshake), but it announces itself first; the banner alone is
    # captured and is enough to classify.
    ch = FakeChannel(b"PowerShell 7.4.2\r\nPS /> ")
    assert probe_platform(ch, timeout=0.5) == "windows"


def test_probe_powershell_wins_when_uname_resolves_on_linux_host():
    # A Linux-hosted pwsh runs the real ``uname`` and prints "Linux", but the
    # $PSVersionTable output must still classify the shell as Windows.
    class LazyPS(FakeChannel):
        def send(self, data: bytes):
            super().send(data)
            self.response = _wrap_with_markers(
                self.sent, b"Linux\nName Value\nPSEdition Core\n"
            )

    ch = LazyPS(b"")
    assert probe_platform(ch, timeout=1.0) == "windows"

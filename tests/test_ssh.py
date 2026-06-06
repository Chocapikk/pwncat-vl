"""
Unit tests for the SSH channel.

Tests the `send` method behavior around the SSH window size limit,
specifically the fix that prevents an instant ``TimeoutError`` on
uploads larger than the current ``out_window_size``.
"""

from unittest.mock import MagicMock

import pytest

from pwncat.channel.ssh import Ssh


def _make_ssh(window_size: int, timeout=0.0):
    """Build an Ssh instance without going through __init__.

    We bypass the real ``__init__`` because it requires a live SSH
    connection. The ``send`` method only uses ``self.client``, so a
    MagicMock standing in for the paramiko Channel is enough.
    """

    channel = object.__new__(Ssh)
    channel.client = MagicMock()
    channel.client.out_window_size = window_size
    channel.client.gettimeout.return_value = timeout
    return channel


class TestSshSend:
    """Verify the window-size aware blocking logic in Ssh.send."""

    def test_small_payload_does_not_touch_timeout(self):
        """Data fitting in the current window must keep the original timeout."""

        channel = _make_ssh(window_size=1024)
        payload = b"A" * 512

        assert channel.send(payload) == len(payload)

        channel.client.sendall.assert_called_once_with(payload)
        channel.client.settimeout.assert_not_called()

    def test_large_payload_switches_to_blocking_and_restores(self):
        """Data larger than the window must briefly enter blocking mode."""

        original_timeout = 0.1
        channel = _make_ssh(window_size=1024, timeout=original_timeout)
        payload = b"B" * 4096

        assert channel.send(payload) == len(payload)

        channel.client.sendall.assert_called_once_with(payload)

        # settimeout should be called twice: once with None to block,
        # once again to restore the previous timeout.
        timeout_calls = channel.client.settimeout.call_args_list
        assert len(timeout_calls) == 2
        assert timeout_calls[0].args == (None,)
        assert timeout_calls[1].args == (original_timeout,)

    def test_timeout_restored_when_sendall_raises(self):
        """If sendall raises, the original timeout must still be restored."""

        original_timeout = 0.25
        channel = _make_ssh(window_size=1024, timeout=original_timeout)
        channel.client.sendall.side_effect = OSError("ssh boom")

        with pytest.raises(OSError):
            channel.send(b"C" * 4096)

        timeout_calls = channel.client.settimeout.call_args_list
        assert len(timeout_calls) == 2
        assert timeout_calls[0].args == (None,)
        assert timeout_calls[1].args == (original_timeout,)

    def test_exact_window_size_does_not_block(self):
        """Boundary check: a payload equal to the window must not block."""

        channel = _make_ssh(window_size=2048)
        payload = b"D" * 2048

        assert channel.send(payload) == len(payload)

        channel.client.sendall.assert_called_once_with(payload)
        channel.client.settimeout.assert_not_called()

    def test_one_byte_over_window_blocks(self):
        """Boundary check: a payload one byte over the window must block."""

        original_timeout = 0.0
        channel = _make_ssh(window_size=2048, timeout=original_timeout)
        payload = b"E" * 2049

        assert channel.send(payload) == len(payload)

        channel.client.sendall.assert_called_once_with(payload)
        timeout_calls = channel.client.settimeout.call_args_list
        assert len(timeout_calls) == 2
        assert timeout_calls[0].args == (None,)
        assert timeout_calls[1].args == (original_timeout,)

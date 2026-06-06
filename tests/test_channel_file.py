"""
Regression tests for ``pwncat.channel.ChannelFile`` write/read paths.

These exercise edge cases of the partial-write loop and the EOF marker
detection that are otherwise only covered by full end-to-end integration
tests against a live target.
"""

from unittest.mock import MagicMock

from pwncat.channel import ChannelFile


def _make_file():
    """Construct a ChannelFile bound to a mock channel.

    The channel is a ``MagicMock`` so each test can rewire its ``send``
    and ``recv`` behaviour.
    """

    channel = MagicMock()
    cf = object.__new__(ChannelFile)
    cf.channel = channel
    cf.mode = "rw"
    cf.sof_marker = None
    cf.eof_marker = b"\xff\xff"
    cf.found_sof = True
    cf.on_close = None
    cf.eof = False
    cf._blocking = True
    return cf, channel


class TestChannelFileWritePartialSend:
    """Regression: ``ChannelFile.write`` used to retransmit the full
    payload on every loop iteration when the underlying channel returned
    a short count. The loop now slices the remaining bytes."""

    def test_send_called_with_remaining_slice_on_partial_write(self):
        cf, channel = _make_file()
        # Simulate a channel that always writes 3 bytes per call.
        channel.send.side_effect = [3, 3, 3]
        payload = b"abcdefghi"

        written = cf.write(payload)

        assert written == 9
        # Three send() calls, each with the unwritten suffix.
        sent_chunks = [call.args[0] for call in channel.send.call_args_list]
        assert sent_chunks == [b"abcdefghi", b"defghi", b"ghi"]

    def test_no_duplicate_bytes_sent(self):
        cf, channel = _make_file()
        # Channel sends 5 bytes the first time, 5 the second.
        channel.send.side_effect = [5, 5]
        payload = b"helloworld"

        written = cf.write(payload)

        assert written == 10
        sent_chunks = [call.args[0] for call in channel.send.call_args_list]
        # First send sees the full payload; the buggy code would send
        # the full payload AGAIN on the second iteration. The fix sends
        # only the unwritten suffix.
        assert sent_chunks[0] == b"helloworld"
        assert sent_chunks[1] == b"world"

    def test_eof_returns_zero_without_sending(self):
        cf, channel = _make_file()
        cf.eof = True

        assert cf.write(b"data") == 0
        channel.send.assert_not_called()

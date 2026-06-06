"""
Unit tests for pwncat.gtfobins parsing primitives.

These tests focus on the in-memory data model (Binary, Method, Capability,
Stream enums) and on the sudo-spec matching logic. They do not require
the bundled JSON file or any network access.
"""

import pytest

from pwncat.gtfobins import (
    Binary,
    Stream,
    GTFOBins,
    Capability,
    BinaryNotFound,
    SudoNotPossible,
)


@pytest.fixture
def empty_gtfo(tmp_path):
    """Build a GTFOBins instance from an empty JSON dict.

    This avoids loading the bundled data file and keeps the tests
    self-contained.
    """

    path = tmp_path / "empty.json"
    path.write_text("{}")
    return GTFOBins(str(path), which=lambda name, **_: None)


class TestCapabilityFlags:
    def test_all_contains_each(self):
        assert Capability.READ in Capability.ALL
        assert Capability.WRITE in Capability.ALL
        assert Capability.SHELL in Capability.ALL

    def test_none_is_falsy(self):
        assert not bool(Capability.NONE)


class TestStreamFlags:
    def test_any_contains_each(self):
        for member in (Stream.RAW, Stream.PRINT, Stream.HEX, Stream.BASE64):
            assert member in Stream.ANY

    def test_none_is_falsy(self):
        assert not bool(Stream.NONE)


class TestBinaryConstruction:
    def test_aggregates_capabilities(self, empty_gtfo):
        methods = [
            {"type": "READ", "stream": "PRINT", "payload": "cat {path}"},
            {"type": "WRITE", "stream": "RAW", "payload": "tee {path}"},
        ]

        binary = Binary(empty_gtfo, "cat", methods)

        assert Capability.READ in binary.caps
        assert Capability.WRITE in binary.caps
        assert Capability.SHELL not in binary.caps
        assert len(binary.methods) == 2

    def test_invalid_method_type_raises(self, empty_gtfo):
        with pytest.raises(RuntimeError):
            Binary(empty_gtfo, "broken", [{"type": "NOPE", "stream": "PRINT"}])

    def test_invalid_stream_raises(self, empty_gtfo):
        with pytest.raises(ValueError):
            Binary(empty_gtfo, "cat", [{"type": "READ", "stream": "INVALID"}])


class TestGtfobinsRegistry:
    def test_parse_binary_data_populates_dict(self, empty_gtfo):
        data = {
            "cat": [{"type": "READ", "stream": "PRINT", "payload": "cat {path}"}],
        }

        empty_gtfo.parse_binary_data(data)

        assert "cat" in empty_gtfo.binaries
        assert Capability.READ in empty_gtfo.binaries["cat"].caps

    def test_find_binary_returns_expected(self, empty_gtfo):
        empty_gtfo.parse_binary_data(
            {"cat": [{"type": "READ", "stream": "PRINT", "payload": "cat {path}"}]},
        )

        result = empty_gtfo.find_binary("/usr/bin/cat")

        assert result is empty_gtfo.binaries["cat"]

    def test_find_binary_missing_raises(self, empty_gtfo):
        with pytest.raises(BinaryNotFound):
            empty_gtfo.find_binary("/usr/bin/missing")

    def test_find_binary_cap_mismatch_raises(self, empty_gtfo):
        empty_gtfo.parse_binary_data(
            {"cat": [{"type": "READ", "stream": "PRINT", "payload": "cat {path}"}]},
        )

        with pytest.raises(BinaryNotFound):
            empty_gtfo.find_binary("/usr/bin/cat", caps=Capability.WRITE)


class TestMethodSudoArgs:
    def _make_method(self, gtfo, args=None):
        binary = Binary(
            gtfo,
            "cat",
            [{"type": "READ", "stream": "PRINT", "payload": "cat {path}"}],
        )
        method = binary.methods[0]
        if args is not None:
            method.args = args
        return binary, method

    def test_all_spec_returns_args(self, empty_gtfo):
        _, method = self._make_method(empty_gtfo, args=["-n"])
        path, args = method.sudo_args("/usr/bin/cat", "ALL")
        assert path == "/usr/bin/cat"
        assert args == ["-n"]

    def test_restricted_arg_raises(self, empty_gtfo):
        _, method = self._make_method(empty_gtfo)
        method.restricted = ["-r"]
        with pytest.raises(SudoNotPossible):
            method.sudo_args("/usr/bin/cat", "/usr/bin/cat -r")

    def test_missing_needed_arg_without_wildcard_raises(self, empty_gtfo):
        _, method = self._make_method(empty_gtfo, args=["-n"])
        with pytest.raises(SudoNotPossible):
            method.sudo_args("/usr/bin/cat", "/usr/bin/cat foo")

    def test_wildcard_spec_returns_command(self, empty_gtfo):
        # A trailing "*" without a leading space is a true wildcard and lets
        # the method inject its own args.
        _, method = self._make_method(empty_gtfo, args=["-n"])
        command, extra = method.sudo_args("/usr/bin/cat", "/usr/bin/cat*")
        assert command == "/usr/bin/cat"
        assert "-n" in extra

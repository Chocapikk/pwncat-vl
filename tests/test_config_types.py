"""
Unit tests for pwncat.config type coercers.

The Config object resolves user-provided strings into typed values via
small callables (``key_type``, ``bool_type``, ``local_file_type``,
``local_dir_type``) and a ``KeyType`` helper class. They are pure
functions so we can exercise them without spinning up a Manager.
"""

import os
import tempfile

import pytest

from pwncat.config import (
    KeyType,
    bool_type,
    key_type,
    local_dir_type,
    local_file_type,
)


class TestKeyTypeCallable:
    def test_single_char_returns_bytes(self):
        assert key_type("a") == b"a"

    def test_named_key_returns_escape_sequence(self):
        # c-k is "ctrl-k" in prompt_toolkit and maps to a known sequence
        result = key_type("c-k")
        assert isinstance(result, bytes)
        assert len(result) >= 1

    def test_invalid_named_key_raises(self):
        with pytest.raises(ValueError):
            key_type("not-a-real-key")


class TestKeyTypeClass:
    def test_single_char(self):
        key = KeyType("z")
        assert bytes(key) == b"z"
        assert key.name == "z"

    def test_named_key(self):
        key = KeyType("c-d")
        assert isinstance(bytes(key), bytes)
        assert key.name == "c-d"

    def test_invalid_named_key_raises(self):
        with pytest.raises(ValueError):
            KeyType("not-a-real-key")

    def test_repr_mentions_name(self):
        key = KeyType("a")
        assert "a" in repr(key)

    def test_equal_keys_share_bytes(self):
        assert bytes(KeyType("x")) == bytes(KeyType("x"))


class TestBoolType:
    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "True", "on", "ON"])
    def test_truthy_strings(self, value):
        assert bool_type(value) is True

    @pytest.mark.parametrize("value", ["0", "false", "FALSE", "False", "off", "OFF"])
    def test_falsy_strings(self, value):
        assert bool_type(value) is False

    def test_pass_through_real_bool(self):
        assert bool_type(True) is True
        assert bool_type(False) is False

    @pytest.mark.parametrize("value", ["maybe", "yes", "no", "2", ""])
    def test_invalid_raises(self, value):
        with pytest.raises(ValueError):
            bool_type(value)


class TestLocalFileType:
    def test_existing_file_is_returned_unchanged(self, tmp_path):
        target = tmp_path / "exists.txt"
        target.write_text("hi")
        assert local_file_type(str(target)) == str(target)

    def test_missing_path_raises(self, tmp_path):
        missing = tmp_path / "missing.txt"
        with pytest.raises(ValueError):
            local_file_type(str(missing))

    def test_directory_is_not_accepted(self, tmp_path):
        with pytest.raises(ValueError):
            local_file_type(str(tmp_path))


class TestLocalDirType:
    def test_existing_dir_is_returned(self, tmp_path):
        assert local_dir_type(str(tmp_path)) == str(tmp_path)

    def test_tilde_is_expanded(self):
        # Home directory should exist on the runner
        expanded = local_dir_type("~")
        assert expanded == os.path.expanduser("~")

    def test_missing_dir_raises(self, tmp_path):
        with pytest.raises(ValueError):
            local_dir_type(str(tmp_path / "nope"))

    def test_file_is_not_accepted(self, tmp_path):
        target = tmp_path / "file.txt"
        target.write_text("x")
        with pytest.raises(ValueError):
            local_dir_type(str(target))

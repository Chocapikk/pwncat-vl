"""
Unit tests for pwncat.util pure functions.

These tests target the deterministic, stateless helpers in util.py so we
have coverage for the small primitives that the rest of the codebase
depends on (sizing, escaping, quoting, formatting).
"""

import re
import string

import pytest

from pwncat import util


class TestHumanReadableSize:
    def test_bytes(self):
        assert util.human_readable_size(500) == "500.00B"

    def test_exact_kibibyte(self):
        # Regression: previously divided by 1000 while showing KiB suffix,
        # so 1024 rendered as "1.02KiB" instead of "1.00KiB".
        assert util.human_readable_size(1024) == "1.00KiB"

    def test_kibibyte_with_remainder(self):
        # 2048 bytes is exactly 2 KiB; the old impl returned "2.05KiB"
        # (2048 / 1000 = 2.048).
        assert util.human_readable_size(2048) == "2.00KiB"

    def test_megabytes(self):
        # 5 * 1024 * 1024 == 5 MiB exactly
        assert util.human_readable_size(5 * 1024 * 1024) == "5.00MiB"

    def test_below_1024_keeps_bytes(self):
        # Old impl switched to KiB at 1000; 1023 must still be bytes.
        assert util.human_readable_size(1023) == "1023.00B"

    def test_zero(self):
        assert util.human_readable_size(0) == "0.00B"

    def test_custom_decimal_places(self):
        assert util.human_readable_size(1500, decimal_places=0) == "1KiB"


class TestHumanReadableDelta:
    def test_under_a_minute(self):
        assert util.human_readable_delta(42) == "42.00 seconds"

    def test_minutes_and_seconds_integer_input(self):
        # 2 minutes and 5 seconds, integer input keeps int formatting
        assert util.human_readable_delta(125) == "2 minutes and 5 seconds"

    def test_float_input_does_not_leak_decimals(self):
        # Regression: float input used to render as ``1.0 minutes`` because
        # ``minutes = seconds // 60`` returns a float on a float ``seconds``.
        result = util.human_readable_delta(125.0)
        assert "1.0" not in result
        assert "minutes" in result and "seconds" in result

    def test_hours_minutes_seconds(self):
        # 3h 12m 7s
        result = util.human_readable_delta(3 * 3600 + 12 * 60 + 7)
        assert result == "3 hours, 12 minutes and 7 seconds"

    def test_hours_float_input(self):
        # 1h 1m 1s as float - must still render with int components
        result = util.human_readable_delta(3661.0)
        assert "1.0" not in result
        assert "hours" in result


class TestQuote:
    def test_no_whitespace_returns_unchanged(self):
        assert util.quote("hello") == "hello"

    def test_with_space_is_double_quoted(self):
        assert util.quote("hello world") == '"hello world"'

    def test_existing_double_quote_is_escaped(self):
        assert util.quote('say "hi"') == '"say \\"hi\\""'

    def test_double_quote_without_whitespace_is_escaped(self):
        # Regression: previously a token like ``a"b`` was returned
        # unchanged, breaking the surrounding shell command (``KEY=a"b``)
        # because the embedded quote unbalanced the parser. The function
        # must now quote+escape any embedded double quote even without
        # whitespace.
        assert util.quote('a"b') == '"a\\"b"'

    def test_empty_string(self):
        assert util.quote("") == ""


class TestJoin:
    def test_joins_simple_tokens(self):
        assert util.join(["a", "b", "c"]) == "a b c"

    def test_quotes_tokens_with_spaces(self):
        assert util.join(["echo", "hello world"]) == 'echo "hello world"'

    def test_empty_list(self):
        assert util.join([]) == ""


class TestStripAnsiEscape:
    def test_removes_color_sequence(self):
        assert util.strip_ansi_escape("\x1b[31mred\x1b[0m") == "red"

    def test_leaves_plain_text_alone(self):
        assert util.strip_ansi_escape("plain text") == "plain text"

    def test_handles_empty_string(self):
        assert util.strip_ansi_escape("") == ""


class TestEscapeMarkdown:
    @pytest.mark.parametrize(
        "char",
        list("\\`*_{}[]()#+!"),
    )
    def test_escapes_special_chars(self, char):
        assert util.escape_markdown(char) == "\\" + char

    def test_passes_normal_text(self):
        assert util.escape_markdown("hello world") == "hello world"


class TestIsPrintable:
    def test_printable_text(self):
        assert util.isprintable("hello world") is True

    def test_newline_is_printable(self):
        # The function explicitly treats newlines as printable
        assert util.isprintable("line1\nline2") is True

    def test_null_byte_not_printable(self):
        assert util.isprintable(b"\x00") is False

    def test_accepts_bytes(self):
        assert util.isprintable(b"abc") is True


class TestRandomString:
    def test_default_length(self):
        result = util.random_string()
        assert len(result) == 8

    def test_custom_length(self):
        assert len(util.random_string(16)) == 16

    def test_starts_with_letter(self):
        # First char must be a letter (per implementation)
        result = util.random_string(20)
        assert result[0] in string.ascii_letters

    def test_only_alphanumeric_chars(self):
        result = util.random_string(50)
        assert re.fullmatch(r"[A-Za-z][A-Za-z0-9]+", result) is not None

import pytest

from dotseal import parser
from dotseal.exceptions import ParseError


def test_parses_entries_comments_blanks():
    text = "# a comment\n\nFOO=bar\nexport BAZ=qux\n"
    parsed = parser.parse(text)
    kinds = [r.kind for r in parsed.records]
    assert kinds == ["comment", "blank", "entry", "entry"]
    entries = {e.key: e for e in parsed.entries()}
    assert entries["FOO"].value == "bar"
    assert entries["BAZ"].value == "qux"
    assert entries["BAZ"].export is True


def test_value_with_equals_sign():
    parsed = parser.parse("PASSWORD=!!@#$%=\n")
    assert parsed.entries()[0].value == "!!@#$%="


def test_whitespace_is_trimmed_around_unquoted():
    parsed = parser.parse("KEY =  value  \n")
    assert parsed.entries()[0].value == "value"


def test_double_quoted_preserves_whitespace_and_escapes():
    parsed = parser.parse('KEY="  a\\tb\\nc  "\n')
    assert parsed.entries()[0].value == "  a\tb\nc  "


def test_single_quoted_is_literal():
    parsed = parser.parse("KEY='no\\nescape'\n")
    assert parsed.entries()[0].value == "no\\nescape"


def test_format_value_quotes_only_when_needed():
    assert parser.format_value("simple") == "simple"
    assert parser.format_value("") == ""
    assert parser.format_value("has space") == '"has space"'
    assert parser.format_value("a\nb") == '"a\\nb"'
    assert parser.format_value(" trailing ") == '" trailing "'
    assert parser.format_value("with#hash") == '"with#hash"'


def test_serialize_roundtrip_for_simple_values():
    text = "# c\nFOO=bar\nexport BAZ=qux\n"
    parsed = parser.parse(text)
    assert parser.serialize(parsed) == text


def test_format_then_parse_roundtrip_special_values():
    for value in ["plain", "with space", "tab\there", "multi\nline", "!!@#$%="]:
        rendered = parser.format_value(value)
        parsed = parser.parse(f"K={rendered}\n")
        assert parsed.entries()[0].value == value


def test_invalid_line_raises():
    with pytest.raises(ParseError):
        parser.parse("this is not valid\n")


def test_serialize_blank_line():
    parsed = parser.parse("FOO=bar\n\nBAZ=qux\n")
    result = parser.serialize(parsed)
    assert result == "FOO=bar\n\nBAZ=qux\n"


def test_inline_comment_stripped_from_unquoted_value():
    parsed = parser.parse("FOO=bar # production key\n")
    entry = parsed.entries()[0]
    assert entry.value == "bar"
    assert entry.comment == " # production key"


def test_hash_without_leading_whitespace_stays_in_value():
    parsed = parser.parse("PASS=ab#cd\n")
    entry = parsed.entries()[0]
    assert entry.value == "ab#cd"
    assert entry.comment == ""


def test_inline_comment_roundtrip():
    text = "FOO=bar # note\nPASS=ab#cd\n"
    assert parser.serialize(parser.parse(text)) == text


def test_quoted_value_with_inline_comment():
    parsed = parser.parse('QUOTED="x" # after quote\n')
    entry = parsed.entries()[0]
    assert entry.value == "x"
    assert entry.comment == " # after quote"


def test_empty_value_when_only_inline_comment():
    parsed = parser.parse("FOO=  # comment only\n")
    entry = parsed.entries()[0]
    assert entry.value == ""
    assert entry.comment == "  # comment only"


def test_quoted_inline_comment_without_leading_space():
    parsed = parser.parse('FOO="x"# note\n')
    entry = parsed.entries()[0]
    assert entry.value == "x"
    assert entry.comment == " # note"


def test_unterminated_quote_falls_back_to_literal():
    parsed = parser.parse('FOO="unclosed\n')
    assert parsed.entries()[0].value == '"unclosed'


def test_quoted_value_with_trailing_junk_falls_back_to_literal():
    parsed = parser.parse('FOO="bar"trailing\n')
    assert parsed.entries()[0].value == '"bar"trailing'

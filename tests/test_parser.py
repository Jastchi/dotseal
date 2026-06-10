import pytest

from secure_dotenv import parser
from secure_dotenv.exceptions import ParseError


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

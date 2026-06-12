"""Structure-preserving parser for ``.env`` / ``.env.enc`` files.

The whole point of dotseal is *structural* encryption: keys stay in
cleartext, comments and blank lines are preserved, and only values change. To
make that possible the parser does not collapse a file into a ``dict`` -- it
keeps an ordered list of :class:`Record` objects so the document can be
faithfully re-serialized.

Value handling follows common ``.env`` conventions:

* ``export FOO=bar`` -- the optional ``export`` prefix is preserved.
* Whitespace around ``=`` and around an unquoted value is trimmed.
* Values may be wrapped in single or double quotes. Double-quoted values
  support ``\\n``, ``\\t``, ``\\r``, ``\\\\`` and ``\\"`` escapes (this is how
  multi-line values are represented on a single physical line). Single-quoted
  values are taken literally.
* The first ``=`` separates key and value, so values may themselves contain
  ``=`` (e.g. ``PASSWORD=!!@#$%=``).
* Inline comments are supported the way most dotenv tools do it: a ``#``
  preceded by whitespace (or following a closing quote) starts a comment and
  is *not* part of the value (``FOO=bar # prod key`` has the value ``bar``).
  A ``#`` with no whitespace before it stays in the value
  (``PASS=ab#cd`` is the value ``ab#cd``). Inline comments are preserved on
  re-serialization.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .exceptions import ParseError

# Matches an optional `export ` prefix followed by KEY=...
_ENTRY_RE = re.compile(
    r"""^(?P<export>export\s+)?      # optional export prefix
         (?P<key>[A-Za-z_][A-Za-z0-9_.]*)   # variable name
         \s*=                         # separator
         (?P<value>.*)$               # everything after the first =
    """,
    re.VERBOSE | re.DOTALL,
)


@dataclass
class Record:
    """A single logical line of the document."""

    kind: str  # 'blank' | 'comment' | 'entry'
    raw: str = ""  # verbatim text for blank/comment records
    key: str = ""
    value: str = ""  # logical (unquoted) value, or an ENC[...] token
    export: bool = False
    comment: str = ""  # inline comment suffix incl. leading whitespace ('' if none)


@dataclass
class ParsedEnv:
    records: List[Record]

    def entries(self) -> List[Record]:
        return [r for r in self.records if r.kind == "entry"]


# --- Value decoding / encoding ----------------------------------------------

_DOUBLE_UNESCAPE = {
    "\\n": "\n",
    "\\t": "\t",
    "\\r": "\r",
    '\\"': '"',
    "\\\\": "\\",
}

_DOUBLE_ESCAPE = {
    "\\": "\\\\",
    '"': '\\"',
    "\n": "\\n",
    "\t": "\\t",
    "\r": "\\r",
}


# A '#' preceded by whitespace starts an inline comment in an unquoted value.
_INLINE_COMMENT_RE = re.compile(r"\s+#")


def _find_closing_quote(text: str, quote: str) -> Optional[int]:
    """Index of the quote that closes ``text[0]``, or None if unterminated."""
    i = 1
    while i < len(text):
        char = text[i]
        if quote == '"' and char == "\\":
            i += 2
            continue
        if char == quote:
            return i
        i += 1
    return None


def _split_value(raw: str) -> Tuple[str, str]:
    """Split the raw text after ``=`` into (logical value, inline comment).

    The comment (if any) is returned with its leading whitespace and ``#`` so
    it can be re-serialized verbatim; it is ``""`` when absent.
    """
    lstripped = raw.lstrip()
    if lstripped.startswith("#") and lstripped != raw:
        # Whitespace then '#': the whole remainder is a comment, value empty.
        return "", raw.rstrip()
    value = raw.strip()
    if value[:1] in ("'", '"'):
        quote = value[0]
        end = _find_closing_quote(value, quote)
        if end is not None:
            rest = value[end + 1:]
            rest_l = rest.lstrip()
            if rest_l == "" or rest_l.startswith("#"):
                inner = value[1:end]
                logical = _unescape_double(inner) if quote == '"' else inner
                if rest_l == "":
                    return logical, ""
                # Guarantee a whitespace separator so the comment cannot fuse
                # with the value on re-serialization.
                comment = rest if rest[0] in (" ", "\t") else " " + rest
                return logical, comment
        # Unterminated quote or trailing junk after the closing quote:
        # fall through and treat the whole thing as an unquoted literal.
    match = _INLINE_COMMENT_RE.search(value)
    if match:
        return value[: match.start()], value[match.start():]
    return value, ""


def _unescape_double(inner: str) -> str:
    out = []
    i = 0
    while i < len(inner):
        two = inner[i : i + 2]
        if two in _DOUBLE_UNESCAPE:
            out.append(_DOUBLE_UNESCAPE[two])
            i += 2
        else:
            out.append(inner[i])
            i += 1
    return "".join(out)


def format_value(value: str) -> str:
    """Render a logical value back to a safe on-disk representation.

    Quotes (and escapes) the value only when necessary so simple values stay
    diff-friendly and unquoted.
    """
    if value == "":
        return ""
    needs_quoting = (
        value != value.strip()  # leading/trailing whitespace
        or any(c in value for c in (" ", "\t", "#", "\n", "\r", '"', "'"))
    )
    if not needs_quoting:
        return value
    escaped = "".join(_DOUBLE_ESCAPE.get(c, c) for c in value)
    return f'"{escaped}"'


# --- Parsing ----------------------------------------------------------------

def parse(text: str) -> ParsedEnv:
    """Parse the full text of a ``.env``/``.env.enc`` file into records."""
    records: List[Record] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped == "":
            records.append(Record(kind="blank", raw=""))
            continue
        if stripped.startswith("#"):
            records.append(Record(kind="comment", raw=line))
            continue
        match = _ENTRY_RE.match(line)
        if not match:
            raise ParseError(
                f"Line {lineno}: could not parse entry: {line!r}"
            )
        key = match.group("key")
        value, comment = _split_value(match.group("value"))
        records.append(
            Record(
                kind="entry",
                key=key,
                value=value,
                export=bool(match.group("export")),
                comment=comment,
            )
        )
    return ParsedEnv(records=records)


def serialize(parsed: ParsedEnv) -> str:
    """Serialize records back to file text (values rendered via ``format_value``).

    Entry values are written verbatim (already-final form -- either an ENC[...]
    token or an already-formatted cleartext value). Use :func:`format_value`
    before assigning cleartext values you want safely quoted.
    """
    lines: List[str] = []
    for r in parsed.records:
        if r.kind == "blank":
            lines.append("")
        elif r.kind == "comment":
            lines.append(r.raw)
        elif r.kind == "entry":
            prefix = "export " if r.export else ""
            lines.append(f"{prefix}{r.key}={r.value}{r.comment}")
        else:  # pragma: no cover - defensive
            raise ParseError(f"Unknown record kind: {r.kind!r}")
    return "\n".join(lines) + "\n"

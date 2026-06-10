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
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

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


def _unquote(raw: str) -> str:
    """Turn a raw on-disk value into its logical string value."""
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        inner = value[1:-1]
        if value[0] == '"':
            return _unescape_double(inner)
        return inner  # single quotes: literal
    return value


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
        raw_value = match.group("value")
        records.append(
            Record(
                kind="entry",
                key=key,
                value=_unquote(raw_value),
                export=bool(match.group("export")),
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
            lines.append(f"{prefix}{r.key}={r.value}")
        else:  # pragma: no cover - defensive
            raise ParseError(f"Unknown record kind: {r.kind!r}")
    return "\n".join(lines) + "\n"

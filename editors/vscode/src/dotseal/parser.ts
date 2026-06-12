import { ParseError } from "./errors";

export type RecordKind = "blank" | "comment" | "entry";

export interface Record {
  kind: RecordKind;
  raw: string;
  key: string;
  value: string;
  export: boolean;
  /** Inline comment suffix incl. leading whitespace ("" if none). */
  comment: string;
}

export interface ParsedEnv {
  records: Record[];
}

const ENTRY_RE = /^(export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=(.*)$/s;

const DOUBLE_UNESCAPE = new Map<string, string>([
  ["\\n", "\n"],
  ["\\t", "\t"],
  ["\\r", "\r"],
  ['\\"', '"'],
  ["\\\\", "\\"]
]);

const DOUBLE_ESCAPE = new Map<string, string>([
  ["\\", "\\\\"],
  ['"', '\\"'],
  ["\n", "\\n"],
  ["\t", "\\t"],
  ["\r", "\\r"]
]);

function blankRecord(): Record {
  return { kind: "blank", raw: "", key: "", value: "", export: false, comment: "" };
}

function commentRecord(raw: string): Record {
  return { kind: "comment", raw, key: "", value: "", export: false, comment: "" };
}

function entryRecord(
  key: string,
  value: string,
  hasExport: boolean,
  comment: string
): Record {
  return { kind: "entry", raw: "", key, value, export: hasExport, comment };
}

// A '#' preceded by whitespace starts an inline comment in an unquoted value.
const INLINE_COMMENT_RE = /\s+#/;

/** Index of the quote that closes `text[0]`, or undefined if unterminated. */
function findClosingQuote(text: string, quote: string): number | undefined {
  let i = 1;
  while (i < text.length) {
    const char = text[i];
    if (quote === '"' && char === "\\") {
      i += 2;
      continue;
    }
    if (char === quote) {
      return i;
    }
    i += 1;
  }
  return undefined;
}

/**
 * Split the raw text after `=` into the logical value and an inline comment.
 * The comment (if any) keeps its leading whitespace and `#` so it can be
 * re-serialized verbatim; it is "" when absent. Mirrors the Python parser.
 */
function splitValue(raw: string): { value: string; comment: string } {
  const lstripped = raw.replace(/^\s+/, "");
  if (lstripped.startsWith("#") && lstripped !== raw) {
    // Whitespace then '#': the whole remainder is a comment, value empty.
    return { value: "", comment: raw.replace(/\s+$/, "") };
  }
  const value = raw.trim();
  if (value[0] === "'" || value[0] === '"') {
    const quote = value[0];
    const end = findClosingQuote(value, quote);
    if (end !== undefined) {
      const rest = value.slice(end + 1);
      const restL = rest.replace(/^\s+/, "");
      if (restL === "" || restL.startsWith("#")) {
        const inner = value.slice(1, end);
        const logical = quote === '"' ? unescapeDouble(inner) : inner;
        if (restL === "") {
          return { value: logical, comment: "" };
        }
        // Guarantee a whitespace separator so the comment cannot fuse with
        // the value on re-serialization.
        const comment = rest[0] === " " || rest[0] === "\t" ? rest : ` ${rest}`;
        return { value: logical, comment };
      }
    }
    // Unterminated quote or trailing junk after the closing quote:
    // fall through and treat the whole thing as an unquoted literal.
  }
  const match = INLINE_COMMENT_RE.exec(value);
  if (match !== null) {
    return { value: value.slice(0, match.index), comment: value.slice(match.index) };
  }
  return { value, comment: "" };
}

function unescapeDouble(inner: string): string {
  const out: string[] = [];
  let i = 0;
  while (i < inner.length) {
    const two = inner.slice(i, i + 2);
    const replacement = DOUBLE_UNESCAPE.get(two);
    if (replacement !== undefined) {
      out.push(replacement);
      i += 2;
    } else {
      out.push(inner[i] ?? "");
      i += 1;
    }
  }
  return out.join("");
}

export function formatValue(value: string): string {
  if (value === "") {
    return "";
  }

  const needsQuoting =
    value !== value.trim() ||
    [...value].some((char) => [" ", "\t", "#", "\n", "\r", '"', "'"].includes(char));

  if (!needsQuoting) {
    return value;
  }

  const escaped = [...value]
    .map((char) => DOUBLE_ESCAPE.get(char) ?? char)
    .join("");
  return `"${escaped}"`;
}

export function parse(text: string): ParsedEnv {
  const records: Record[] = [];
  const lines = text.split(/\r?\n/);
  if (lines.length > 0 && lines[lines.length - 1] === "") {
    lines.pop();
  }

  lines.forEach((line, index) => {
    const stripped = line.trim();
    if (stripped === "") {
      records.push(blankRecord());
      return;
    }

    if (stripped.startsWith("#")) {
      records.push(commentRecord(line));
      return;
    }

    const match = ENTRY_RE.exec(line);
    if (match === null) {
      throw new ParseError(`Line ${index + 1}: could not parse entry: ${JSON.stringify(line)}`);
    }

    const [, exportPrefix, key, rawValue] = match;
    const { value, comment } = splitValue(rawValue ?? "");
    records.push(entryRecord(key ?? "", value, exportPrefix !== undefined, comment));
  });

  return { records };
}

export function serialize(parsed: ParsedEnv): string {
  const lines = parsed.records.map((record) => {
    switch (record.kind) {
      case "blank":
        return "";
      case "comment":
        return record.raw;
      case "entry": {
        const prefix = record.export ? "export " : "";
        return `${prefix}${record.key}=${record.value}${record.comment}`;
      }
      default:
        throw new ParseError(`Unknown record kind: ${(record as { kind: string }).kind}`);
    }
  });

  return `${lines.join("\n")}\n`;
}

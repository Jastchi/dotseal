import { ParseError } from "./errors";

export type RecordKind = "blank" | "comment" | "entry";

export interface Record {
  kind: RecordKind;
  raw: string;
  key: string;
  value: string;
  export: boolean;
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
  return { kind: "blank", raw: "", key: "", value: "", export: false };
}

function commentRecord(raw: string): Record {
  return { kind: "comment", raw, key: "", value: "", export: false };
}

function entryRecord(key: string, value: string, hasExport: boolean): Record {
  return { kind: "entry", raw: "", key, value, export: hasExport };
}

function unquote(raw: string): string {
  const value = raw.trim();
  if (
    value.length >= 2 &&
    value[0] === value[value.length - 1] &&
    (value[0] === "'" || value[0] === '"')
  ) {
    const inner = value.slice(1, -1);
    if (value[0] === '"') {
      return unescapeDouble(inner);
    }
    return inner;
  }
  return value;
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
    records.push(entryRecord(key ?? "", unquote(rawValue ?? ""), exportPrefix !== undefined));
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
        return `${prefix}${record.key}=${record.value}`;
      }
      default:
        throw new ParseError(`Unknown record kind: ${(record as { kind: string }).kind}`);
    }
  });

  return `${lines.join("\n")}\n`;
}

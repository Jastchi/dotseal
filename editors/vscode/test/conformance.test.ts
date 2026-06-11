import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { decryptText, encryptText } from "../src/dotseal/core";
import {
  decryptValue,
  encryptValue,
  keyFingerprint,
  loadKeyBytes
} from "../src/dotseal/crypto";
import { findKeyFile } from "../src/dotseal/keys";
import { formatValue, parse, serialize } from "../src/dotseal/parser";
import {
  pythonDecryptText,
  pythonDecryptValue,
  pythonEncryptText,
  pythonEncryptValue,
  pythonFindKeyFile,
  pythonFingerprint,
  pythonFormatValue,
  pythonParse,
  pythonSerialize
} from "./python-client";

const keyString = Buffer.alloc(32, 1).toString("base64");
const keyBytes = loadKeyBytes(keyString);

const PARSER_FIXTURES = [
  "# a comment\n\nFOO=bar\nexport BAZ=qux\n",
  "PASSWORD=!!@#$%=\n",
  "KEY =  value  \n",
  'KEY="  a\\tb\\nc  "\n',
  "KEY='no\\nescape'\n",
  "# hello\nexport API_KEY = \"line\\nvalue\"\nEMPTY=\n\n"
];

const FORMAT_VALUES = [
  "simple",
  "",
  "has space",
  "a\nb",
  " trailing ",
  "with#hash",
  "!!@#$%=",
  "héllo wörld",
  "tab\there",
  "multi\nline"
];

const CRYPTO_VALUES = ["", "!!@#$%=", "héllo wörld", "a".repeat(5000), "line1\nline2"];

const ENCRYPT_FIXTURES = [
  "# user comment\nDATABASE_URL=postgres://example\nDEBUG=True\n",
  "API_KEY=secret\nEMPTY=\n",
  "A=1\n\n",
  "# banner\n# dotseal: v=1 alg=AES_GCM key_fp=deadbeef\nSECRET=already\n",
  'export HOST="my host"\nPORT=8080\nQUOTED="a\\nb"\n',
  "# keep me\n\nFOO=bar\n# tail\n"
];

function normalizeEncrypted(text: string): string {
  return text.replace(/ENC\[AES_GCM,data:[^\]]+\]/g, "ENC[PLACEHOLDER]");
}

describe("Python conformance: crypto", () => {
  it("agrees on key fingerprints", () => {
    expect(keyFingerprint(keyBytes)).toBe(pythonFingerprint(keyString));
  });

  it.each(CRYPTO_VALUES)("cross-decrypts values (%j)", (value) => {
    const fromPython = pythonEncryptValue(keyString, value, "TEST_KEY");
    const fromTypeScript = encryptValue(keyBytes, value, "TEST_KEY");

    expect(decryptValue(keyBytes, fromPython, "TEST_KEY")).toBe(value);
    expect(pythonDecryptValue(keyString, fromTypeScript, "TEST_KEY")).toBe(value);
  });
});

describe("Python conformance: parser", () => {
  it.each(FORMAT_VALUES)("agrees on format_value (%j)", (value) => {
    expect(formatValue(value)).toBe(pythonFormatValue(value));
  });

  it.each(PARSER_FIXTURES)("agrees on parse output", (text) => {
    expect(parse(text).records).toEqual(pythonParse(text));
  });

  it.each(PARSER_FIXTURES)("agrees on serialize(parse(text))", (text) => {
    expect(serialize(parse(text))).toBe(pythonSerialize(text));
  });
});

describe("Python conformance: core", () => {
  it.each(ENCRYPT_FIXTURES)(
    "round-trips to identical cleartext in both implementations",
    (cleartext) => {
      const pythonRoundTrip = pythonDecryptText(
        keyString,
        pythonEncryptText(keyString, cleartext)
      );
      const typeScriptRoundTrip = decryptText(
        encryptText(cleartext, keyBytes),
        keyBytes
      );

      expect(typeScriptRoundTrip).toBe(pythonRoundTrip);
    }
  );

  it.each(ENCRYPT_FIXTURES)(
    "decrypts Python-encrypted text with TypeScript",
    (cleartext) => {
      const encrypted = pythonEncryptText(keyString, cleartext);

      expect(decryptText(encrypted, keyBytes)).toBe(pythonDecryptText(keyString, encrypted));
    }
  );

  it.each(ENCRYPT_FIXTURES)(
    "decrypts TypeScript-encrypted text with Python",
    (cleartext) => {
      const encrypted = encryptText(cleartext, keyBytes);

      expect(pythonDecryptText(keyString, encrypted)).toBe(decryptText(encrypted, keyBytes));
    }
  );

  it.each(ENCRYPT_FIXTURES)(
    "produces the same encrypted file structure",
    (cleartext) => {
      const fromPython = normalizeEncrypted(pythonEncryptText(keyString, cleartext));
      const fromTypeScript = normalizeEncrypted(encryptText(cleartext, keyBytes));

      expect(fromTypeScript).toBe(fromPython);
    }
  );
});

describe("Python conformance: key discovery", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dotseal-conformance-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("finds the same .dotseal.key file walking upward", () => {
    const keyPath = path.join(tmpDir, ".dotseal.key");
    fs.writeFileSync(keyPath, keyString);
    const nested = path.join(tmpDir, "apps", "api");
    fs.mkdirSync(nested, { recursive: true });

    expect(findKeyFile(nested)).toBe(pythonFindKeyFile(nested));
    expect(findKeyFile(nested)).toBe(keyPath);
  });
});

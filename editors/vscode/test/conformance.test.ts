import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { decryptText, encryptText, reencryptText } from "../src/dotseal/core";
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
  pythonReencryptText,
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
  "# hello\nexport API_KEY = \"line\\nvalue\"\nEMPTY=\n\n",
  "FOO=bar # production key\nPASS=ab#cd\n",
  'QUOTED="x" # after quote\n'
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

const REENCRYPT_FIXTURES = [
  {
    original: "KEEP=same\nCHANGE=old\n",
    edited: "KEEP=same\nCHANGE=new\n",
    unchangedKey: "KEEP"
  },
  {
    original: "# user comment\nDATABASE_URL=postgres://example\nDEBUG=True\n",
    edited: "# user comment\nDATABASE_URL=postgres://updated\nDEBUG=True\n",
    unchangedKey: "DEBUG"
  },
  {
    original: "API_KEY=secret\nEMPTY=\n",
    edited: "API_KEY=rotated\nEMPTY=\n",
    unchangedKey: "EMPTY"
  },
  {
    original: "# keep me\n\nFOO=bar\n# tail\n",
    edited: "# keep me\n\nFOO=baz\n# tail\n",
    unchangedKey: undefined
  }
];

function normalizeEncrypted(text: string): string {
  return text.replace(/ENC\[AES_GCM,data:[^\]]+\]/g, "ENC[PLACEHOLDER]");
}

function entryToken(text: string, key: string): string | undefined {
  const record = parse(text).records.find(
    (entry) => entry.kind === "entry" && entry.key === key
  );
  return record?.value;
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

describe("Python conformance: reencryptText", () => {
  it.each(REENCRYPT_FIXTURES)(
    "produces the same re-encrypted file structure",
    ({ original, edited }) => {
      const encrypted = pythonEncryptText(keyString, original);
      const fromPython = normalizeEncrypted(
        pythonReencryptText(keyString, edited, encrypted)
      );
      const fromTypeScript = normalizeEncrypted(
        reencryptText(edited, keyBytes, encrypted)
      );

      expect(fromTypeScript).toBe(fromPython);
    }
  );

  it.each(REENCRYPT_FIXTURES)(
    "decrypts re-encrypted output to the edited cleartext in both implementations",
    ({ original, edited }) => {
      const encrypted = pythonEncryptText(keyString, original);
      const fromPython = pythonReencryptText(keyString, edited, encrypted);
      const fromTypeScript = reencryptText(edited, keyBytes, encrypted);

      expect(decryptText(fromTypeScript, keyBytes)).toBe(edited);
      expect(pythonDecryptText(keyString, fromPython)).toBe(edited);
    }
  );

  it.each(
    REENCRYPT_FIXTURES.filter(
      (fixture): fixture is typeof fixture & { unchangedKey: string } =>
        fixture.unchangedKey !== undefined
    )
  )(
    "reuses identical ciphertext tokens for unchanged values (%s)",
    ({ original, edited, unchangedKey }) => {
      const encrypted = pythonEncryptText(keyString, original);
      const fromPython = pythonReencryptText(keyString, edited, encrypted);
      const fromTypeScript = reencryptText(edited, keyBytes, encrypted);

      expect(entryToken(fromTypeScript, unchangedKey)).toBe(
        entryToken(fromPython, unchangedKey)
      );
      expect(entryToken(fromTypeScript, unchangedKey)).toBe(
        entryToken(encrypted, unchangedKey)
      );
    }
  );

  it.each(REENCRYPT_FIXTURES)(
    "agrees on re-encryption structure for TypeScript-encrypted originals",
    ({ original, edited }) => {
      const encrypted = encryptText(original, keyBytes);
      const fromPython = normalizeEncrypted(
        pythonReencryptText(keyString, edited, encrypted)
      );
      const fromTypeScript = normalizeEncrypted(
        reencryptText(edited, keyBytes, encrypted)
      );

      expect(fromTypeScript).toBe(fromPython);
    }
  );

  it.each(REENCRYPT_FIXTURES)(
    "decrypts Python-reencrypted output with TypeScript",
    ({ original, edited }) => {
      const encrypted = encryptText(original, keyBytes);

      expect(decryptText(pythonReencryptText(keyString, edited, encrypted), keyBytes)).toBe(
        edited
      );
    }
  );

  it.each(REENCRYPT_FIXTURES)(
    "decrypts TypeScript-reencrypted output with Python",
    ({ original, edited }) => {
      const encrypted = pythonEncryptText(keyString, original);

      expect(
        pythonDecryptText(keyString, reencryptText(edited, keyBytes, encrypted))
      ).toBe(edited);
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

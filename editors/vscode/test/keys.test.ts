import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MasterKeyNotFoundError } from "../src/dotseal/errors";
import { findKeyFile, resolveMasterKey } from "../src/dotseal/keys";

const keyString = Buffer.alloc(32, 1).toString("base64");

describe("keys", () => {
  let tmpDir: string;
  const originalEnv = process.env.DOTSEAL_MASTER_KEY;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dotseal-keys-"));
    delete process.env.DOTSEAL_MASTER_KEY;
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    if (originalEnv === undefined) {
      delete process.env.DOTSEAL_MASTER_KEY;
    } else {
      process.env.DOTSEAL_MASTER_KEY = originalEnv;
    }
  });

  it("findKeyFile discovers a key in a parent directory", () => {
    fs.writeFileSync(path.join(tmpDir, ".dotseal.key"), keyString);
    const nested = path.join(tmpDir, "apps", "api");
    fs.mkdirSync(nested, { recursive: true });

    expect(findKeyFile(nested)).toBe(path.join(tmpDir, ".dotseal.key"));
  });

  it("findKeyFile returns undefined when no key exists", () => {
    expect(findKeyFile(tmpDir)).toBeUndefined();
  });

  it("resolveMasterKey prefers the masterKey setting", () => {
    fs.writeFileSync(path.join(tmpDir, ".dotseal.key"), "from-file");

    expect(resolveMasterKey(tmpDir, { masterKey: keyString })).toBe(keyString);
  });

  it("resolveMasterKey reads an explicit key file path", () => {
    const keyFile = path.join(tmpDir, "custom.key");
    fs.writeFileSync(keyFile, `  ${keyString}  `);

    expect(resolveMasterKey(tmpDir, { keyFile })).toBe(keyString);
  });

  it("resolveMasterKey expands a tilde key file path", () => {
    const homeKey = path.join(os.homedir(), `.dotseal-test-${process.pid}`);
    fs.writeFileSync(homeKey, keyString);
    try {
      expect(resolveMasterKey(tmpDir, { keyFile: `~/${path.basename(homeKey)}` })).toBe(keyString);
    } finally {
      fs.unlinkSync(homeKey);
    }
  });

  it("resolveMasterKey falls back to DOTSEAL_MASTER_KEY", () => {
    process.env.DOTSEAL_MASTER_KEY = `  ${keyString}  `;

    expect(resolveMasterKey(tmpDir)).toBe(keyString);
  });

  it("resolveMasterKey discovers a local .dotseal.key file", () => {
    fs.writeFileSync(path.join(tmpDir, ".dotseal.key"), keyString);

    expect(resolveMasterKey(tmpDir)).toBe(keyString);
  });

  it("throws MasterKeyNotFoundError when no key source exists", () => {
    expect(() => resolveMasterKey(tmpDir)).toThrow(MasterKeyNotFoundError);
  });
});

describe("keys explicit keyFile", () => {
  let tmpDir: string;
  const originalEnv = process.env.DOTSEAL_MASTER_KEY;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dotseal-keyfile-"));
    delete process.env.DOTSEAL_MASTER_KEY;
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    if (originalEnv === undefined) {
      delete process.env.DOTSEAL_MASTER_KEY;
    } else {
      process.env.DOTSEAL_MASTER_KEY = originalEnv;
    }
  });

  it("throws when an explicitly configured key file is missing", () => {
    process.env.DOTSEAL_MASTER_KEY = keyString; // must NOT be used as fallback

    expect(() =>
      resolveMasterKey(tmpDir, { keyFile: path.join(tmpDir, "missing.key") })
    ).toThrow(MasterKeyNotFoundError);
  });

  it("explicit key file beats the environment variable", () => {
    const fileKey = Buffer.alloc(32, 3).toString("base64");
    const keyFile = path.join(tmpDir, "explicit.key");
    fs.writeFileSync(keyFile, fileKey);
    process.env.DOTSEAL_MASTER_KEY = keyString;

    expect(resolveMasterKey(tmpDir, { keyFile })).toBe(fileKey);
  });
});

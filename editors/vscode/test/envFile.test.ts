import { describe, expect, it } from "vitest";
import { isEncryptedEnvBasename, isEncryptedEnvFile } from "../src/envFile";

describe("isEncryptedEnvBasename", () => {
  it.each([
    ".env.enc",
    ".env.local.enc",
    ".env.production.enc",
    ".env.development.enc",
    ".env.staging.enc",
    ".env.test.enc",
    ".env.development.local.enc",
    ".env.production.local.enc"
  ])("accepts %s", (name) => {
    expect(isEncryptedEnvBasename(name)).toBe(true);
  });

  it.each([
    ".env",
    ".env.local",
    ".env.production",
    "env.enc",
    "secrets.env.enc",
    "brand-new.env.enc",
    ".environment.enc",
    ".env.enc.bak",
    "not-env.enc"
  ])("rejects %s", (name) => {
    expect(isEncryptedEnvBasename(name)).toBe(false);
  });
});

describe("isEncryptedEnvFile", () => {
  function makeFileUri(fsPath: string): { scheme: string; fsPath: string } {
    return { scheme: "file", fsPath };
  }

  it("accepts file URIs with dotenv-style encrypted basenames", () => {
    const uri = makeFileUri("/repo/apps/mobile/.env.production.enc");
    expect(isEncryptedEnvFile(uri as Parameters<typeof isEncryptedEnvFile>[0])).toBe(true);
  });

  it("rejects non-file schemes", () => {
    const uri = { scheme: "dotseal", fsPath: "/repo/.env.enc" };
    expect(isEncryptedEnvFile(uri as Parameters<typeof isEncryptedEnvFile>[0])).toBe(false);
  });

  it("rejects non-dotenv-style basenames", () => {
    const uri = makeFileUri("/repo/secrets.env.enc");
    expect(isEncryptedEnvFile(uri as Parameters<typeof isEncryptedEnvFile>[0])).toBe(false);
  });
});

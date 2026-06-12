import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type * as vscode from "vscode";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { encryptText } from "../src/dotseal/core";
import { loadKeyBytes } from "../src/dotseal/crypto";
import { DotsealError, MasterKeyNotFoundError } from "../src/dotseal/errors";

const { MockFileSystemError, makeDotsealUri, makeFileUri } = vi.hoisted(() => {
  class MockFileSystemError extends Error {
    constructor(message: string) {
      super(message);
      this.name = "FileSystemError";
    }

    static Unavailable(message: string): MockFileSystemError {
      return new MockFileSystemError(message);
    }

    static FileNotFound(message: string): MockFileSystemError {
      return new MockFileSystemError(message);
    }

    static NoPermissions(message: string): MockFileSystemError {
      return new MockFileSystemError(message);
    }
  }

  function makeUri(scheme: string, fsPath: string): vscode.Uri {
    return {
      scheme,
      fsPath,
      with(changes: { scheme?: string }) {
        return makeUri(changes.scheme ?? scheme, fsPath);
      }
    } as vscode.Uri;
  }

  return {
    MockFileSystemError,
    makeFileUri: (fsPath: string): vscode.Uri => makeUri("file", fsPath),
    makeDotsealUri: (fsPath: string): vscode.Uri => makeUri("dotseal", fsPath)
  };
});

vi.mock("vscode", () => ({
  FileSystemError: MockFileSystemError,
  FileType: { File: 1, Directory: 2 },
  FileChangeType: { Changed: 1, Created: 2 },
  EventEmitter: class<T> {
    private listener: ((value: T) => void) | undefined;

    event = (listener: (value: T) => void): { dispose: () => void } => {
      this.listener = listener;
      return { dispose: () => undefined };
    };

    fire(value: T): void {
      this.listener?.(value);
    }
  },
  Disposable: class {
    constructor(private readonly disposeFn: () => void) {}
    dispose(): void {
      this.disposeFn();
    }
  },
  Uri: {
    file(fsPath: string) {
      return makeFileUri(fsPath);
    }
  }
}));

import {
  DotsealFsProvider,
  fileSystemError,
  fromDotsealUri,
  toDotsealUri
} from "../src/provider";

const keyString = Buffer.alloc(32, 1).toString("base64");
const keyBytes = loadKeyBytes(keyString);

describe("provider URI helpers", () => {
  it("maps file URIs to dotseal URIs", () => {
    const fileUri = makeFileUri("/tmp/project/.env.enc");

    expect(toDotsealUri(fileUri).scheme).toBe("dotseal");
    expect(toDotsealUri(fileUri).fsPath).toBe("/tmp/project/.env.enc");
  });

  it("rejects unsupported URI schemes", () => {
    expect(() => fromDotsealUri(makeFileUri("/tmp/project/.env.enc"))).toThrow(
      "Unsupported URI scheme: file"
    );
  });

  it("maps dotseal errors to vscode file system errors", () => {
    const error = fileSystemError(new MasterKeyNotFoundError("missing key"));

    expect(error).toBeInstanceOf(MockFileSystemError);
    expect(error.message).toBe("missing key");
  });

  it("maps ENOENT errors to file-not-found errors", () => {
    const error = fileSystemError(Object.assign(new Error("missing"), { code: "ENOENT" }));

    expect(error.message).toContain("missing");
  });
});

describe("DotsealFsProvider", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dotseal-provider-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("decrypts on read and encrypts on write", () => {
    const cleartext = "API_KEY=secret\nDEBUG=true\n";
    const encPath = path.join(tmpDir, ".env.enc");
    fs.writeFileSync(encPath, encryptText(cleartext, keyBytes), "utf8");

    const provider = new DotsealFsProvider(() => ({ masterKey: keyString }));
    const uri = makeDotsealUri(encPath);

    expect(Buffer.from(provider.readFile(uri)).toString("utf8")).toBe(cleartext);

    const updated = "API_KEY=rotated\nDEBUG=false\n";
    provider.writeFile(uri, Buffer.from(updated, "utf8"), { create: false, overwrite: true });

    expect(Buffer.from(provider.readFile(uri)).toString("utf8")).toBe(updated);
    expect(fs.readFileSync(encPath, "utf8")).toContain("API_KEY=ENC[AES_GCM,data:");
  });

  it("rejects write when the file is missing and create is false", () => {
    const provider = new DotsealFsProvider(() => ({ masterKey: keyString }));
    const uri = makeDotsealUri(path.join(tmpDir, "missing.env.enc"));

    expect(() =>
      provider.writeFile(uri, Buffer.from("A=1\n", "utf8"), { create: false, overwrite: true })
    ).toThrow(MockFileSystemError);
  });

  it("rejects overwrite when create and overwrite are both false", () => {
    const encPath = path.join(tmpDir, ".env.enc");
    fs.writeFileSync(encPath, encryptText("A=1\n", keyBytes), "utf8");
    const provider = new DotsealFsProvider(() => ({ masterKey: keyString }));
    const uri = makeDotsealUri(encPath);

    expect(() =>
      provider.writeFile(uri, Buffer.from("A=2\n", "utf8"), { create: true, overwrite: false })
    ).toThrow(MockFileSystemError);
  });

  it("creates a new encrypted file when create is true", () => {
    const encPath = path.join(tmpDir, "new.env.enc");
    const provider = new DotsealFsProvider(() => ({ masterKey: keyString }));
    const uri = makeDotsealUri(encPath);
    const cleartext = "NEW=value\n";
    const events: Array<{ type: number }> = [];
    provider.onDidChangeFile((changes) => {
      events.push(...changes);
    });

    provider.writeFile(uri, Buffer.from(cleartext, "utf8"), { create: true, overwrite: false });

    expect(fs.existsSync(encPath)).toBe(true);
    expect(Buffer.from(provider.readFile(uri)).toString("utf8")).toBe(cleartext);
    expect(events.some((event) => event.type === 2)).toBe(true);
  });

  it("surfaces dotseal errors from readFile", () => {
    const provider = new DotsealFsProvider(() => ({ masterKey: "" }));
    const uri = makeDotsealUri(path.join(tmpDir, "missing.env.enc"));

    expect(() => provider.readFile(uri)).toThrow(MockFileSystemError);
  });

  it("rejects directory operations", () => {
    const provider = new DotsealFsProvider(() => ({ masterKey: keyString }));

    expect(() => provider.readDirectory()).toThrow("directories are not supported");
    expect(() => provider.delete()).toThrow("Delete the real .env.enc file directly");
  });

  it("maps unknown provider errors through fileSystemError", () => {
    const error = fileSystemError(new DotsealError("boom"));

    expect(error.message).toBe("boom");
  });
});

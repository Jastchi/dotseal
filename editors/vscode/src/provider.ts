import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";
import {
  decryptText,
  encryptText,
  reencryptText,
  SelectiveEncryptionOptions
} from "./dotseal/core";
import { DotsealError } from "./dotseal/errors";
import { KeyOptions, resolveKeyBytes } from "./dotseal/keys";

export const DOTSEAL_SCHEME = "dotseal";

export type KeyOptionsProvider = () => KeyOptions;
export type SelectiveEncryptionOptionsProvider = (
  fileUri: vscode.Uri
) => SelectiveEncryptionOptions;

export class DotsealFsProvider implements vscode.FileSystemProvider {
  private readonly emitter = new vscode.EventEmitter<vscode.FileChangeEvent[]>();
  readonly onDidChangeFile = this.emitter.event;

  constructor(
    private readonly getKeyOptions: KeyOptionsProvider,
    private readonly getSelectiveEncryptionOptions: SelectiveEncryptionOptionsProvider = () => ({})
  ) {}

  watch(): vscode.Disposable {
    return new vscode.Disposable(() => undefined);
  }

  stat(uri: vscode.Uri): vscode.FileStat {
    const realPath = fromDotsealUri(uri);
    try {
      const stat = fs.statSync(realPath);
      return {
        type: vscode.FileType.File,
        ctime: stat.ctimeMs,
        mtime: stat.mtimeMs,
        size: stat.size
      };
    } catch (error) {
      throw fileSystemError(error);
    }
  }

  readDirectory(): [string, vscode.FileType][] {
    throw vscode.FileSystemError.NoPermissions("dotseal: directories are not supported.");
  }

  createDirectory(): void {
    throw vscode.FileSystemError.NoPermissions("dotseal: directories are not supported.");
  }

  readFile(uri: vscode.Uri): Uint8Array {
    const realPath = fromDotsealUri(uri);
    try {
      const encrypted = fs.readFileSync(realPath, "utf8");
      const keyBytes = resolveKeyBytes(path.dirname(realPath), this.getKeyOptions());
      const cleartext = decryptText(encrypted, keyBytes);
      return Buffer.from(cleartext, "utf8");
    } catch (error) {
      throw fileSystemError(error);
    }
  }

  writeFile(
    uri: vscode.Uri,
    content: Uint8Array,
    options: { readonly create: boolean; readonly overwrite: boolean }
  ): void {
    const realPath = fromDotsealUri(uri);
    try {
      const exists = fs.existsSync(realPath);
      if (!exists && !options.create) {
        throw vscode.FileSystemError.FileNotFound(uri);
      }
      if (exists && options.create && !options.overwrite) {
        throw vscode.FileSystemError.FileExists(uri);
      }
      const keyBytes = resolveKeyBytes(path.dirname(realPath), this.getKeyOptions());
      const cleartext = Buffer.from(content).toString("utf8");
      // Reuse the existing ciphertext for unchanged values so saving only
      // produces a diff for the variables that actually changed.
      const original = exists ? fs.readFileSync(realPath, "utf8") : undefined;
      const encrypted =
        original !== undefined
          ? reencryptText(cleartext, keyBytes, original)
          : encryptText(
              cleartext,
              keyBytes,
              this.getSelectiveEncryptionOptions(vscode.Uri.file(realPath))
            );
      // Write to a sibling temp file and rename so a crash mid-write can
      // never leave a truncated/corrupt .env.enc behind.
      const tmpPath = path.join(
        path.dirname(realPath),
        `.dotseal-tmp-${process.pid}-${Date.now()}`
      );
      try {
        fs.writeFileSync(tmpPath, encrypted, "utf8");
        fs.renameSync(tmpPath, realPath);
      } catch (error) {
        try {
          fs.unlinkSync(tmpPath);
        } catch {
          // best effort cleanup
        }
        throw error;
      }
      this.emitter.fire([
        { type: exists ? vscode.FileChangeType.Changed : vscode.FileChangeType.Created, uri }
      ]);
    } catch (error) {
      throw fileSystemError(error);
    }
  }

  delete(): void {
    throw vscode.FileSystemError.NoPermissions("Delete the real .env.enc file directly.");
  }

  rename(): void {
    throw vscode.FileSystemError.NoPermissions("Rename the real .env.enc file directly.");
  }
}

export function toDotsealUri(fileUri: vscode.Uri): vscode.Uri {
  return fileUri.with({ scheme: DOTSEAL_SCHEME });
}

export function fromDotsealUri(uri: vscode.Uri): string {
  if (uri.scheme !== DOTSEAL_SCHEME) {
    throw vscode.FileSystemError.Unavailable(`Unsupported URI scheme: ${uri.scheme}`);
  }
  return uri.fsPath;
}

export function fileSystemError(error: unknown): vscode.FileSystemError {
  if (error instanceof vscode.FileSystemError) {
    return error;
  }
  if (error instanceof DotsealError) {
    return vscode.FileSystemError.Unavailable(error.message);
  }
  if (error && typeof error === "object" && "code" in error) {
    const code = (error as { code?: string }).code;
    if (code === "ENOENT") {
      return vscode.FileSystemError.FileNotFound(String(error));
    }
    if (code === "EACCES" || code === "EPERM") {
      return vscode.FileSystemError.NoPermissions(String(error));
    }
  }
  const message = error instanceof Error ? error.message : String(error);
  return vscode.FileSystemError.Unavailable(message);
}

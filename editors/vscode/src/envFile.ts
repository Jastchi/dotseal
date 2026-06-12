import * as path from "node:path";
import * as vscode from "vscode";

/** Matches `.env.enc` and dotenv-style variants like `.env.production.enc`. */
export const ENCRYPTED_ENV_BASENAME_PATTERN = /^\.env(?:\.[A-Za-z0-9._-]+)*\.enc$/;

export function isEncryptedEnvBasename(basename: string): boolean {
  return ENCRYPTED_ENV_BASENAME_PATTERN.test(basename);
}

export function isEncryptedEnvFile(uri: vscode.Uri): boolean {
  return uri.scheme === "file" && isEncryptedEnvBasename(path.basename(uri.fsPath));
}

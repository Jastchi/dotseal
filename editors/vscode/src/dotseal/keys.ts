import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { ENV_VAR_NAME, KEY_FILE_NAME } from "./core";
import { loadKeyBytes } from "./crypto";
import { MasterKeyNotFoundError } from "./errors";

export interface KeyOptions {
  masterKey?: string;
  keyFile?: string;
}

export function findKeyFile(startDir: string): string | undefined {
  let current = path.resolve(startDir);
  while (true) {
    const candidate = path.join(current, KEY_FILE_NAME);
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return candidate;
    }

    const parent = path.dirname(current);
    if (parent === current) {
      return undefined;
    }
    current = parent;
  }
}

export function resolveMasterKey(searchDir: string, options: KeyOptions = {}): string {
  if (options.masterKey?.trim()) {
    return options.masterKey.trim();
  }

  if (options.keyFile?.trim()) {
    const keyFile = resolveUserPath(options.keyFile.trim());
    if (fs.existsSync(keyFile) && fs.statSync(keyFile).isFile()) {
      return fs.readFileSync(keyFile, "utf8").trim();
    }
  }

  const envValue = process.env[ENV_VAR_NAME];
  if (envValue?.trim()) {
    return envValue.trim();
  }

  const keyFile = findKeyFile(searchDir);
  if (keyFile && fs.existsSync(keyFile) && fs.statSync(keyFile).isFile()) {
    return fs.readFileSync(keyFile, "utf8").trim();
  }

  throw new MasterKeyNotFoundError(
    `No master key found. Provide one in settings, set the ${ENV_VAR_NAME} environment variable, or run \`dotseal init\` to create a local ${KEY_FILE_NAME} file.`
  );
}

export function resolveKeyBytes(searchDir: string, options: KeyOptions = {}): Buffer {
  return loadKeyBytes(resolveMasterKey(searchDir, options));
}

function resolveUserPath(input: string): string {
  if (input === "~") {
    return os.homedir();
  }
  if (input.startsWith("~/")) {
    return path.join(os.homedir(), input.slice(2));
  }
  return path.resolve(input);
}

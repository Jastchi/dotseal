import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import type { Record as EnvRecord } from "../src/dotseal/parser";

const repoRoot = path.resolve(__dirname, "../../..");
const bridgeScript = path.join(__dirname, "python-bridge.py");

export function findPython(): string {
  if (process.env.DOTSEAL_PYTHON) {
    return process.env.DOTSEAL_PYTHON;
  }
  const venvPython = path.join(repoRoot, ".venv", "bin", "python");
  if (fs.existsSync(venvPython)) {
    return venvPython;
  }
  return "python3";
}

export function callPython<T>(payload: object): T {
  const result = spawnSync(findPython(), [bridgeScript], {
    cwd: repoRoot,
    input: JSON.stringify(payload),
    encoding: "utf8",
    env: {
      ...process.env,
      PYTHONPATH: repoRoot
    }
  });

  if (result.status !== 0) {
    throw new Error(result.stderr || `Python exited with ${result.status}`);
  }

  return JSON.parse(result.stdout) as T;
}

export function pythonFingerprint(key: string): string {
  return callPython<string>({ op: "key_fingerprint", key });
}

export function pythonFormatValue(value: string): string {
  return callPython<string>({ op: "format_value", value });
}

export function pythonParse(text: string): EnvRecord[] {
  return callPython<EnvRecord[]>({ op: "parse", text });
}

export function pythonSerialize(text: string): string {
  return callPython<string>({ op: "serialize", text });
}

export function pythonFindKeyFile(startDir: string): string | null {
  return callPython<string | null>({ op: "find_key_file", start_dir: startDir });
}

export function pythonEncryptValue(
  key: string,
  plaintext: string,
  aad: string
): string {
  return callPython<string>({ op: "encrypt_value", key, plaintext, aad });
}

export function pythonDecryptValue(key: string, token: string, aad: string): string {
  return callPython<string>({ op: "decrypt_value", key, token, aad });
}

export function pythonEncryptText(key: string, text: string): string {
  return callPython<string>({ op: "encrypt_text", key, text });
}

export function pythonDecryptText(key: string, text: string): string {
  return callPython<string>({ op: "decrypt_text", key, text });
}

export function pythonReencryptText(
  key: string,
  cleartext: string,
  originalText: string
): string {
  return callPython<string>({
    op: "reencrypt_text",
    key,
    cleartext,
    original_text: originalText
  });
}

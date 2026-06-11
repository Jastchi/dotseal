import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes
} from "node:crypto";
import {
  DecryptionError,
  EncryptionError,
  InvalidMasterKeyError
} from "./errors";

export const ALGORITHM = "AES_GCM";
export const KEY_SIZE = 32;
export const NONCE_SIZE = 12;
export const TAG_SIZE = 16;
export const ENC_PREFIX = `ENC[${ALGORITHM},data:`;
export const ENC_SUFFIX = "]";

const FINGERPRINT_DOMAIN = Buffer.from("dotseal/key-fingerprint/v1", "utf8");

export function generateMasterKey(): string {
  return randomBytes(KEY_SIZE).toString("base64");
}

export function loadKeyBytes(masterKey: string): Buffer {
  if (typeof masterKey !== "string") {
    throw new InvalidMasterKeyError("Master key must be a string.");
  }

  const cleaned = masterKey.trim();
  if (cleaned.length === 0) {
    throw new InvalidMasterKeyError("Master key is empty.");
  }

  let raw: Buffer;
  try {
    raw = Buffer.from(cleaned, "base64");
  } catch (error) {
    throw new InvalidMasterKeyError(
      "Master key is not valid base64. It must be a base64-encoded 32-byte key as produced by `dotseal init`."
    );
  }

  if (raw.length !== KEY_SIZE || raw.toString("base64") !== cleaned) {
    throw new InvalidMasterKeyError(
      `Master key must decode to ${KEY_SIZE} bytes (got ${raw.length}). Did you copy the whole key?`
    );
  }

  return raw;
}

export function keyFingerprint(keyBytes: Buffer): string {
  const digest = createHash("sha256")
    .update(FINGERPRINT_DOMAIN)
    .update(keyBytes)
    .digest();
  return digest.subarray(0, 8).toString("hex");
}

export function isEncryptedValue(value: string): boolean {
  return value.startsWith(ENC_PREFIX) && value.endsWith(ENC_SUFFIX);
}

export function encryptValue(
  keyBytes: Buffer,
  plaintext: string,
  aad: string
): string {
  const nonce = randomBytes(NONCE_SIZE);
  const cipher = createCipheriv("aes-256-gcm", keyBytes, nonce);
  cipher.setAAD(Buffer.from(aad, "utf8"));

  try {
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(plaintext, "utf8")),
      cipher.final()
    ]);
    const payload = Buffer.concat([
      nonce,
      ciphertext,
      cipher.getAuthTag()
    ]).toString("base64");
    return `${ENC_PREFIX}${payload}${ENC_SUFFIX}`;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new EncryptionError(`Failed to encrypt value: ${message}`);
  }
}

export function decryptValue(
  keyBytes: Buffer,
  token: string,
  aad: string
): string {
  if (!isEncryptedValue(token)) {
    throw new DecryptionError("Value is not a recognized ENC[AES_GCM,...] token.");
  }

  const payloadB64 = token.slice(ENC_PREFIX.length, -ENC_SUFFIX.length);
  let blob: Buffer;
  try {
    blob = Buffer.from(payloadB64, "base64");
  } catch (error) {
    throw new DecryptionError("Corrupted data: payload is not valid base64.");
  }

  if (blob.length < NONCE_SIZE + TAG_SIZE) {
    throw new DecryptionError("Corrupted data: ciphertext is too short.");
  }

  const nonce = blob.subarray(0, NONCE_SIZE);
  const ciphertext = blob.subarray(NONCE_SIZE, -TAG_SIZE);
  const tag = blob.subarray(-TAG_SIZE);
  const decipher = createDecipheriv("aes-256-gcm", keyBytes, nonce);
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(tag);

  try {
    return Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]).toString("utf8");
  } catch (error) {
    throw new DecryptionError("Invalid Master Key or Corrupted Data.");
  }
}

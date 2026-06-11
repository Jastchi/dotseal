export class DotsealError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class MasterKeyNotFoundError extends DotsealError {}

export class InvalidMasterKeyError extends DotsealError {}

export class KeyFingerprintMismatchError extends DotsealError {}

export class DecryptionError extends DotsealError {}

export class EncryptionError extends DotsealError {}

export class ParseError extends DotsealError {}

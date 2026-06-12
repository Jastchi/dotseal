"""JSON stdin/stdout bridge for TypeScript conformance tests."""

from __future__ import annotations

import json
import sys

from dotseal import core, crypto, parser


def record_to_dict(record: parser.Record) -> dict[str, object]:
    return {
        "kind": record.kind,
        "raw": record.raw,
        "key": record.key,
        "value": record.value,
        "export": record.export,
        "comment": record.comment,
    }


def main() -> None:
    request = json.load(sys.stdin)
    op = request["op"]

    if op == "key_fingerprint":
        key_bytes = crypto.load_key_bytes(request["key"])
        json.dump(crypto.key_fingerprint(key_bytes), sys.stdout)
        return

    if op == "format_value":
        json.dump(parser.format_value(request["value"]), sys.stdout)
        return

    if op == "parse":
        parsed = parser.parse(request["text"])
        json.dump([record_to_dict(record) for record in parsed.records], sys.stdout)
        return

    if op == "serialize":
        parsed = parser.parse(request["text"])
        json.dump(parser.serialize(parsed), sys.stdout)
        return

    if op == "find_key_file":
        json.dump(core.find_key_file(request["start_dir"]), sys.stdout)
        return

    key_bytes = crypto.load_key_bytes(request["key"])

    if op == "encrypt_value":
        token = crypto.encrypt_value(
            key_bytes, request["plaintext"], aad=request["aad"]
        )
        json.dump(token, sys.stdout)
        return

    if op == "decrypt_value":
        plaintext = crypto.decrypt_value(
            key_bytes, request["token"], aad=request["aad"]
        )
        json.dump(plaintext, sys.stdout)
        return

    if op == "encrypt_text":
        json.dump(core.encrypt_text(request["text"], key_bytes), sys.stdout)
        return

    if op == "decrypt_text":
        json.dump(core.decrypt_text(request["text"], key_bytes), sys.stdout)
        return

    raise SystemExit(f"unknown op: {op}")


if __name__ == "__main__":
    main()

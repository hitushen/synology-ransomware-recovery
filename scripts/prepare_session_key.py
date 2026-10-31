#!/usr/bin/env python3
"""Normalize explicitly identified private AES session material to IV16 + key32.

No secret bytes are printed. Output is exclusively created; POSIX mode 0600.
On Windows, the containing directory must have a suitable private ACL.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys


class MaterialError(ValueError):
    pass


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise MaterialError("Duplicate JSON field")
        result[key] = value
    return result


def hex_bytes(value, length, label):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{%d}" % (length * 2), value):
        raise MaterialError(label + " must contain exactly " + str(length * 2) + " hexadecimal characters")
    return bytes.fromhex(value)


def normalize(data, material_format):
    if material_format == "raw-iv-key":
        if len(data) != 48:
            raise MaterialError("Explicit raw IV16 + key32 input must be exactly 48 bytes")
        return data
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError:
        raise MaterialError("Expected UTF-8 key text") from None
    if material_format == "json":
        try:
            fields = json.loads(text, object_pairs_hook=strict_pairs)
        except (ValueError, TypeError):
            raise MaterialError("Invalid JSON or duplicate fields") from None
        if not isinstance(fields, dict) or set(fields) != {"aes_key_hex", "aes_iv_hex"}:
            raise MaterialError("JSON must contain only aes_key_hex and aes_iv_hex")
        key, iv = fields["aes_key_hex"], fields["aes_iv_hex"]
    elif material_format == "solar-key-sys":
        fields = {}
        for line in text.splitlines():
            if not line.strip():
                continue
            match = re.fullmatch(r"(AES_KEY|AES_IV)=([0-9a-fA-F]+)", line.strip())
            if match is None or match[1] in fields:
                raise MaterialError("Expected exactly one AES_KEY and AES_IV assignment; no other lines")
            fields[match[1]] = match[2]
        if set(fields) != {"AES_KEY", "AES_IV"}:
            raise MaterialError("Solar key.sys requires both AES_KEY and AES_IV")
        key, iv = fields["AES_KEY"], fields["AES_IV"]
    else:
        raise MaterialError("Unsupported material format")
    return hex_bytes(iv, 16, "AES IV") + hex_bytes(key, 32, "AES key")


def prepare(input_path, material_format, output_path):
    path = Path(input_path)
    if path.is_symlink():
        raise MaterialError("Secret input cannot be a symlink")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise MaterialError("Secret input must be an independent regular file")
        data = stream.read(65537)
        if len(data) > 65536:
            raise MaterialError("Secret material file exceeds 64 KiB limit")
    master = normalize(data, material_format)
    fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    created = os.fstat(fd)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(master)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        current = Path(output_path).lstat()
        if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
            Path(output_path).unlink()
        raise
    return {"format": "IV16 + AES-key32", "bytes": 48,
            "validation": "syntax and length only; validate on an independent encrypted file"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--format", choices=["json", "solar-key-sys", "raw-iv-key"], required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.input, args.format, args.output)
    except (OSError, MaterialError) as error:
        print("Material preparation refused: " + type(error).__name__ + "; " +
              (str(error) if isinstance(error, MaterialError) else "filesystem operation failed"), file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

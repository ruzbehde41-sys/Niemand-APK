#!/usr/bin/env python3
"""Read-only DEX header and identifier inspector; never executes DEX bytecode."""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

HEADER_SIZE = 0x70
ENDIAN_CONSTANT = 0x12345678
REVERSE_ENDIAN_CONSTANT = 0x78563412
MAX_ITEMS = 2_000_000


class DexFormatError(ValueError):
    """Raised when a DEX file is malformed or internally inconsistent."""


def _require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise DexFormatError(f"{label} is outside the file bounds")


def _u32(data: bytes, offset: int, label: str) -> int:
    _require_range(data, offset, 4, label)
    return struct.unpack_from("<I", data, offset)[0]


def _uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for index in range(5):
        _require_range(data, offset, 1, "ULEB128 value")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << (index * 7)
        if not byte & 0x80:
            return value, offset
    raise DexFormatError("invalid or oversized ULEB128 value")


def _read_string(data: bytes, offset: int) -> str:
    _utf16_size, cursor = _uleb128(data, offset)
    end = data.find(b"\x00", cursor)
    if end < 0:
        raise DexFormatError("unterminated DEX string data")
    # Decode conservatively. DEX uses modified UTF-8; preserve readable text
    # while replacing byte sequences unsupported by Python's standard decoder.
    raw = data[cursor:end].replace(b"\xc0\x80", b"\x00")
    return raw.decode("utf-8", errors="replace")


def inspect_dex(path: Path, max_items: int = 5000) -> dict:
    """Read DEX metadata, strings, type descriptors, class and method identifiers."""
    if not path.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    data = path.read_bytes()
    if len(data) < HEADER_SIZE:
        raise DexFormatError("file is shorter than the DEX header")
    if data[:4] != b"dex\n" or data[7] != 0:
        raise DexFormatError("invalid DEX magic")
    version = data[4:7].decode("ascii", errors="replace")
    file_size = _u32(data, 0x20, "file_size")
    header_size = _u32(data, 0x24, "header_size")
    endian_tag = _u32(data, 0x28, "endian_tag")
    if header_size != HEADER_SIZE:
        raise DexFormatError(f"unsupported DEX header size: {header_size}")
    if file_size != len(data):
        raise DexFormatError(f"declared file_size {file_size} does not match actual size {len(data)}")
    if endian_tag == REVERSE_ENDIAN_CONSTANT:
        raise DexFormatError("reverse-endian DEX files are not supported")
    if endian_tag != ENDIAN_CONSTANT:
        raise DexFormatError("invalid DEX endian tag")

    tables = {
        "string_ids": (0x38, 4),
        "type_ids": (0x40, 4),
        "proto_ids": (0x48, 12),
        "field_ids": (0x50, 8),
        "method_ids": (0x58, 8),
        "class_defs": (0x60, 32),
    }
    counts = {}
    offsets = {}
    for name, (header_offset, item_size) in tables.items():
        count = _u32(data, header_offset, f"{name}_size")
        offset = _u32(data, header_offset + 4, f"{name}_off")
        if count > MAX_ITEMS:
            raise DexFormatError(f"{name} count exceeds safety limit")
        if count and offset == 0:
            raise DexFormatError(f"{name} offset is zero despite nonzero count")
        _require_range(data, offset, count * item_size, name)
        counts[name] = count
        offsets[name] = offset

    string_values = []
    for index in range(counts["string_ids"]):
        string_offset = _u32(data, offsets["string_ids"] + index * 4, "string_data_off")
        if string_offset >= len(data):
            raise DexFormatError("string_data_off is outside the file")
        string_values.append(_read_string(data, string_offset))

    type_descriptors = []
    for index in range(counts["type_ids"]):
        descriptor_index = _u32(data, offsets["type_ids"] + index * 4, "descriptor_idx")
        if descriptor_index >= len(string_values):
            raise DexFormatError("type descriptor index is outside string_ids")
        type_descriptors.append(string_values[descriptor_index])

    class_descriptors = []
    for index in range(counts["class_defs"]):
        class_idx = _u32(data, offsets["class_defs"] + index * 32, "class_idx")
        if class_idx >= len(type_descriptors):
            raise DexFormatError("class_idx is outside type_ids")
        class_descriptors.append(type_descriptors[class_idx])

    methods = []
    for index in range(counts["method_ids"]):
        item_offset = offsets["method_ids"] + index * 8
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", data, item_offset)
        if class_idx >= len(type_descriptors) or name_idx >= len(string_values):
            raise DexFormatError("method identifier references an invalid class or name")
        methods.append({
            "class": type_descriptors[class_idx],
            "name": string_values[name_idx],
            "proto_index": proto_idx,
        })

    return {
        "file": path.name,
        "size_bytes": len(data),
        "dex_version": version,
        "header_size": header_size,
        "counts": counts,
        "classes": class_descriptors[:max_items],
        "methods": methods[:max_items],
        "strings": string_values[:max_items],
        "truncated": {
            "classes": len(class_descriptors) > max_items,
            "methods": len(methods) > max_items,
            "strings": len(string_values) > max_items,
        },
        "limitations": [
            "Method bodies and bytecode instructions are not decoded.",
            "Class and method lists come from identifier tables; inherited or dynamically generated members are not resolved.",
            "String decoding is conservative for modified UTF-8.",
            "DEX checksum and signature are not cryptographically verified.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dex", type=Path, help="Path to a DEX file (for example classes.dex)")
    parser.add_argument("--max-items", type=int, default=5000,
                        help="Maximum strings/classes/methods included in JSON (default: 5000)")
    args = parser.parse_args()
    if args.max_items < 0 or args.max_items > MAX_ITEMS:
        parser.error(f"--max-items must be between 0 and {MAX_ITEMS}")
    try:
        print(json.dumps(inspect_dex(args.dex, args.max_items), indent=2, ensure_ascii=False))
    except (OSError, DexFormatError) as exc:
        parser.exit(1, f"DEX inspection failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

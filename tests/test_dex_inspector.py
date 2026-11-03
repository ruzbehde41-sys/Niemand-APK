import struct
import sys
from pathlib import Path
import tempfile
import unittest

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))
from dex_inspector import DexFormatError, inspect_dex


def make_minimal_dex():
    strings = ["Lcom/example/Demo;", "demo", "V"]
    string_ids_off = 0x70
    type_ids_off = string_ids_off + len(strings) * 4
    method_ids_off = type_ids_off + 2 * 4
    class_defs_off = method_ids_off + 1 * 8
    data_off = class_defs_off + 1 * 32
    data = bytearray()
    string_offsets = []
    for value in strings:
        string_offsets.append(data_off + len(data))
        encoded = value.encode("utf-8")
        data.append(len(value))
        data.extend(encoded)
        data.append(0)
    file_size = data_off + len(data)
    header = bytearray(0x70)
    header[:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x20, file_size)
    struct.pack_into("<I", header, 0x24, 0x70)
    struct.pack_into("<I", header, 0x28, 0x12345678)
    struct.pack_into("<I", header, 0x38, len(strings))
    struct.pack_into("<I", header, 0x3C, string_ids_off)
    struct.pack_into("<I", header, 0x40, 2)
    struct.pack_into("<I", header, 0x44, type_ids_off)
    struct.pack_into("<I", header, 0x58, 1)
    struct.pack_into("<I", header, 0x5C, method_ids_off)
    struct.pack_into("<I", header, 0x60, 1)
    struct.pack_into("<I", header, 0x64, class_defs_off)
    tables = bytearray()
    for offset in string_offsets:
        tables.extend(struct.pack("<I", offset))
    tables.extend(struct.pack("<II", 0, 2))
    tables.extend(struct.pack("<HHI", 0, 0, 1))
    class_def = bytearray(32)
    struct.pack_into("<I", class_def, 0, 0)
    return bytes(header + tables + class_def + data)


class DexInspectorTests(unittest.TestCase):
    def test_reads_header_strings_class_and_method(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "classes.dex"
            path.write_bytes(make_minimal_dex())
            result = inspect_dex(path)
            self.assertEqual(result["dex_version"], "035")
            self.assertEqual(result["classes"], ["Lcom/example/Demo;"])
            self.assertEqual(result["strings"], ["Lcom/example/Demo;", "demo", "V"])
            self.assertEqual(result["methods"][0]["class"], "Lcom/example/Demo;")
            self.assertEqual(result["methods"][0]["name"], "demo")

    def test_rejects_invalid_magic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.dex"
            path.write_bytes(b"not a dex file" + bytes(100))
            with self.assertRaises(DexFormatError):
                inspect_dex(path)

    def test_rejects_truncated_header(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "short.dex"
            path.write_bytes(b"dex\n035\x00")
            with self.assertRaises(DexFormatError):
                inspect_dex(path)

    def test_missing_file_raises(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.dex"
            with self.assertRaises(FileNotFoundError):
                inspect_dex(path)


if __name__ == "__main__":
    unittest.main()

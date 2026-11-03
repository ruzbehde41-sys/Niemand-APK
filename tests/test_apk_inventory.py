import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "apk_inventory.py"
SPEC = importlib.util.spec_from_file_location("apk_inventory", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)

class ApkInventoryTests(unittest.TestCase):
    def test_non_zip_file_is_hashed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.apk"
            path.write_bytes(b"not a zip")
            result = MODULE.inventory(path)
            self.assertFalse(result["is_zip"])
            self.assertEqual(result["size_bytes"], 9)
            self.assertEqual(len(result["sha256"]), 64)

    def test_zip_metadata_and_dex_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"manifest")
                archive.writestr("classes.dex", b"dex")
                archive.writestr("classes2.dex", b"dex2")
                archive.writestr("res/raw/data.bin", b"x")
            result = MODULE.inventory(path)
            self.assertTrue(result["is_zip"])
            self.assertTrue(result["manifest_present"])
            self.assertEqual(result["dex_files"], ["classes.dex", "classes2.dex"])
            self.assertEqual(result["entry_count"], 4)

    def test_empty_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.apk"
            with zipfile.ZipFile(path, "w"):
                pass
            result = MODULE.inventory(path)
            self.assertTrue(result["is_zip"])
            self.assertEqual(result["dex_files"], [])

if __name__ == "__main__":
    unittest.main()

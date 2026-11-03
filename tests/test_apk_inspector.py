import sys
from pathlib import Path
import tempfile
import unittest
import zipfile

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))
from apk_inspector import inspect_apk


class ApkInspectorTests(unittest.TestCase):
    def test_non_zip_input_returns_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.apk"
            path.write_bytes(b"not zip")
            result = inspect_apk(path)
            self.assertFalse(result["is_zip"])
            self.assertTrue(result["warnings"])

    def test_detects_common_apk_components(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"manifest")
                archive.writestr("resources.arsc", b"resources")
                archive.writestr("classes.dex", b"dex")
                archive.writestr("classes2.dex", b"dex2")
                archive.writestr("lib/arm64-v8a/libsample.so", b"native")
                archive.writestr("assets/config.json", b"{}")
                archive.writestr("META-INF/CERT.RSA", b"signature")
            result = inspect_apk(path)
            self.assertTrue(result["manifest_present"])
            self.assertTrue(result["resources_table_present"])
            self.assertEqual(result["dex_files"], ["classes.dex", "classes2.dex"])
            self.assertEqual(result["native_libraries"], ["lib/arm64-v8a/libsample.so"])
            self.assertEqual(result["asset_file_count"], 1)
            self.assertEqual(result["signature_files"], ["META-INF/CERT.RSA"])

    def test_flags_unsafe_and_duplicate_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("../outside.txt", b"x")
                archive.writestr("duplicate.txt", b"one")
                archive.writestr("duplicate.txt", b"two")
            result = inspect_apk(path)
            self.assertIn("../outside.txt", result["unsafe_paths"])
            self.assertIn("duplicate.txt", result["duplicate_entries"])
            self.assertTrue(result["warnings"])

    def test_missing_file_raises(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.apk"
            with self.assertRaises(FileNotFoundError):
                inspect_apk(path)


if __name__ == "__main__":
    unittest.main()

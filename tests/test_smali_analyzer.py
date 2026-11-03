import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "smali_analyzer.py"


class SmaliAnalyzerTests(unittest.TestCase):
    def run_tool(self, target, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(target), *args],
            text=True, capture_output=True, check=False,
        )

    def test_extracts_class_method_string_url_and_network_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "Example.smali"
            source.write_text(
                '.class public Lcom/example/Example;\n'
                '.super Ljava/lang/Object;\n'
                '.method public load()V\n'
                '    const-string v0, "https://example.test/api"\n'
                '    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;\n'
                '.end method\n',
                encoding="utf-8",
            )
            result = self.run_tool(source)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual(data["files_scanned"], 1)
            self.assertEqual(data["counts"]["classes"], 1)
            self.assertEqual(data["counts"]["methods"], 1)
            self.assertEqual(data["counts"]["strings"], 1)
            self.assertEqual(data["counts"]["urls"], 1)
            self.assertEqual(data["counts"]["network_calls"], 1)

    def test_directory_scans_nested_smali_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "smali" / "x"
            nested.mkdir(parents=True)
            (nested / "A.smali").write_text(".class public LA;\n", encoding="utf-8")
            (nested / "ignore.txt").write_text("not smali", encoding="utf-8")
            result = self.run_tool(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["files_scanned"], 1)

    def test_rejects_non_smali_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "input.txt"
            source.write_text("text", encoding="utf-8")
            result = self.run_tool(source)
            self.assertEqual(result.returncode, 2)
            self.assertIn(".smali", result.stderr)

    def test_missing_input_returns_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_tool(Path(tmp) / "missing")
            self.assertEqual(result.returncode, 2)

    def test_invalid_limit_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_tool(tmp, "--max-items", "0")
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()

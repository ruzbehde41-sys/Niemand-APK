import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "smali_flow_analyzer.py"


class SmaliFlowAnalyzerTests(unittest.TestCase):
    def run_tool(self, path, *args):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), str(path), *args],
            text=True, capture_output=True, check=True
        )
        return json.loads(proc.stdout)

    def test_extracts_methods_and_call_edges(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "A.smali"
            file.write_text(
                ".class public Lcom/example/A;\n"
                ".method public run()V\n"
                "    invoke-virtual {v0}, Lcom/example/B;->send(Ljava/lang/String;)V\n"
                ".end method\n"
            )
            data = self.run_tool(file)
            self.assertEqual(data["totals"]["methods"], 1)
            self.assertEqual(data["totals"]["call_edges"], 1)
            edge = data["results"][0]["call_edges"][0]
            self.assertEqual(edge["caller_method"], "run()V")
            self.assertIn("Lcom/example/B;->send", edge["callee"])

    def test_detects_network_namespace(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "Net.smali"
            file.write_text(
                ".class public Lcom/example/Net;\n"
                ".method public connect()V\n"
                " invoke-interface {v0}, Lokhttp3/Call;->execute()Lokhttp3/Response;\n"
                ".end method\n"
            )
            data = self.run_tool(file)
            self.assertEqual(data["totals"]["network_calls"], 1)

    def test_extracts_url_and_protocol_literals(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "Socket.smali"
            file.write_text(
                '.class public Lcom/example/Socket;\n'
                '.method public open()V\n'
                ' const-string v0, "wss://example.invalid/gateway/websocket"\n'
                ' const-string v1, "GatewayClientEvent.Subscribe"\n'
                ".end method\n"
            )
            data = self.run_tool(file)
            self.assertEqual(data["totals"]["endpoints"], 1)
            self.assertGreaterEqual(data["totals"]["protocol_strings"], 2)

    def test_redacts_token_like_literals(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "Secret.smali"
            file.write_text(
                '.class public Lcom/example/Secret;\n'
                '.method public value()V\n'
                ' const-string v0, "Gateway access_token=abc123secret"\n'
                ".end method\n"
            )
            data = self.run_tool(file)
            value = data["results"][0]["protocol_strings"][0]["value"]
            self.assertIn("[REDACTED]", value)
            self.assertNotIn("abc123secret", value)

    def test_scans_nested_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "one" / "two" / "A.smali"
            file.parent.mkdir(parents=True)
            file.write_text(".class public Lcom/example/A;\n")
            data = self.run_tool(Path(tmp))
            self.assertEqual(data["files_scanned"], 1)

    def test_respects_file_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("A.smali", "B.smali", "C.smali"):
                (Path(tmp) / name).write_text(".class public Lcom/example/X;\n")
            data = self.run_tool(Path(tmp), "--max-files", "2")
            self.assertEqual(data["files_scanned"], 2)
            self.assertTrue(data["file_limit_reached"])

    def test_package_prefix_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "A.smali").write_text(".class public Lcom/example/A;\n")
            (Path(tmp) / "B.smali").write_text(".class public Lorg/other/B;\n")
            data = self.run_tool(Path(tmp), "--package-prefix", "com.example")
            self.assertEqual(data["files_scanned"], 1)
            self.assertEqual(data["results"][0]["class"], "Lcom/example/A;")

    def test_rejects_missing_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing"
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(missing)],
                text=True, capture_output=True
            )
            self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()

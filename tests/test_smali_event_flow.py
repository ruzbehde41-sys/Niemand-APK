import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "smali_event_flow.py"


class SmaliEventFlowTests(unittest.TestCase):
    def run_tool(self, path, *args):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), str(path), *args],
            text=True, capture_output=True, check=True
        )
        return json.loads(proc.stdout)

    def test_maps_client_event_to_method_and_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "Gateway.smali"
            file.write_text(
                ".class public Lai/x/grok/chat/websocket/Gateway;\n"
                ".method public send()V\n"
                ' const-string v0, "GatewayClientEvent.Subscribe"\n'
                " invoke-virtual {v1}, Lai/x/grok/chat/websocket/Socket;->send()V\n"
                ".end method\n"
            )
            data = self.run_tool(file)
            self.assertEqual(data["totals"]["events"], 1)
            event = data["events"][0]
            self.assertEqual(event["direction"], "client")
            self.assertEqual(event["event"], "Subscribe")
            self.assertEqual(event["category"], "subscription")
            self.assertIn("->send()V", event["related_calls"][0])

    def test_maps_server_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "Gateway.smali"
            file.write_text(
                ".class public Lai/x/grok/chat/websocket/Gateway;\n"
                ".method public receive()V\n"
                ' const-string v0, "GatewayServerEvent.MessageDelta"\n'
                ".end method\n"
            )
            data = self.run_tool(file)
            self.assertEqual(data["events"][0]["direction"], "server")
            self.assertEqual(data["events"][0]["category"], "message")

    def test_redacts_sensitive_protocol_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "Gateway.smali"
            file.write_text(
                ".class public Lai/x/grok/chat/websocket/Gateway;\n"
                ".method public send()V\n"
                ' const-string v0, "GatewayClientEvent.Send access_token=secret123"\n'
                ".end method\n"
            )
            data = self.run_tool(file)
            rendered = json.dumps(data)
            self.assertNotIn("secret123", rendered)
            self.assertIn("[REDACTED]", rendered)

    def test_package_prefix_filters_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "A.smali").write_text(".class public Lai/x/grok/chat/websocket/A;\n")
            (Path(tmp) / "B.smali").write_text(".class public Lother/B;\n")
            data = self.run_tool(Path(tmp), "--package-prefix", "ai.x.grok.chat.websocket")
            self.assertEqual(data["files_scanned"], 1)

    def test_respects_event_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "Gateway.smali"
            file.write_text(
                ".class public Lai/x/grok/chat/websocket/Gateway;\n"
                ".method public run()V\n"
                ' const-string v0, "GatewayClientEvent.Send"\n'
                ' const-string v1, "GatewayServerEvent.Message"\n'
                ".end method\n"
            )
            data = self.run_tool(file, "--max-items", "1")
            self.assertEqual(data["totals"]["events"], 1)

    def test_rejects_missing_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(Path(tmp) / "missing")],
                text=True, capture_output=True
            )
            self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()

import json
import os
import socket
import subprocess
import tempfile
import threading
import unittest
import uuid
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
CLIPCTL = next(
    candidate for candidate in (
        APP_ROOT / ".build" / "debug" / "clipctl",
        APP_ROOT / ".build" / "out" / "Products" / "Debug" / "clipctl",
    ) if candidate.exists()
)
SECRET = "SYNTHETIC-SECRET-MUST-NEVER-REACH-CLIPCTL"


class ClipCtlSocketContractTests(unittest.TestCase):
    def run_cli(self, arguments, response):
        with tempfile.TemporaryDirectory() as temp_dir:
            socket_path = str(Path(temp_dir) / "clipvault.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(socket_path)
            listener.listen(1)
            received = []

            def serve():
                connection, _ = listener.accept()
                with connection:
                    data = bytearray()
                    while not data.endswith(b"\n"):
                        chunk = connection.recv(1)
                        if not chunk:
                            break
                        data.extend(chunk)
                    received.append(json.loads(data))
                    connection.sendall(json.dumps(response).encode() + b"\n")
                listener.close()

            server = threading.Thread(target=serve, daemon=True)
            server.start()
            environment = os.environ.copy()
            environment["CLIPVAULT_SOCKET"] = socket_path
            result = subprocess.run(
                [str(CLIPCTL), *arguments], capture_output=True, text=True,
                env=environment, timeout=5,
            )
            server.join(timeout=5)
            self.assertFalse(server.is_alive(), "socket fixture did not finish")
            return result, received

    def test_list_emits_only_metadata(self):
        metadata = {
            "reference": f"clip://{uuid.uuid4()}",
            "type": "text", "size": len(SECRET), "sourceApp": "Example",
            "timestamp": "2026-01-01T00:00:00Z", "sensitivityLabel": "normal",
            "providerTag": "local-encrypted",
        }
        result, requests = self.run_cli(["list"], {"ok": True, "items": [metadata]})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [metadata])
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].get("command"), "list")
        self.assertIsNone(requests[0].get("reference"))

    def test_copy_and_paste_send_only_opaque_reference_and_print_no_secret(self):
        for command in ("copy", "paste"):
            reference = f"clip://{uuid.uuid4()}"
            result, requests = self.run_cli([command, reference], {"ok": True})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(requests, [{"command": command, "reference": reference}])
            self.assertNotIn(SECRET, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "")

    def test_cli_rejects_import_and_malformed_references_without_socket_call(self):
        for arguments in (["import"], ["copy", "not-a-reference"]):
            result = subprocess.run(
                [str(CLIPCTL), *arguments], capture_output=True, text=True, timeout=5
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_store_and_import_paths_keep_contract_boundaries(self):
        app_source = (APP_ROOT / "Sources" / "ClipVaultApp" / "main.swift").read_text()
        store_source = (APP_ROOT.parent / "vault" / "Sources" / "ClipVault" / "VaultStoreService.swift").read_text()
        socket_source = (APP_ROOT / "Sources" / "ClipVaultApp" / "ClipVaultSocketServer.swift").read_text()
        contract = (APP_ROOT.parent / "specs" / "STORE.md").read_text()

        self.assertIn('ProcessInfo.processInfo.environment["CLIPVAULT_TEST_MODE"] == "1"', app_source)
        self.assertIn("InMemoryTestVaultProvider()", app_source)
        self.assertIn("LocalEncryptedProvider(directory:", app_source)
        test_provider_branch = app_source.split("if testMode {", 1)[1].split("} else {", 1)[0]
        self.assertNotIn("LocalEncryptedProvider", test_provider_branch)
        self.assertIn('ProcessInfo.processInfo.environment["CLIPVAULT_TEST_REFERENCE_FILE"]', app_source)
        self.assertIn('text.hasPrefix("clipvault-smoke-")', app_source)

        for field in ("type", "size", "sourceApp", "timestamp", "sensitivityLabel", "providerTag"):
            self.assertIn(field, contract)
        self.assertIn("func resolveToPasteboard(_ ref: URL) throws", store_source)
        resolve_store = store_source.split("func resolveToPasteboard(_ ref: URL) throws", 1)[1].split("public func delete", 1)[0]
        self.assertIn("pasteboard.setData(item.payload", resolve_store)
        self.assertNotIn("return item.payload", resolve_store)

        model_source = app_source.split("final class ClipboardModel", 1)[1].split("struct ClipboardMenu", 1)[0]
        resolve_model = model_source.split("func resolve(_ item:", 1)[1].split("func delete", 1)[0]
        self.assertIn("@Published var items: [VaultMetadata]", model_source)
        self.assertIn("store?.listMetadata()", model_source)
        self.assertIn("try store?.resolveToPasteboard(url)", resolve_model)
        self.assertNotIn("return item.payload", resolve_model)
        menu_source = app_source.split("struct ClipboardMenu", 1)[1].split("struct HistoryRow", 1)[0]
        row_source = app_source.split("struct HistoryRow", 1)[1].split("private func togglePin", 1)[0]
        self.assertNotIn("payload", menu_source)
        self.assertNotIn("payload", row_source)
        self.assertIn("store.listMetadata().map(SocketMetadata.init)", socket_source)
        self.assertIn("try store.resolveToPasteboard(ref)", socket_source)
        self.assertIn("if request.command == \"paste\" { synthesizePaste() }", socket_source)
        response_struct = socket_source.split("private struct SocketResponse: Encodable {", 1)[1].split("\n}", 1)[0]
        metadata_struct = socket_source.split("private struct SocketMetadata: Encodable {", 1)[1].split("\n}", 1)[0]
        self.assertIn("let ok: Bool", response_struct)
        self.assertIn("var items: [SocketMetadata]?", response_struct)
        self.assertIn("let reference: String", metadata_struct)
        self.assertNotIn("payload", response_struct)
        self.assertNotIn("payload", metadata_struct)
        self.assertIn("let reference: String", metadata_struct)

        self.assertIn(".fileImporter(", app_source)
        self.assertIn("PasswordCSVImporter.parse(csv, format: importFormat)", app_source)
        for format_name in ("chrome", "edge", "brave", "firefox", "safari", "applePasswords"):
            self.assertIn(f"PasswordCSVFormat.{format_name}", app_source)
        import_flow = app_source.split("func commitImport", 1)[1].split("private func bestEffortSecureDelete", 1)[0]
        self.assertIn("store.put(content: encoded", import_flow)
        self.assertNotIn("NSPasteboard", import_flow)
        self.assertNotIn("ClipboardHistory", import_flow)


if __name__ == "__main__":
    unittest.main()

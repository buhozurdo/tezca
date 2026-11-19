"""
Tests for the tezca CLI interface.
"""

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tezca.cli import main
from tezca.ledger import Ledger


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "cli_test.db"

        with Ledger(self.db_path) as ledger:
            ledger.record("agent-cli", "query", {"prompt": "Analyze dataset"})
            ledger.record("agent-cli", "result", {"status": "ok"})

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cli_verify_success(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["verify", str(self.db_path)])
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("[OK] 2 events verified.", output)
        self.assertIn("Chain integrity: INTACT", output)

    def test_cli_tail(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["tail", str(self.db_path), "-n", "1"])
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("#1", output)
        self.assertIn("type=result", output)

    def test_cli_export(self):
        export_file = Path(self.temp_dir.name) / "exported.jsonl"
        code = main(["export", str(self.db_path), "-o", str(export_file)])
        self.assertEqual(code, 0)
        self.assertTrue(export_file.exists())
        lines = export_file.read_text(encoding="utf-8").strip().split("\n")
        self.assertEqual(len(lines), 2)

    def test_cli_inspect(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["inspect", str(self.db_path), "0"])
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn('"agent_id": "agent-cli"', output)
        self.assertIn('"event_type": "query"', output)

    def test_cli_proof_and_verify_proof(self):
        proof_file = Path(self.temp_dir.name) / "test_cli.tezcaproof"
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["proof", str(self.db_path), "0", "-o", str(proof_file)])
        self.assertEqual(code, 0)
        self.assertTrue(proof_file.exists())
        self.assertIn("[OK] Cryptographic proof bundle exported", buf.getvalue())

        # Verify the exported proof file
        buf_verify = io.StringIO()
        with redirect_stdout(buf_verify):
            code_verify = main(["verify-proof", str(proof_file)])
        self.assertEqual(code_verify, 0)
        self.assertIn("[OK] Proof verified: Receipt #0 is cryptographically sealed.", buf_verify.getvalue())


if __name__ == "__main__":
    unittest.main()

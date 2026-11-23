"""
Comprehensive tests for the tezca CLI interface covering all commands and error paths.
"""

import io
import json
import sqlite3
import subprocess
import sys
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

    def test_cli_verify_nonexistent(self):
        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            code = main(["verify", "nonexistent_file_path.db"])
        self.assertEqual(code, 1)
        self.assertIn("not found", err_buf.getvalue())

    def test_cli_verify_tampered_chain(self):
        # Directly alter hash chain link
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("UPDATE tezca_receipts SET prev_hash = '9999999999999999999999999999999999999999999999999999999999999999' WHERE index_num = 1;")
        conn.commit()
        conn.close()

        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            code = main(["verify", str(self.db_path)])
        self.assertEqual(code, 1)
        self.assertIn("Tampering detected", err_buf.getvalue())
        self.assertIn("Expected prev_hash", err_buf.getvalue())

    def test_cli_tail_text_and_json(self):
        # Text output
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["tail", str(self.db_path), "-n", "1"])
        self.assertEqual(code, 0)
        self.assertIn("#1", buf.getvalue())

        # JSON output
        buf_json = io.StringIO()
        with redirect_stdout(buf_json):
            code_json = main(["tail", str(self.db_path), "-n", "2", "--json"])
        self.assertEqual(code_json, 0)
        lines = buf_json.getvalue().strip().split("\n")
        self.assertEqual(len(lines), 2)
        parsed = json.loads(lines[0])
        self.assertEqual(parsed["index"], 0)

    def test_cli_tail_nonexistent(self):
        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            code = main(["tail", "nonexistent.db"])
        self.assertEqual(code, 1)

    def test_cli_export_file_and_stdout(self):
        # Export to file
        export_file = Path(self.temp_dir.name) / "exported.jsonl"
        code = main(["export", str(self.db_path), "-o", str(export_file)])
        self.assertEqual(code, 0)
        self.assertTrue(export_file.exists())

        # Export to stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            code_stdout = main(["export", str(self.db_path)])
        self.assertEqual(code_stdout, 0)
        self.assertIn('"agent-cli"', buf.getvalue())

    def test_cli_export_nonexistent(self):
        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            code = main(["export", "nonexistent.db"])
        self.assertEqual(code, 1)

    def test_cli_inspect_found_and_not_found(self):
        # Found
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["inspect", str(self.db_path), "0"])
        self.assertEqual(code, 0)
        self.assertIn('"agent_id": "agent-cli"', buf.getvalue())

        # Not found
        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            code_nf = main(["inspect", str(self.db_path), "999"])
        self.assertEqual(code_nf, 1)
        self.assertIn("not found", err_buf.getvalue())

        # Nonexistent file
        err_file = io.StringIO()
        with redirect_stderr(err_file):
            code_file = main(["inspect", "nonexistent.db", "0"])
        self.assertEqual(code_file, 1)

    def test_cli_proof_and_verify_proof_complete(self):
        proof_file = Path(self.temp_dir.name) / "test_cli.tezcaproof"
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["proof", str(self.db_path), "0", "-o", str(proof_file)])
        self.assertEqual(code, 0)
        self.assertTrue(proof_file.exists())

        # Default output path
        buf_def = io.StringIO()
        with redirect_stdout(buf_def):
            code_def = main(["proof", str(self.db_path), "1"])
        self.assertEqual(code_def, 0)
        expected_def = Path(f"{self.db_path.stem}_event_1.tezcaproof")
        if expected_def.exists():
            expected_def.unlink()

        # Proof out of range
        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            code_bad = main(["proof", str(self.db_path), "999"])
        self.assertEqual(code_bad, 1)

        # Proof nonexistent DB
        err_db = io.StringIO()
        with redirect_stderr(err_db):
            code_nodb = main(["proof", "nonexistent.db", "0"])
        self.assertEqual(code_nodb, 1)

        # Verify-proof valid
        buf_v = io.StringIO()
        with redirect_stdout(buf_v):
            code_v = main(["verify-proof", str(proof_file)])
        self.assertEqual(code_v, 0)

        # Verify-proof nonexistent
        err_pv = io.StringIO()
        with redirect_stderr(err_pv):
            code_pv = main(["verify-proof", "nonexistent.tezcaproof"])
        self.assertEqual(code_pv, 1)

        # Verify-proof tampered
        tampered_file = Path(self.temp_dir.name) / "corrupt.tezcaproof"
        data = json.loads(proof_file.read_text(encoding="utf-8"))
        data["receipt"]["hash"] = "0" * 64
        tampered_file.write_text(json.dumps(data), encoding="utf-8")

        err_tamper = io.StringIO()
        with redirect_stderr(err_tamper):
            code_t = main(["verify-proof", str(tampered_file)])
        self.assertEqual(code_t, 1)
        self.assertIn("Proof verification failed", err_tamper.getvalue())

        # Verify-proof invalid JSON syntax
        bad_json = Path(self.temp_dir.name) / "syntax_error.tezcaproof"
        bad_json.write_text("{not valid json", encoding="utf-8")
        err_bad = io.StringIO()
        with redirect_stderr(err_bad):
            code_syntax = main(["verify-proof", str(bad_json)])
        self.assertEqual(code_syntax, 1)

    def test_cli_module_execution(self):
        # Test python -m tezca --help
        res = subprocess.run([sys.executable, "-m", "tezca", "--help"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("usage: tezca", res.stdout)

    def test_cli_verify_unexpected_exception(self):
        import unittest.mock
        with unittest.mock.patch("tezca.cli.Ledger", side_effect=RuntimeError("disk error")):
            err_buf = io.StringIO()
            with redirect_stderr(err_buf):
                code = main(["verify", str(self.db_path)])
            self.assertEqual(code, 1)
            self.assertIn("Verification failed", err_buf.getvalue())

    def test_cli_proof_unexpected_exception(self):
        import unittest.mock
        with unittest.mock.patch("tezca.ledger.Ledger.export_proof", side_effect=RuntimeError("export failed")):
            err_buf = io.StringIO()
            with redirect_stderr(err_buf):
                code = main(["proof", str(self.db_path), "0"])
            self.assertEqual(code, 1)
            self.assertIn("Failed to export proof", err_buf.getvalue())

    def test_cli_report_html_and_json(self):
        html_out = Path(self.temp_dir.name) / "compliance.html"
        json_out = Path(self.temp_dir.name) / "compliance.json"

        # 1. HTML generation to file
        buf = io.StringIO()
        with redirect_stdout(buf):
            code_html = main(["report", str(self.db_path), "-o", str(html_out)])
        self.assertEqual(code_html, 0)
        self.assertTrue(html_out.exists())
        self.assertIn("<!DOCTYPE html>", html_out.read_text(encoding="utf-8"))

        # 2. JSON generation to file with auto-detected .json extension
        buf = io.StringIO()
        with redirect_stdout(buf):
            code_json = main(["report", str(self.db_path), "-o", str(json_out)])
        self.assertEqual(code_json, 0)
        self.assertTrue(json_out.exists())
        data = json.loads(json_out.read_text(encoding="utf-8"))
        self.assertEqual(data["total_events"], 2)
        self.assertTrue(data["is_valid"])

        # 3. JSON to stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            code_stdout = main(["report", str(self.db_path), "--format", "json"])
        self.assertEqual(code_stdout, 0)
        stdout_data = json.loads(buf.getvalue())
        self.assertEqual(stdout_data["total_events"], 2)

        # 4. Non-existent file
        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            code_missing = main(["report", "missing_ledger.db"])
        self.assertEqual(code_missing, 1)
        self.assertIn("not found", err_buf.getvalue())

    def test_cli_report_tampered_fails(self):
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE tezca_receipts SET data_json = '{\"bad\": true}' WHERE index_num = 1;")
        conn.commit()
        conn.close()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["report", str(self.db_path)])
        self.assertEqual(code, 1)

    def test_cli_report_unexpected_exception(self):
        import unittest.mock
        with unittest.mock.patch("tezca.cli.generate_compliance_report", side_effect=RuntimeError("report err")):
            err_buf = io.StringIO()
            with redirect_stderr(err_buf):
                code = main(["report", str(self.db_path)])
            self.assertEqual(code, 1)
            self.assertIn("Failed to generate compliance report", err_buf.getvalue())

    def test_cli_compare_identical_and_output(self):
        import shutil
        replica_path = Path(self.temp_dir.name) / "replica.db"
        shutil.copyfile(self.db_path, replica_path)

        # stdout text
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["compare", str(self.db_path), str(replica_path)])
        self.assertEqual(code, 0)
        self.assertIn("Status:             IDENTICAL", buf.getvalue())
        self.assertIn("Compatible:         YES", buf.getvalue())

        # output file json
        out_json = Path(self.temp_dir.name) / "compare.json"
        buf = io.StringIO()
        with redirect_stdout(buf):
            code_json = main(["compare", str(self.db_path), str(replica_path), "-o", str(out_json)])
        self.assertEqual(code_json, 0)
        self.assertTrue(out_json.exists())
        data = json.loads(out_json.read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "identical")

    def test_cli_compare_forked(self):
        import dataclasses
        replica_path = Path(self.temp_dir.name) / "forked_replica.db"
        with Ledger(replica_path) as repl, Ledger(self.db_path) as prim:
            repl.record("agent-x", "divergent", {"rogue": True})
            # Replay receipt from prim at index 1
            prim_r1 = prim.storage.get_by_index(1)
            assert prim_r1 is not None
            repl.storage.append(dataclasses.replace(prim_r1, index=1))

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["compare", str(self.db_path), str(replica_path)])
        self.assertEqual(code, 1)
        self.assertIn("Fork Detected:      YES", buf.getvalue())
        self.assertIn("Replay Detected:    YES", buf.getvalue())

    def test_cli_compare_missing_files_and_error(self):
        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            c1 = main(["compare", "missing_p.db", str(self.db_path)])
        self.assertEqual(c1, 1)
        self.assertIn("Primary ledger file not found", err_buf.getvalue())

        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            c2 = main(["compare", str(self.db_path), "missing_r.db"])
        self.assertEqual(c2, 1)
        self.assertIn("Replica ledger file not found", err_buf.getvalue())

        import unittest.mock
        with unittest.mock.patch("tezca.ledger.Ledger.compare_with", side_effect=RuntimeError("comp crash")):
            err_buf = io.StringIO()
            with redirect_stderr(err_buf):
                c3 = main(["compare", str(self.db_path), str(self.db_path)])
            self.assertEqual(c3, 1)
            self.assertIn("Comparison failed", err_buf.getvalue())

    def test_cli_direct_main_call(self):
        import runpy
        old_argv = sys.argv
        sys.argv = ["tezca", "--help"]
        try:
            with self.assertRaises(SystemExit) as cm:
                runpy.run_module("tezca.cli", run_name="__main__")
            self.assertEqual(cm.exception.code, 0)
        finally:
            sys.argv = old_argv


if __name__ == "__main__":
    unittest.main()

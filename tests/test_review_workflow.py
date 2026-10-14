import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pi_logs
import pandas as pd
from wraith.audit.audit_log import log_batch, new_run_context
from wraith.enrichment.triage import iter_triage
from wraith.parsers.cowrie_parser import SessionSummary
from pi_logs import export_payload_manifest, validate_manifest


class ReviewWorkflowTests(unittest.TestCase):
	def test_correlation_sees_unassessed_session(self):
		target = SessionSummary(session_id="download", src_ip="192.0.2.1", files_downloaded=["file"])
		other = SessionSummary(session_id="login", src_ip="192.0.2.1", login_attempts=5, login_success=True)
		analyze = Mock(return_value=SimpleNamespace(classification="malicious", confidence="high"))
		results = list(iter_triage([target], analyze, "url", "model", correlation_summaries=[target, other]))
		self.assertEqual(analyze.call_count, 1)
		self.assertEqual(results[0]["ioc_history"].related_session_ids, ["login"])
		self.assertTrue(results[0]["ioc_history"].any_login_success)

	def test_repeated_records_have_distinct_runs_and_input_hashes(self):
		with tempfile.TemporaryDirectory() as folder:
			input_path = Path(folder) / "input.json"
			input_path.write_text("first")
			first = new_run_context([input_path], "model")
			input_path.write_text("second")
			second = new_run_context([input_path], "model")
			self.assertNotEqual(first["run_id"], second["run_id"])
			self.assertNotEqual(first["input_files"], second["input_files"])
			result = dict(session_id="same", src_ip="ip", method="rule", classification="benign", confidence="high")
			path = Path(folder) / "audit.jsonl"
			for context in [first, second]:
				log_batch([result], "model", path=path, run_context=context)
			records = [json.loads(line) for line in path.read_text().splitlines()]
			self.assertEqual(len(records), 2)
			self.assertEqual([r["run_context"]["run_id"] for r in records], [first["run_id"], second["run_id"]])

	def test_manifest_selects_reviewed_sessions_and_deduplicates_transfers(self):
		digest = hashlib.sha256(b"payload").hexdigest()
		events = pd.DataFrame([dict(session=s, eventid="cowrie.session.file_download", outfile=f"var/lib/cowrie/downloads/{digest}", shasum=digest) for s in ["a", "b", "c"]])
		with tempfile.TemporaryDirectory() as folder:
			manifest = export_payload_manifest(events, ["a", "b"], Path(folder) / "manifest.json")
		self.assertEqual([r["session_id"] for r in manifest["files"]], ["a", "b"])
		self.assertEqual(len(validate_manifest(manifest)), 1)
		with self.assertRaises(ValueError):
			validate_manifest({"version": 1, "files": [{"stored_name": "../bad", "sha256": digest}]})

	def test_verified_download_skip_and_mismatch_preserves_local(self):
		payload = b"captured evidence"
		digest = hashlib.sha256(payload).hexdigest()
		with tempfile.TemporaryDirectory() as folder:
			manifest_path = Path(folder) / "manifest.json"
			manifest_path.write_text(json.dumps({"version": 1, "files": [{"stored_name": digest, "sha256": digest}]}))
			args = SimpleNamespace(manifest=manifest_path, dest=Path(folder) / "downloads", overwrite=False, host="pi", port=22, key=Path("key"), payload_dir="/store")
			def transfer(command, **kwargs):
				Path(command[-1]).write_bytes(payload)
			with patch.object(pi_logs.subprocess, "run", side_effect=transfer) as run:
				self.assertEqual(pi_logs.download_payloads(args), 0)
				self.assertEqual(pi_logs.download_payloads(args), 0)
				self.assertEqual(run.call_count, 1)
			target = args.dest / digest
			target.write_bytes(b"old copy")
			args.overwrite = True
			def bad_transfer(command, **kwargs):
				Path(command[-1]).write_bytes(b"wrong remote bytes")
			with patch.object(pi_logs.subprocess, "run", side_effect=bad_transfer):
				self.assertEqual(pi_logs.download_payloads(args), 1)
			self.assertEqual(target.read_bytes(), b"old copy")


if __name__ == "__main__":
	unittest.main()

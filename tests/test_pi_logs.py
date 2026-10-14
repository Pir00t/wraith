import importlib.util
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("pi_logs", Path(__file__).resolve().parents[1] / "scripts" / "pi_logs.py")
pi_logs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pi_logs)


class PiLogsTests(unittest.TestCase):
	def test_selection_includes_rotated_json_only(self):
		names = ["cowrie.json", "cowrie.json.2026-09-15", "cowrie.log"]
		result = pi_logs.select_logs([{"name": n} for n in names], "cowrie.json*")
		self.assertEqual([r["name"] for r in result], names[:2])

	def test_failed_transfer_preserves_existing_copy(self):
		with tempfile.TemporaryDirectory() as folder:
			target = Path(folder) / "cowrie.json"
			target.write_text("original")
			args = SimpleNamespace(dest=Path(folder), overwrite=True, key=Path("key"), port=22,
								   host="sentinel@100.111.235.18", remote_dir="/logs")
			with patch.object(pi_logs.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "scp")):
				with self.assertRaises(subprocess.CalledProcessError):
					pi_logs.download(args, [{"name": "cowrie.json"}])
			self.assertEqual(target.read_text(), "original")
			self.assertEqual(list(Path(folder).iterdir()), [target])

	def test_existing_copy_skipped_then_explicitly_refreshed(self):
		with tempfile.TemporaryDirectory() as folder:
			target = Path(folder) / "cowrie.json"
			target.write_text("original")
			args = SimpleNamespace(dest=Path(folder), overwrite=False, key=Path("key"), port=22,
								   host="sentinel@100.111.235.18", remote_dir="/logs")
			with patch.object(pi_logs.subprocess, "run") as run:
				pi_logs.download(args, [{"name": "cowrie.json"}])
				run.assert_not_called()
			args.overwrite = True
			def transfer(command, **kwargs):
				Path(command[-1]).write_text("refreshed")
			with patch.object(pi_logs.subprocess, "run", side_effect=transfer):
				pi_logs.download(args, [{"name": "cowrie.json"}])
			self.assertEqual(target.read_text(), "refreshed")

	def test_rejects_path_traversal(self):
		with tempfile.TemporaryDirectory() as folder:
			args = SimpleNamespace(dest=Path(folder))
			with self.assertRaises(ValueError):
				pi_logs.download(args, [{"name": "../outside"}])


if __name__ == "__main__":
	unittest.main()

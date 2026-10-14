import sys
import unittest
from pathlib import Path

import pandas as pd


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from wraith.enrichment.session_stats import command_stats, credential_stats, download_stats, ip_stats
from wraith.parsers.cowrie_parser import build_session_summaries_df, parse_sessions


class SparseCowrieLogTests(unittest.TestCase):
	def setUp(self):
		self.events = pd.DataFrame([
			{
				"eventid": "cowrie.session.connect",
				"session": "session-1",
				"src_ip": "192.0.2.10",
				"timestamp": "2026-08-25T10:00:00Z",
			},
			{
				"eventid": "cowrie.session.closed",
				"session": "session-1",
				"timestamp": "2026-08-25T10:00:01Z",
				"duration": 1.0,
			},
		])

	def test_missing_event_specific_columns_return_empty_stats(self):
		self.assertTrue(credential_stats(self.events).empty)
		self.assertTrue(command_stats(self.events).empty)
		self.assertTrue(download_stats(self.events).empty)
		self.assertEqual(ip_stats(self.events).to_dict(), {"192.0.2.10": 1})

	def test_session_summary_defaults_missing_downloads_to_empty_list(self):
		sessions = build_session_summaries_df(self.events)
		self.assertEqual(sessions.loc[0, "files_downloaded"], [])

	def test_cowrie_destfile_is_retained_as_download_reference(self):
		events = pd.concat([
			self.events,
			pd.DataFrame([{
				"eventid": "cowrie.session.file_download",
				"session": "session-1",
				"destfile": "/tmp/payload",
				"shasum": "abc123",
			}]),
		], ignore_index=True)

		sessions = build_session_summaries_df(events)
		self.assertEqual(sessions.loc[0, "files_downloaded"], ["/tmp/payload"])
		self.assertEqual(download_stats(events).to_dict(), {"/tmp/payload": 1})

	def test_sanitized_fixture_parses_end_to_end(self):
		fixture = REPO_ROOT / "data" / "raw" / "fixtures" / "cowrie_sparse.jsonl"
		summaries = parse_sessions(fixture, verbose=False)
		by_id = {summary.session_id: summary for summary in summaries}

		self.assertEqual(len(summaries), 2)
		self.assertEqual(by_id["fixture-noise"].files_downloaded, [])
		self.assertEqual(by_id["fixture-download"].files_downloaded, ["/tmp/payload"])


if __name__ == "__main__":
	unittest.main()

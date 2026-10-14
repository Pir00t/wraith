"""
WRAITH - session-level statistics

Operates directly on the event-level DataFrame from
cowrie_parser.load_events_df() - one row per raw event, same shape as
pd.read_json(path, lines=True). No LLM involved, deterministic, meant
to run in under a second even across thousands of events.

Event-level counts (e.g. ip_stats) answer "how much total activity did
this IP generate" - a session with 50 commands contributes 50 rows.
That's a different question from "how many separate sessions did this
IP open", which needs the session-level DataFrame instead
(sessions_df['src_ip'].value_counts()) - use whichever matches the
question you're actually asking.
"""

import pandas as pd

from wraith.enrichment.attack_mapping import enrich_session

TOP_N_DEFAULT = 15


def credential_stats(events_df: pd.DataFrame, top_n: int = TOP_N_DEFAULT) -> pd.Series:
	"""Most attempted username:password pairs, failed and successful
	alike, across every login event in the raw data."""
	if not {"eventid", "username", "password"}.issubset(events_df.columns):
		return pd.Series(dtype=int, name="count")
	logins = events_df[events_df["eventid"].isin(
		["cowrie.login.failed", "cowrie.login.success"]
	)].copy()
	if logins.empty:
		return pd.Series(dtype=int)
	logins["credential"] = logins["username"].astype(str) + ":" + logins["password"].astype(str)
	return logins["credential"].value_counts().head(top_n)


def ip_stats(events_df: pd.DataFrame, top_n: int = TOP_N_DEFAULT) -> pd.Series:
	"""Event count per source IP. src_ip only appears on connect events,
	so this reflects distinct connections, not total activity volume -
	use command_stats/credential_stats grouped by IP if you want
	activity volume per IP instead."""
	if not {"eventid", "src_ip"}.issubset(events_df.columns):
		return pd.Series(dtype=int, name="count")
	connects = events_df[events_df["eventid"] == "cowrie.session.connect"]
	return connects["src_ip"].value_counts().head(top_n)


def command_stats(events_df: pd.DataFrame, top_n: int = TOP_N_DEFAULT) -> pd.Series:
	"""Most frequently entered exact command strings."""
	if not {"eventid", "input"}.issubset(events_df.columns):
		return pd.Series(dtype=int, name="count")
	commands = events_df[events_df["eventid"] == "cowrie.command.input"]
	return commands["input"].value_counts().head(top_n)


def download_stats(events_df: pd.DataFrame, top_n: int = TOP_N_DEFAULT) -> pd.Series:
	"""Most frequently downloaded artifact references.

	Cowrie may record a URL, destination filename, stored output path, or
	SHA-256 depending on how the file was captured. Use the most descriptive
	available field and treat an absent field as sparse JSONL, not an error.
	"""
	if "eventid" not in events_df.columns:
		return pd.Series(dtype=int, name="count")
	downloads = events_df[events_df["eventid"] == "cowrie.session.file_download"]
	download_fields = [
		field for field in ("url", "destfile", "outfile", "shasum")
		if field in downloads.columns
	]
	if downloads.empty or not download_fields:
		return pd.Series(dtype=int, name="count")
	references = downloads[download_fields].bfill(axis=1).iloc[:, 0]
	return references.value_counts().head(top_n)


def technique_stats(sessions_df: pd.DataFrame, top_n: int = TOP_N_DEFAULT) -> pd.Series:
	"""ATT&CK technique candidate frequency across sessions. Takes the
	SESSION-level frame (not events_df) since enrich_session() needs
	per-session commands/login/download context, not individual event
	rows. Same deterministic matching used for LLM prompts, aggregated
	here instead of feeding one prompt at a time."""
	all_ids = [
		c.technique_id
		for row in sessions_df.itertuples()
		for c in enrich_session(
			commands=row.commands,
			login_attempts=row.login_attempts,
			login_success=row.login_success,
			downloads=row.files_downloaded,
		)
	]
	return pd.Series(all_ids).value_counts().head(top_n)


def print_overview(events_df: pd.DataFrame, top_n: int = TOP_N_DEFAULT) -> None:
	"""Event-level stats overview - credentials, source IPs, commands,
	downloads. Called automatically by cowrie_parser.parse_sessions()
	unless verbose=False. Technique-candidate stats aren't included here
	since those need session-level context - call technique_stats()
	directly against a session DataFrame if you want that."""
	print(f"=== {len(events_df)} event(s) ===")

	print(f"\n--- top {top_n} attempted credentials ---")
	print(credential_stats(events_df, top_n).to_string())

	print(f"\n--- top {top_n} source IPs (by connection count) ---")
	print(ip_stats(events_df, top_n).to_string())

	print(f"\n--- top {top_n} commands ---")
	print(command_stats(events_df, top_n).to_string())

	print(f"\n--- downloads ---")
	dl_stats = download_stats(events_df, top_n)
	download_count = (
		int((events_df["eventid"] == "cowrie.session.file_download").sum())
		if "eventid" in events_df.columns else 0
	)
	print(f"  {download_count} download event(s)")
	print(dl_stats.to_string())

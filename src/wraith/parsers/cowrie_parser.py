"""
WRAITH - Cowrie log parser

Pandas is the core of this module now, not a manual per-event loop.
load_events_df() gives you the raw event-level DataFrame directly -
one row per event, 1 line = 1 row, exactly the shape you'd get from
pd.read_json(path, lines=True), just combined across multiple rotated
files. build_session_summaries_df() groups that down to one row per
session using groupby/agg rather than hand-rolled iteration.

SessionSummary (Pydantic) still exists as the final boundary object,
because triage.py / session_assessment.py / audit_log.py all depend on
its typed shape (session.commands, session.login_attempts, etc.) and
on model_dump_json() for prompt building. dataframe_to_summaries()
is the one place that conversion happens - everything before it is
pure pandas.
"""

import json
from pathlib import Path
from typing import Optional

import pandas as pd
from pydantic import BaseModel


class SessionSummary(BaseModel):
	session_id: str
	src_ip: str
	start_time: Optional[str] = None
	end_time: Optional[str] = None
	duration_seconds: Optional[float] = None
	login_attempts: int = 0
	login_success: bool = False
	successful_credentials: Optional[str] = None
	attempted_credentials: list[str] = []
	commands: list[str] = []
	files_downloaded: list[str] = []
	event_count: int = 0


def _rotation_sort_key(path: Path) -> str:
	"""Sort matched files so multi-file concatenation is chronological:
	date-suffixed files sort correctly as plain strings, and '\uffff'
	pushes the un-suffixed live file to the end rather than the
	(incorrect) start, since it's always the most recent activity."""
	suffix = path.name.replace("cowrie.json", "")
	return suffix or "\uffff"


def resolve_log_files(target: str | Path) -> list[Path]:
	"""Resolve `target` into the list of files to process. Three forms,
	nothing else - no date logic, no 'since':

	- an exact file path -> that one file, alone
	- a directory path -> every cowrie.json* file inside it
	- a wildcard pattern string, e.g. "data/raw/cowrie.json.2026-08-2*"
	  -> every file matching that pattern
	"""
	path = Path(target)

	if path.is_dir():
		matched = sorted(path.glob("cowrie.json*"), key=_rotation_sort_key)
	elif path.exists():
		matched = [path]
	else:
		# not an existing file or directory - treat as a glob pattern
		matched = sorted(path.parent.glob(path.name), key=_rotation_sort_key)

	if not matched:
		raise FileNotFoundError(f"No files matched: {target}")
	return matched


def load_raw_events(target: str | Path) -> list[dict]:
	"""Load raw Cowrie events from one or more JSONL files as a plain
	list of dicts. Cowrie writes JSON Lines (one JSON object per line,
	not a single JSON array) - each line is parsed individually so one
	malformed line doesn't take down the whole file."""
	matched_files = resolve_log_files(target)

	events = []
	for file_path in matched_files:
		with open(file_path, "r") as f:
			for line_number, line in enumerate(f, start=1):
				line = line.strip()
				if not line:
					continue
				try:
					events.append(json.loads(line))
				except json.JSONDecodeError as e:
					print(f"WARNING: skipped malformed line {line_number} in {file_path.name}: {e}")

	return events


def load_events_df(target: str | Path) -> pd.DataFrame:
	"""Raw event-level DataFrame, one row per event - the same shape
	you'd get from pd.read_json(path, lines=True), just combined across
	however many files `target` resolves to. This is the frame to use
	for event-level exploration (e.g. df['src_ip'].value_counts())."""
	events = load_raw_events(target)
	return pd.DataFrame(events)


# Named constant rather than a magic string repeated across the groupby
# logic below - the two eventids that represent a login attempt.
LOGIN_EVENT_IDS = ["cowrie.login.failed", "cowrie.login.success"]


def build_session_summaries_df(events_df: pd.DataFrame) -> pd.DataFrame:
	"""Group the raw event-level frame down to one row per session.

	Each eventid type carries different meaningful columns (src_ip only
	on connect, duration only on closed, username/password only on
	login events, etc.) - so this filters to the relevant event subset
	per field, aggregates each subset separately with groupby(), then
	joins them back together on session ID rather than one single agg()
	call trying to handle every field's different logic at once."""

	all_session_ids = events_df["session"].dropna().unique()
	sessions = pd.DataFrame({"session_id": all_session_ids}).set_index("session_id")

	# --- connect / closed: one row expected per session, first/last wins
	# if a session somehow has more than one (shouldn't happen, but
	# drop_duplicates guards against it silently breaking the join).
	# Guarded against a batch with zero connect/closed events at all,
	# same reasoning as commands/downloads below. ---
	if {"session", "src_ip", "timestamp"}.issubset(events_df.columns):
		connects = (
			events_df[events_df["eventid"] == "cowrie.session.connect"]
			[["session", "src_ip", "timestamp"]]
			.drop_duplicates(subset="session", keep="first")
			.rename(columns={"session": "session_id", "timestamp": "start_time"})
			.set_index("session_id")
		)
	else:
		connects = pd.DataFrame(columns=["src_ip", "start_time"])

	if {"session", "timestamp", "duration"}.issubset(events_df.columns):
		closes = (
			events_df[events_df["eventid"] == "cowrie.session.closed"]
			[["session", "timestamp", "duration"]]
			.drop_duplicates(subset="session", keep="last")
			.rename(columns={"session": "session_id", "timestamp": "end_time", "duration": "duration_seconds"})
			.set_index("session_id")
		)
	else:
		closes = pd.DataFrame(columns=["end_time", "duration_seconds"])

	# --- logins: both failed and successful count as an "attempt" ---
	logins = events_df[events_df["eventid"].isin(LOGIN_EVENT_IDS)].copy()
	if not logins.empty:
		logins["credential"] = logins["username"].astype(str) + ":" + logins["password"].astype(str)

		login_agg = logins.groupby("session").agg(
			login_attempts=("eventid", "size"),
			# any() across the group - True if at least one success event is present
			login_success=("eventid", lambda s: (s == "cowrie.login.success").any()),
			attempted_credentials=("credential", list),
		)
		login_agg.index.name = "session_id"

		successful = (
			logins[logins["eventid"] == "cowrie.login.success"]
			.groupby("session")["credential"].first()
			.rename("successful_credentials")
		)
		successful.index.name = "session_id"
	else:
		login_agg = pd.DataFrame(columns=["login_attempts", "login_success", "attempted_credentials"])
		successful = pd.Series(name="successful_credentials", dtype=object)

	# --- commands / downloads: list per session. Guarded the same way as
	# logins above - if this batch has zero command/download events, the
	# 'input'/download columns never existed in events_df at all (pandas only
	# creates columns for keys present in the source dicts), so filtering
	# by eventid still leaves a column-less frame that groupby() can't
	# index into. ---
	if "input" in events_df.columns:
		commands = (
			events_df[events_df["eventid"] == "cowrie.command.input"]
			.groupby("session")["input"].apply(list)
			.rename("commands")
		)
		commands.index.name = "session_id"
	else:
		commands = pd.Series(name="commands", dtype=object)

	download_fields = [
		field for field in ("url", "destfile", "outfile", "shasum")
		if field in events_df.columns
	]
	if download_fields:
		download_events = events_df[
			events_df["eventid"] == "cowrie.session.file_download"
		].copy()
		# Cowrie's file_download schema varies by transfer mechanism/version.
		# Prefer the source URL when present, then the destination path, stored
		# artifact path, and finally SHA-256 as a stable artifact identifier.
		download_events["download_reference"] = (
			download_events[download_fields].bfill(axis=1).iloc[:, 0]
		)
		downloads = (
			download_events.dropna(subset=["download_reference"])
			.groupby("session")["download_reference"].apply(list)
			.rename("files_downloaded")
		)
		downloads.index.name = "session_id"
	else:
		downloads = pd.Series(name="files_downloaded", dtype=object)

	event_counts = events_df.groupby("session").size().rename("event_count")
	event_counts.index.name = "session_id"

	# --- join everything back onto the full session index ---
	sessions = (
		sessions
		.join(connects)
		.join(closes)
		.join(login_agg)
		.join(successful)
		.join(commands)
		.join(downloads)
		.join(event_counts)
	)

	# Fill defaults for sessions that had no login/command/download events
	# at all - join() leaves these as NaN, but SessionSummary expects
	# proper types (0, False, [], None), not NaN.
	sessions["login_attempts"] = sessions["login_attempts"].fillna(0).astype(int)
	sessions["login_success"] = sessions["login_success"].fillna(False).astype(bool)
	sessions["event_count"] = sessions["event_count"].fillna(0).astype(int)
	sessions["src_ip"] = sessions["src_ip"].fillna("unknown")

	# List columns: NaN -> empty list. .apply() here because a plain
	# .fillna([]) doesn't work element-wise on object columns holding lists.
	for col in ["attempted_credentials", "commands", "files_downloaded"]:
		sessions[col] = sessions[col].apply(lambda v: v if isinstance(v, list) else [])

	return sessions.reset_index()


def dataframe_to_summaries(sessions_df: pd.DataFrame) -> list[SessionSummary]:
	"""Convert a session-level DataFrame (from build_session_summaries_df(),
	or a filtered subset of it) into SessionSummary objects - the typed
	boundary object triage.py / session_assessment.py / audit_log.py
	expect. Pydantic handles NaN->None coercion for the Optional fields."""
	records = sessions_df.to_dict(orient="records")
	summaries = []
	for r in records:
		# pandas leaves genuinely-missing optional fields as float('nan'),
		# which Pydantic won't accept for an Optional[str] - convert to
		# None explicitly rather than letting validation fail.
		for key in ("start_time", "end_time", "duration_seconds", "successful_credentials"):
			if pd.isna(r.get(key)):
				r[key] = None
		summaries.append(SessionSummary(**r))
	return summaries


def parse_sessions(target: str | Path, verbose: bool = True) -> list[SessionSummary]:
	"""Full pipeline: resolve file(s) -> event-level DataFrame ->
	session-level DataFrame -> SessionSummary objects.

	`target` accepts exactly what resolve_log_files() does: an exact
	file, a directory, or a wildcard pattern string.

	verbose=True (default) prints a stats overview at parse time - see
	session_stats.print_overview(). This is the intended entry point for
	'parse it and show me what's in it' rather than two separate steps."""
	events_df = load_events_df(target)
	sessions_df = build_session_summaries_df(events_df)

	if verbose:
		from wraith.enrichment.session_stats import print_overview
		print_overview(events_df)

	return dataframe_to_summaries(sessions_df)

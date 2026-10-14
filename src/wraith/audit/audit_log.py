"""
WRAITH - audit trail

Append-only, structured log of every session assessment: rule-based skips
and LLM assessments alike. Every record captures not just the decision,
but how it was reached (model, temperature, seed) and every technique
decision with its justification - including excluded candidates, which is
where the most interesting review-worthy findings tend to hide (see:
T1078 "not significant in isolation" exclusion on a session that also
had four other included techniques - correct in isolation, contextually
blind in practice, 2026-08-06).

Format: JSONL (one JSON object per line). Chosen over a database for now -
trivial to append to, human-greppable, diffable, loads straight into
pandas later. Revisit only once volume actually justifies it.

Records are never edited or overwritten. Re-running the same session
through an updated prompt/model produces a NEW record, not a replacement -
the history of how an assessment changed over iterations is itself
useful, not just the latest result.
"""

import hashlib
import json
from uuid import uuid4
from datetime import datetime, timezone
from pathlib import Path

# This module lives at src/wraith/audit, so parents[3] is the repo root.
DEFAULT_LOG_PATH = Path(__file__).resolve().parents[3] / "logs" / "audit_trail.jsonl"

# Heuristic flag: an excluded technique whose justification uses
# isolation-type language, on a session that ALSO has other included
# techniques, gets flagged for human review. Cheap, not a solved problem -
# a starting point for surfacing contextually-blind exclusions like the
# T1078 case, not a claim that this catches every such case.
ISOLATION_LANGUAGE = ["in isolation", "on its own", "alone", "by itself"]


def _looks_contextually_blind(techniques: list) -> str | None:
	"""Check for an excluded technique justified via isolation-language
	on a session that has other included techniques. Returns a reason
	string if flagged, else None."""
	included = [t for t in techniques if t.included]
	if not included:
		return None

	for t in techniques:
		if t.included:
			continue
		justification_lower = t.justification.lower()
		if any(phrase in justification_lower for phrase in ISOLATION_LANGUAGE):
			return (
				f"{t.technique_id} excluded using isolation-type language "
				f"('{t.justification}') despite {len(included)} other "
				f"technique(s) included in the same session"
			)
	return None


def new_run_context(input_files, model: str, source_files=()) -> dict:
	"""Create once per run; hashes identify inputs and assessment implementation."""
	def fingerprints(paths):
		rows = []
		for value in paths:
			path = Path(value)
			with path.open("rb") as stream:
				digest = hashlib.file_digest(stream, "sha256").hexdigest()
			rows.append({"path": str(path.resolve()), "sha256": digest})
		return rows
	return {
		"run_id": str(uuid4()),
		"started_at": datetime.now(timezone.utc).isoformat(),
		"requested_model": model,
		"input_files": fingerprints(input_files),
		"implementation_files": fingerprints(source_files),
	}


def build_record(result: dict, model: str, temperature: float, seed: int, run_context=None) -> dict:
	"""Turn one triage_batch() result dict into a structured audit record."""
	assessment = result.get("assessment")

	record = {
		"run_context": run_context,
		"timestamp": datetime.now(timezone.utc).isoformat(),
		"session_id": result["session_id"],
		"src_ip": result["src_ip"],
		"method": result["method"],
		"classification": result["classification"],
		"confidence": result["confidence"],
		"model": model if result["method"] == "LLM assessment" else None,
		"temperature": temperature if result["method"] == "LLM assessment" else None,
		"seed": seed if result["method"] == "LLM assessment" else None,
		"summary": assessment.summary if assessment else None,
		"techniques": (
			[
				{
					"technique_id": t.technique_id,
					"included": t.included,
					"justification": t.justification,
				}
				for t in assessment.techniques
			]
			if assessment else []
		),
		"ioc_history": (
			{
				"indicator": result["ioc_history"].indicator,
				"related_session_ids": result["ioc_history"].related_session_ids,
				"any_login_success": result["ioc_history"].any_login_success,
				"total_commands": result["ioc_history"].total_commands,
				"total_downloads": result["ioc_history"].total_downloads,
			}
			if result.get("ioc_history") else None
		),
		"flagged_for_review": False,
		"flag_reason": None,
	}

	if assessment:
		flag_reason = _looks_contextually_blind(assessment.techniques)
		if flag_reason:
			record["flagged_for_review"] = True
			record["flag_reason"] = flag_reason

	return record


def append_record(record: dict, path: Path = DEFAULT_LOG_PATH) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	with open(path, "a") as f:
		f.write(json.dumps(record) + "\n")


def log_batch(results: list[dict], model: str, temperature: float = 0,
              seed: int = 42, path: Path = DEFAULT_LOG_PATH, run_context=None) -> list[dict]:
	"""Log every result from a triage_batch() run. Returns the list of
	records written, so the caller can inspect flagged ones immediately
	without re-reading the log file."""
	if run_context is None:
		run_context = new_run_context([], model)
	records = []
	for result in results:
		record = build_record(result, model, temperature, seed, run_context)
		append_record(record, path)
		records.append(record)

	flagged = [r for r in records if r["flagged_for_review"]]
	if flagged:
		print(f"\n{len(flagged)} record(s) flagged for review:")
		for r in flagged:
			print(f"  [{r['session_id']}] {r['flag_reason']}")

	return records

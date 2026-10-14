"""
WRAITH - triage layer

Two deterministic (non-LLM) functions that sit either side of LLM
assessment:

1. is_trivial_session() - filters out sessions with no meaningful signal
   BEFORE they reach the LLM at all. A bare connect/disconnect with no
   login attempts and no commands doesn't need model judgment - it's
   benign by definition, and sending it to the LLM only creates
   hallucination surface for no benefit (see: a1b2c3d4/0f1e2d3c
   inventing T1210 from nothing, 2026-08-06).

2. correlate_ioc() - runs AFTER a session is flagged suspicious/malicious
   by its own individual assessment. Looks up other activity from the
   same indicator (currently: source IP) across the full dataset. This
   replaces an earlier approach of asking the LLM to reason about
   correlation inside a single-session prompt - that was unreliable
   (multi-fact reasoning across sessions is exactly where these models
   are weakest) and is properly a deterministic lookup, not a judgment
   call. This is also where the future "Document" layer's known-bad/
   known-good IoC check will eventually plug in.

IoCHistory is a small dataclass (same reasoning as TechniqueCandidate in
attack_mapping.py) - a fixed handful of named fields passed between
functions, not something that needs full class machinery beyond that.

triage_batch() runs the WHOLE batch before returning anything - fine for
a small synthetic set, but on a real multi-hour run against live Pi data
it means zero visibility until every session is done, and nothing gets
logged to the audit trail until the very end either. iter_triage() below
is the same logic as a generator, yielding one result at a time as it's
computed, so a caller (notebook, CLI) can print progress and log each
result immediately rather than waiting on the whole batch. triage_batch()
is kept as-is and now just consumes the generator, so main() and anything
else already calling it is unaffected.
"""

from dataclasses import dataclass


def is_trivial_session(summary) -> bool:
	"""A session is trivial if it has no login attempts, no commands,
	no downloads, and a near-instant duration. These are connect/scan
	noise with nothing for an LLM to meaningfully assess."""
	return (
		summary.login_attempts == 0
		and len(summary.commands) == 0
		and len(summary.files_downloaded) == 0
		and (summary.duration_seconds or 0) < 1.0
	)


@dataclass
class IoCHistory:
	indicator: str
	related_session_ids: list[str]
	any_login_success: bool
	total_commands: int
	total_downloads: int


def correlate_ioc(target, all_summaries) -> IoCHistory:
	"""Given a flagged session, look up all OTHER sessions sharing its
	source IP across the full dataset. Purely deterministic aggregation -
	no LLM involved. Call this only after a session has independently
	earned a suspicious/malicious classification, not on every session."""
	related = [
		s for s in all_summaries
		if target.src_ip and s.src_ip == target.src_ip and s.session_id != target.session_id
	]

	return IoCHistory(
		indicator=target.src_ip,
		related_session_ids=[s.session_id for s in related],
		any_login_success=any(s.login_success for s in related),
		total_commands=sum(len(s.commands) for s in related),
		total_downloads=sum(len(s.files_downloaded) for s in related),
	)


def iter_triage(summaries: list, analyze_fn, base_url: str, model: str, *, correlation_summaries=None):
	"""Same triage flow as triage_batch(), but yields one result at a
	time instead of returning a full list at the end. Lets a caller show
	progress and log each result as it's produced, rather than waiting
	on the entire batch with no visibility.

	analyze_fn is passed in (rather than imported directly) to keep this
	module independent of session_assessment.py's specific signature.
	"""
	correlation_pool = summaries if correlation_summaries is None else correlation_summaries
	for summary in summaries:
		if is_trivial_session(summary):
			yield {
				"session_id": summary.session_id,
				"src_ip": summary.src_ip,
				"assessment": None,
				"classification": "benign",
				"confidence": "high",
				"method": "rule-based (trivial session, LLM skipped)",
				"ioc_history": None,
			}
			continue

		assessment = analyze_fn(summary, base_url, model)
		if assessment is None:
			yield {
				"session_id": summary.session_id,
				"src_ip": summary.src_ip,
				"assessment": None,
				"classification": "unknown",
				"confidence": "low",
				"method": "LLM assessment failed guardrails",
				"ioc_history": None,
			}
			continue

		ioc_history = None
		if assessment.classification in ("suspicious", "malicious"):
			ioc_history = correlate_ioc(summary, correlation_pool)

		yield {
			"session_id": summary.session_id,
			"src_ip": summary.src_ip,
			"assessment": assessment,
			"classification": assessment.classification,
			"confidence": assessment.confidence,
			"method": "LLM assessment",
			"ioc_history": ioc_history,
		}


def triage_batch(summaries: list, analyze_fn, base_url: str, model: str) -> list[dict]:
	"""Run the full triage flow over a batch of parsed sessions and
	return every result as a list. Thin wrapper over iter_triage() kept
	for backwards compatibility (e.g. session_assessment.py's main()) -
	prefer iter_triage() directly for anything long-running where
	per-session progress/logging matters."""
	return list(iter_triage(summaries, analyze_fn, base_url, model))

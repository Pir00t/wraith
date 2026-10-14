"""
WRAITH - ATT&CK technique enrichment

Deterministic keyword/pattern matching against parsed session data to
generate a CANDIDATE list of MITRE ATT&CK techniques. Technique NAMES are
resolved from the local MITRE lookup (attack_lookup.py) - see that file
for why names aren't hardcoded here.

Thresholds are named constants rather than inline magic numbers, following
the pattern used by Panther's detection rules (panther-labs/panther-analysis)
where thresholds are explicit, documented config values rather than buried
in conditional logic.

TechniqueCandidate is a small dataclass rather than a plain dict - it's
passed between several functions/files as a fixed 3-field structure, and
named fields (candidate.technique_id) are easier to read at the call site
than dict key lookups (candidate["technique_id"]). This is the extent of
class usage this module needs.

This is a starter set, not exhaustive - expand as you encounter new
patterns in real Pi4/Cowrie data.
"""

import re
from dataclasses import dataclass

from wraith.enrichment.attack_lookup import load_lookup, resolve_technique


# --- Named thresholds (Panther-style: explicit, not buried in conditionals) ---
BRUTE_FORCE_MIN_ATTEMPTS = 3      # >= this many login attempts before T1110.001 applies
VALID_ACCOUNTS_MAX_ATTEMPTS = 2   # T1078 only applies if success came within this many attempts
                                   # (a success after many attempts is the culmination of
                                   # brute force, not evidence of a "valid"/leaked account -
                                   # see LLM's own reasoning on this distinction, 2026-08-06)


@dataclass
class TechniqueCandidate:
	technique_id: str
	name: str
	matched_on: str  # what triggered this match, for auditability


# Pattern -> technique_id only. Name is resolved from the MITRE lookup at
# match time, not stored here.
COMMAND_PATTERNS: list[tuple[str, str]] = [
	(r"\buname\b|\bcat /proc/cpuinfo\b|\bcat /etc/os-release\b|\blscpu\b", "T1082"),
	(r"\bwhoami\b|\bid\b|\bw\b|\bwho\b", "T1033"),
	(r"\bwget\b|\bcurl\b.*(-O|--output)", "T1105"),
	(r"\bchmod \+x\b", "T1222.002"),
	(r"\bhistory -c\b|\brm.*\.bash_history\b|\bunset HISTFILE\b", "T1070.003"),
	(r"\bcrontab\b|\becho.*>> /etc/cron", "T1053.003"),
	(r"\biptables\b.*-F|\bufw disable\b", "T1562.004"),
	(r"\bnc\b|\bnetcat\b|\b/dev/tcp/", "T1095"),
	(r"\bpasswd\b|\buseradd\b|\bssh-keygen\b|\bauthorized_keys\b", "T1098"),
]


def _resolve(technique_id: str, matched_on: str, lookup: dict) -> TechniqueCandidate | None:
	"""Resolve a technique_id against the MITRE lookup. Skips silently if
	the ID isn't real - this should never happen for IDs we've hardcoded
	above, but guards against a typo in this file going unnoticed."""
	info = resolve_technique(technique_id, lookup)
	if info is None:
		print(f"WARNING: {technique_id} not found in MITRE lookup - check attack_mapping.py for a typo")
		return None
	return TechniqueCandidate(technique_id=technique_id, name=info["name"], matched_on=matched_on)


def match_commands(commands: list[str], lookup: dict) -> list[TechniqueCandidate]:
	candidates = []
	seen_ids = set()

	for cmd in commands:
		for pattern, tid in COMMAND_PATTERNS:
			if re.search(pattern, cmd, re.IGNORECASE):
				if tid not in seen_ids:
					resolved = _resolve(tid, matched_on=cmd, lookup=lookup)
					if resolved:
						candidates.append(resolved)
						seen_ids.add(tid)

	return candidates


def match_session_metadata(login_attempts: int, login_success: bool,
                            downloads: list[str], lookup: dict) -> list[TechniqueCandidate]:
	candidates = []

	if login_attempts >= BRUTE_FORCE_MIN_ATTEMPTS:
		resolved = _resolve(
			"T1110.001",
			matched_on=f"{login_attempts} login attempts (threshold: {BRUTE_FORCE_MIN_ATTEMPTS})",
			lookup=lookup,
		)
		if resolved:
			candidates.append(resolved)

	if downloads:
		resolved = _resolve("T1105", matched_on=f"{len(downloads)} file(s) downloaded", lookup=lookup)
		if resolved:
			candidates.append(resolved)

	# T1078 (Valid Accounts) only applies when success follows a LOW attempt
	# count - a brute-forced success is the culmination of T1110, not a
	# separate Valid Accounts event. Attempt count is stated explicitly in
	# matched_on so the LLM has it directly in front of it rather than
	# needing to infer/recall it (see: model incorrectly speculating about
	# "possible brute-force" on a session with attempts=1, 2026-08-06).
	if login_success and login_attempts <= VALID_ACCOUNTS_MAX_ATTEMPTS:
		resolved = _resolve(
			"T1078",
			matched_on=f"successful auth after only {login_attempts} attempt(s) "
			           f"(max for this technique: {VALID_ACCOUNTS_MAX_ATTEMPTS})",
			lookup=lookup,
		)
		if resolved:
			candidates.append(resolved)

	return candidates


def enrich_session(commands: list[str], login_attempts: int,
                    login_success: bool, downloads: list[str]) -> list[TechniqueCandidate]:
	"""Full enrichment: combine command-based and metadata-based candidates."""
	lookup = load_lookup()

	candidates = match_commands(commands, lookup)
	candidates += match_session_metadata(login_attempts, login_success, downloads, lookup)

	seen = {}
	for c in candidates:
		if c.technique_id not in seen:
			seen[c.technique_id] = c
	return list(seen.values())

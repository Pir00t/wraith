# WRAITH — Project Status

Last updated: 2026-09-16

## Current pipeline

Status: working learning prototype

```text
Cowrie JSONL
→ pandas event DataFrame
→ deterministic session summaries
→ deterministic ATT&CK candidates
→ local Ollama assessment
→ Pydantic and candidate guardrails
→ rule-based correlation
→ append-only JSONL audit trail
```

## Completed

- Cowrie file, directory, and wildcard resolution
- Malformed JSONL line handling
- Sparse Cowrie event handling
- Session summaries for connections, logins, commands, and downloads
- Download-field compatibility for `url`, `destfile`, `outfile`, and `shasum`
- Deterministic ATT&CK candidate generation from a local MITRE lookup
- Structured Ollama output with per-session Pydantic schemas
- Trivial-session filtering and source-IP correlation
- Append-only audit records and contextual-review flags
- Installable `wraith` package layout
- Declared runtime and notebook dependencies
- Sanitized parser fixture and automated regression checks
- Correlation against all loaded sessions while assessing selected targets
- Per-run audit IDs with input and analysis-source hashes
- Reviewed-session payload manifests and hash-verified SCP collection
- Explicit untrusted-evidence boundary in the LLM prompt

## Current notebook workflow

`notebooks/01_playground.ipynb` is the main exploration path. Its first check parses a sanitized fixture and displays the resulting pandas session DataFrame. The remaining cells select real Cowrie logs, inspect event/session statistics, choose triage targets, call Ollama, and review results.

## Important design findings

Cowrie JSONL is sparse: pandas only creates columns for fields present in the selected batch. A batch can therefore have no `url`, `input`, or credential columns. Statistics and aggregation must treat missing event-specific columns as zero matching events.

Cowrie `cowrie.session.file_download` does not always contain a source URL. The observed Pi data uses `destfile`, `outfile`, and `shasum`, so WRAITH now chooses the most descriptive available artifact reference instead of assuming `url`.

Adversary-controlled commands must be retained as forensic evidence. WRAITH does not describe this as full sanitization: it serializes the evidence, places it inside a named untrusted-data boundary, instructs the model not to follow it, and validates the model's structured response afterward.

## Next priorities

1. Add more sanitized fixtures for failed/successful brute force, command-only activity, URL-based downloads, and incomplete sessions.
2. Add immutable Ollama model digests alongside run IDs, input hashes, and analysis-source hashes.
3. Improve ATT&CK pattern coverage using observed, labelled Cowrie sessions.
4. Add confidence review rules for novel or low-confidence activity.
5. Introduce orchestration only when the linear workflow has a concrete state-management limitation.

## Deferred

- Cross-case memory
- GeoIP and external threat-intelligence enrichment
- LangGraph orchestration
- DShield/SANS ISC reporting

These remain useful directions, but the deterministic parser, evidence model, and reproducible audit trail come first.

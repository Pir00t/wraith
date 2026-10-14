# WRAITH

**W**orkbench for **R**apid **A**nalysis, **I**ntelligence & **T**riage **H**unts

An AI-augmented workbench for digital forensics, threat hunting, and rapid incident triage — combining honeypot-sourced attacker data, structured DFIR parsing, and LLM-driven analysis to accelerate investigation workflows.

WRAITH is a defensive security research and portfolio project. It does not perform offensive operations against third-party systems — all data ingested comes from self-hosted honeypot sensors under the operator's own control.

---

## Overview

WRAITH exists to explore how LLM-based agents can meaningfully assist — not replace — human analysts during incident triage. Rather than pointing a model at raw logs and hoping for the best, WRAITH deliberately separates deterministic parsing from LLM reasoning, wraps model output in guardrails before it ever reaches case history, and keeps an auditable trail of every decision the system makes.

The name leans into the imagery on purpose: something that watches quietly from the shadows, observes what haunts the honeypot, and reports back — a fitting metaphor for a passive, always-on triage layer sitting behind live sensors.

---

## Architecture

```
[Data Sources]
      ↓
[Parsing / DFIR Tooling]        ← deterministic, Python-based
      ↓
[LLM Layer (Ollama)]            ← initial assessment + on-demand tool calls
      ↓
[LangGraph Orchestration]       ← manages state across passes
      ↓
[Guardrails + Validation]       ← sanitizes/validates before persistence
      ↓
[Memory + Case Tracking]        ← per-case context, structured history
      ↓
[Audit Trail / Reporting]       ← append-only log of every decision
```

### Layer breakdown

**Data Sources**
Real attacker telemetry from a self-hosted Cowrie honeypot (SSH/Telnet), network-isolated on a dedicated segment. Optional synthetic/labeled data via Atomic Red Team or Caldera for ground-truth ATT&CK technique validation.

**Parsing / DFIR Tooling**
Deterministic extraction of session IDs, source IPs, command sequences, timings, and downloaded-artifact references from raw Cowrie JSONL. Event values remain evidence rather than being silently rewritten. Before the LLM boundary they are serialized as structured JSON and placed inside an explicitly named untrusted-data section; this reduces prompt-injection risk but does not claim to eliminate it.

**LLM Layer**
Runs locally via Ollama. Reads structured session summaries (not raw logs) to produce MITRE ATT&CK-mapped assessments and narrative summaries. Can invoke parsing functions as tools mid-reasoning when it needs additional context (e.g. checking prior sightings of a source IP), rather than working from a single static snapshot.

**LangGraph Orchestration**
Coordinates state across parsing, LLM calls, tool invocations, and guardrail checks as a graph rather than a linear script.

**Guardrails + Validation**
Sits between the LLM layer and case memory. Validates model output before it can be written to case history, preventing unvalidated or hallucinated conclusions from polluting future context.

**Memory + Case Tracking**
Per-case context by default (isolated per incident) rather than cumulative — favors auditability over cross-case pattern learning, at least for now.

**Audit Trail / Reporting**
Append-only record of every LLM decision and guardrail outcome, not just a final report. This is the layer that makes model-assisted conclusions defensible after the fact.

---

## Roadmap

- [ ] Core pipeline: parsing → LLM → guardrails → case tracking, end to end
- [ ] Cowrie honeypot integration with DShield/SANS ISC reporting
- [ ] Confidence-scoring for low-confidence/novel session patterns
- [ ] Human-in-the-loop parser proposal workflow for novel patterns
- [ ] Structured audit trail suitable for future fine-tuning/few-shot reuse

---

## Status

Early-stage / active development. Built as a home-lab research project — not production security tooling. Feedback and issues welcome.

## Local setup

WRAITH uses Python 3.13 and `uv`. From the repository root:

```text
uv sync --dev
```

The notebooks add the repository's `src` directory once and import modules through the `wraith` package. `01_playground.ipynb` begins with a sanitized parser-fixture check before operating on live Cowrie logs.

Real sensor telemetry in `data/raw/` and generated audit records in `logs/` are ignored by Git. Only deliberately sanitized files under `data/raw/fixtures/` should be committed.

### Pi log inventory and download

From the repository root, use the standalone helper (no additional Python packages):

```powershell
# List available files, sizes, modification times (UTC), and total size
python scripts/pi_logs.py list

# Download Cowrie JSON logs, including rotated files, into data/raw/
python scripts/pi_logs.py pull

# Refresh the active log when you already have a local copy
python scripts/pi_logs.py pull --pattern "cowrie.json" --overwrite

# Select rotated logs or a different local folder
python scripts/pi_logs.py pull --pattern "cowrie.json.2026-09-*" --dest "D:\Evidence\cowrie"
```

Defaults are `sentinel@100.111.235.18`, port 22, remote directory
`/home/cowrie/cowrie/var/log/cowrie`, and your home directory's `.ssh/id_ed25519` key.
Override these with `--host`, `--port`, `--remote-dir`, or `--key`.
The default destination is the repository's `data/raw/` regardless of the current directory.
`list` includes all regular, non-symlink files directly in the remote directory;
`--pattern` filters by filename. It reports file metadata, not event counts or log contents.

The helper requires local `ssh` and `scp`, Python 3 on the Pi, and connectivity to
the Pi (including Tailscale when using its address). It passes the key directly to
OpenSSH, so `ssh-add` is optional. An encrypted key can still prompt for its
passphrase for the inventory and each transfer; loading it into a running SSH agent
once per agent session avoids repeated prompts. Normal SSH host-key verification
remains enabled; verify the Pi's fingerprint when connecting for the first time.

Existing local files are skipped unless `--overwrite` is supplied. Transfers are
staged before replacing local files, so a failed transfer preserves the old copy.
Remote files are never deleted or changed. Active logs can grow or rotate during
listing/copying, so their listed size is a point-in-time observation and a download
is not a consistent snapshot of a running sensor. A file rotated away between
listing and copying may require retrying the command.

---

## Disclaimer

WRAITH processes data only from sensors the operator owns and controls. It is intended for research, learning, and portfolio purposes. Do not point it at systems or data you don't have explicit authorization to monitor.

### Reviewed payload collection

In notebook section 8, fill `REVIEWED_SESSION_IDS` after reviewing the evidence
and export `data/payload_manifest.json`. An empty selection exports no files.
Then run from the repository root:

```powershell
python scripts/pi_logs.py payloads --manifest data/payload_manifest.json
```

The default Pi store is `/home/cowrie/cowrie/var/lib/cowrie/downloads` (override
with `--payload-dir`); the local destination is `data/downloads/` (override with
`--dest`). This retrieves Cowrie's stored files, never attacker URLs, and executes
nothing. The manifest requires SHA-256 storage filenames and recorded hashes.
Repeated references transfer once. Verified existing copies are skipped. Local
hash mismatches require `--overwrite`; failed or mismatched remote copies never
replace local evidence. Other selected files continue after a failure, and the
command exits nonzero if any file fails. Re-run the notebook payload preview cell
after collection; set `COWRIE_DOWNLOAD_DIR` if using a custom local destination.

### Assessment run history

The playground assesses selected targets but correlates flagged sessions against
all loaded sessions. Correlation does not search historical audits or external data.
Each triage execution creates a run ID shared by its appended audit records,
recording start time, configured model name, selected session IDs, input log hashes,
and hashes of parser, prompt/assessment, ATT&CK mapping/lookup, and triage code.
Repeated assessments intentionally append new records; there is no automatic skip
of previously assessed sessions. Older records have no run context.

The model name is not an immutable Ollama digest. Code hashes identify the
implementation but do not archive its source. Keep input files unchanged during
analysis; the notebook checks for changes before triage and asks you to reload.

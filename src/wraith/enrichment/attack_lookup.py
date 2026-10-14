"""
WRAITH - MITRE ATT&CK technique lookup

Downloads the official MITRE ATT&CK Enterprise STIX dataset and builds a
lightweight local JSON lookup (technique_id -> name, tactics). This is
the authoritative source of truth for technique IDs and names - nothing
elsewhere in WRAITH should hardcode a technique name as a string.

Run this file directly to (re)build the local lookup file. It's a
periodic refresh, not something re-fetched on every pipeline run.

Usage:
	python -m wraith.enrichment.attack_lookup
	from wraith.enrichment.attack_lookup import load_lookup, resolve_technique
"""

import json
from pathlib import Path

import requests

SOURCE_URL = (
	"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
	"master/enterprise-attack/enterprise-attack.json"
)

# This module lives at src/wraith/enrichment, so parents[3] is the repo root.
DEFAULT_OUTPUT = Path(__file__).resolve().parents[3] / "data" / "processed" / "attack_lookup.json"


def build_lookup(source_url: str = SOURCE_URL) -> dict[str, dict]:
	"""Download the STIX bundle and extract a technique_id -> {name, tactics} map."""
	response = requests.get(source_url)
	response.raise_for_status()  # raises if MITRE's raw.githubusercontent.com URL 404s/errors
	data = response.json()

	lookup = {}
	for obj in data["objects"]:
		if obj.get("type") != "attack-pattern":
			continue
		if obj.get("revoked") or obj.get("x_mitre_deprecated"):
			continue

		technique_id = None
		for ref in obj.get("external_references", []):
			if ref.get("source_name") == "mitre-attack":
				technique_id = ref.get("external_id")
				break
		if not technique_id:
			continue

		tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
		lookup[technique_id] = {"name": obj.get("name"), "tactics": tactics}

	return lookup


def save_lookup(lookup: dict, output_path: Path = DEFAULT_OUTPUT) -> None:
	output_path.parent.mkdir(parents=True, exist_ok=True)
	with open(output_path, "w") as f:
		json.dump(lookup, f, indent=2)


def load_lookup(path: Path = DEFAULT_OUTPUT) -> dict[str, dict]:
	"""Load the local lookup file. Raises if it hasn't been built yet."""
	if not path.exists():
		raise FileNotFoundError(
			f"Lookup file not found at {path}. Run attack_lookup.py directly "
			"to build it first."
		)
	with open(path, "r") as f:
		return json.load(f)


def resolve_technique(technique_id: str, lookup: dict[str, dict]) -> dict | None:
	"""Look up a single technique ID. Returns None if not a real technique."""
	return lookup.get(technique_id)


def main() -> None:
	print(f"Fetching ATT&CK dataset from {SOURCE_URL} ...")
	lookup = build_lookup()
	print(f"Indexed {len(lookup)} techniques.")
	save_lookup(lookup)
	print(f"Saved to {DEFAULT_OUTPUT}")


if __name__ == "__main__":
	main()

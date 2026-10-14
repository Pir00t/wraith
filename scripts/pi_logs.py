"""List and fetch Pi logs and reviewed payloads using the installed OpenSSH tools."""

import argparse
from datetime import datetime, timezone
import fnmatch
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
REMOTE_LIST = """
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
rows = []
for p in root.iterdir():
	if p.is_file() and not p.is_symlink():
		s = p.stat()
		rows.append(dict(name=p.name, size=s.st_size, mtime=s.st_mtime))
print(json.dumps(sorted(rows, key=lambda r: r['name'])))
"""


def connection_options(args):
	return ["-i", str(args.key.expanduser()), "-o", "ConnectTimeout=15"]


def inventory(args):
	command = "python3 -c " + shlex.quote(REMOTE_LIST) + " " + shlex.quote(args.remote_dir)
	result = subprocess.run(
		["ssh", *connection_options(args), "-p", str(args.port), args.host, command],
		check=True, stdout=subprocess.PIPE, text=True,
	)
	return json.loads(result.stdout)


def select_logs(rows, pattern):
	return [row for row in rows if fnmatch.fnmatchcase(row["name"], pattern)]


def show(rows):
	print(f"{'File':48} {'Bytes':>14}  Modified (UTC)")
	for row in rows:
		modified = datetime.fromtimestamp(row["mtime"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
		print(f"{ascii(row['name']):48} {row['size']:14,}  {modified}")
	print(f"\n{len(rows)} file(s), {sum(row['size'] for row in rows):,} bytes total")


def download(args, rows):
	destination = args.dest.resolve()
	destination.mkdir(parents=True, exist_ok=True)
	# Conservative names work with Windows and both modern and legacy SCP.
	for row in rows:
		name = row["name"]
		if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", name) or name.endswith("."):
			raise ValueError(f"Unsupported filename: {name!r}")
	for row in rows:
		name = row["name"]
		target = destination / name
		if target.is_symlink():
			raise ValueError(f"Refusing symbolic link destination: {target}")
		if target.exists() and not args.overwrite:
			print(f"Skipping {name} (exists; use --overwrite to refresh)")
			continue
		# A failed transfer leaves the existing local copy intact.
		with tempfile.TemporaryDirectory(prefix=".pi-logs-", dir=destination) as staging:
			staged = Path(staging) / name
			remote = f"{args.host}:{args.remote_dir.rstrip('/')}/{name}"
			subprocess.run(
				["scp", *connection_options(args), "-P", str(args.port), remote, str(staged)],
				check=True,
			)
			staged.replace(target)
		print(f"Saved {target}")


def validate_manifest(manifest):
	if not isinstance(manifest, dict) or manifest.get("version") != 1 or not isinstance(manifest.get("files"), list):
		raise ValueError("Expected a version 1 payload manifest with a files list")
	seen = {}
	for row in manifest["files"]:
		if not isinstance(row, dict):
			raise ValueError("Manifest file entries must be objects")
		name, digest = row.get("stored_name"), row.get("sha256")
		# Cowrie's content-addressed store uses SHA-256 filenames.
		if not isinstance(name, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", name):
			raise ValueError(f"Expected a SHA-256 storage filename: {name!r}")
		if not isinstance(digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
			raise ValueError(f"Missing or invalid SHA-256 for {name}")
		if name.lower() != digest.lower():
			raise ValueError(f"Storage filename differs from recorded SHA-256: {name}")
		seen.setdefault(name, row)
	return list(seen.values())


def export_payload_manifest(events, session_ids, destination):
	"""Export only explicitly selected sessions; fail on incomplete download evidence."""
	selected = set(session_ids)
	rows = []
	for event in events.to_dict("records"):
		if event.get("session") not in selected or event.get("eventid") != "cowrie.session.file_download":
			continue
		outfile = event.get("outfile")
		if not isinstance(outfile, str) or ".." in PurePosixPath(outfile).parts or "\\" in outfile:
			raise ValueError("Download event has no usable Cowrie outfile")
		rows.append({
			"session_id": event["session"],
			"outfile": outfile,
			"stored_name": PurePosixPath(outfile).name,
			"sha256": event.get("shasum"),
		})
	manifest = {"version": 1, "files": rows}
	validate_manifest(manifest)
	path = Path(destination)
	path.parent.mkdir(parents=True, exist_ok=True)
	path.write_text(json.dumps(manifest, indent="\t") + "\n", encoding="utf-8")
	return manifest


def sha256(path):
	with path.open("rb") as stream:
		return hashlib.file_digest(stream, "sha256").hexdigest()


def download_payloads(args):
	manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
	rows = validate_manifest(manifest)
	destination = args.dest.resolve()
	destination.mkdir(parents=True, exist_ok=True)
	failures = 0
	for row in rows:
		name = row["stored_name"]
		digest = row["sha256"].lower()
		target = destination / name
		try:
			if target.is_symlink():
				raise ValueError(f"Refusing symbolic link destination: {target}")
			if target.exists():
				if sha256(target) == digest:
					print(f"Verified existing copy; skipping {name}")
					continue
				if not args.overwrite:
					raise ValueError(f"Existing copy hash mismatch: {name}; use --overwrite to replace")
			with tempfile.TemporaryDirectory(prefix=".pi-payload-", dir=destination) as staging:
				staged = Path(staging) / name
				remote = f"{args.host}:{args.payload_dir.rstrip('/')}/{name}"
				subprocess.run(
					["scp", *connection_options(args), "-P", str(args.port), remote, str(staged)],
					check=True,
				)
				if sha256(staged) != digest:
					raise ValueError(f"Downloaded hash mismatch: {name}; copy discarded")
				staged.replace(target)
			print(f"Verified and saved {target}")
		except (OSError, ValueError, subprocess.CalledProcessError) as exc:
			failures += 1
			print(f"Payload {name} failed (check remote file exists and is readable): {exc}", file=sys.stderr)
	print(f"{len(rows)} unique payload(s), {failures} failure(s)")
	return 1 if failures else 0


def main(argv=None):
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("action", choices=["list", "pull", "payloads"])
	parser.add_argument("--host", default="sentinel@100.111.235.18")
	parser.add_argument("--port", type=int, default=22)
	parser.add_argument("--key", type=Path, default=Path.home() / ".ssh" / "id_ed25519")
	parser.add_argument("--remote-dir", default="/home/cowrie/cowrie/var/log/cowrie")
	parser.add_argument("--pattern", help="Filename or wildcard; defaults to * for list, cowrie.json* for pull")
	parser.add_argument("--dest", type=Path, help="Defaults to data/raw for logs, data/downloads for payloads")
	parser.add_argument("--manifest", type=Path, help="Reviewed payload manifest for the payloads action")
	parser.add_argument("--payload-dir", default="/home/cowrie/cowrie/var/lib/cowrie/downloads")
	parser.add_argument("--overwrite", action="store_true", help="Replace existing files, including the active log")
	args = parser.parse_args(argv)
	if args.action == "payloads" and args.manifest is None:
		parser.error("payloads requires --manifest")
	if args.dest is None:
		args.dest = ROOT / "data" / ("downloads" if args.action == "payloads" else "raw")
	if not re.fullmatch(r"/[A-Za-z0-9_./-]+", args.payload_dir) or ".." in args.payload_dir.split("/"):
		parser.error("--payload-dir must be an absolute path with simple directory names")
	if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]*", args.host):
		parser.error("--host must be a hostname, IPv4 address, or user@host")
	if not re.fullmatch(r"/[A-Za-z0-9_./-]+", args.remote_dir) or ".." in args.remote_dir.split("/"):
		parser.error("--remote-dir must be an absolute path with simple directory names")
	if not 1 <= args.port <= 65535:
		parser.error("--port must be between 1 and 65535")
	try:
		if args.action == "payloads":
			return download_payloads(args)
		rows = select_logs(inventory(args), args.pattern or ("*" if args.action == "list" else "cowrie.json*"))
		show(rows)
		if not rows:
			print("No matching files.")
		elif args.action == "pull":
			download(args, rows)
		return 0
	except (OSError, ValueError, subprocess.CalledProcessError) as exc:
		print(f"Pi log operation failed: {exc}", file=sys.stderr)
		return 1


if __name__ == "__main__":
	raise SystemExit(main())

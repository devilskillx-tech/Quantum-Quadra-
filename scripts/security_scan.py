"""Conservative dependency-free Git-tracked file scan.

Checks common accidental secret formats and risky file names. Not a replacement
for GitHub secret scanning, code review, branch rules, or runtime authorization.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

DENIED_NAMES = frozenset({
    "id_rsa", "id_ed25519", ".npmrc", ".pypirc", ".netrc",
    "credentials.json", "service-account.json", "service_account.json",
})
DENIED_DIRECTORIES = frozenset({"secrets", "credentials", ".ssh", ".aws"})
DENIED_SUFFIXES = frozenset({
    ".pem", ".key", ".p12", ".pfx", ".sqlite", ".db", ".zip", ".7z",
    ".tar", ".gz",
})
EXAMPLE_ENVS = frozenset({".env.example", ".env.sample"})
TOKEN_FORMATS = {
    "private key block": re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "GitHub classic token": re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,}"),
    "GitHub fine-grained token": re.compile(rb"github_pat_[A-Za-z0-9_]{20,}"),
    "AWS access key ID": re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    "OpenAI API key": re.compile(rb"sk-(?:proj-)?[A-Za-z0-9_-]{32,}"),
}

def inspect_file(root: Path, relative: str) -> list[str]:
    name = PurePosixPath(relative)
    issues: list[str] = []
    if name.is_absolute() or ".." in name.parts:
        return ["unsafe path"]
    basename = name.name.lower()
    if basename in DENIED_NAMES or any(p.lower() in DENIED_DIRECTORIES for p in name.parts[:-1]):
        issues.append("sensitive file path")
    if basename == ".env" or (basename.startswith(".env.") and basename not in EXAMPLE_ENVS):
        issues.append("environment secrets file")
    if name.suffix.lower() in DENIED_SUFFIXES:
        issues.append("sensitive or opaque file extension")

    path = root.joinpath(*name.parts)
    if path.is_symlink():
        issues.append("symlink requires explicit review")
        return issues
    if not path.is_file():
        issues.append("not a regular readable file")
        return issues
    try:
        content = path.read_bytes()
    except OSError:
        issues.append("file could not be inspected")
        return issues
    for label, pattern in TOKEN_FORMATS.items():
        if pattern.search(content):
            issues.append(f"possible {label}")
    return issues

def tracked_paths(root: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True, capture_output=True,
    )
    return [p.decode("utf-8", errors="surrogateescape") for p in completed.stdout.split(b"\0") if p]

def main() -> int:
    try:
        paths = tracked_paths(ROOT)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: cannot enumerate tracked files ({type(exc).__name__})", file=sys.stderr)
        return 2
    if not paths:
        print("ERROR: repository has no tracked files", file=sys.stderr)
        return 2
    findings = 0
    for relative in paths:
        for reason in inspect_file(ROOT, relative):
            print(f"FAIL {relative}: {reason}")
            findings += 1
    if findings:
        print(f"Security scan failed: {findings} finding(s)")
        return 1
    print(f"Security scan passed: {len(paths)} tracked file(s) checked")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

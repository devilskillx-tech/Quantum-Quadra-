"""V7.7 evidence-bound CI verifier; executes from a separately approved trust root.

Security boundary: GitHub API metadata is independently queried, artifacts are fetched
from the referenced GitHub run, and candidate-controlled JSON is never authoritative.
This DOES NOT cryptographically attest the truth of test assertions: workflow source
and test implementation must be independently reviewed and pinned by an operator.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import urllib.error
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{40}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
SCHEMA_VERSION = "quadra.evidence.v77.1"
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024


class EvidenceError(ValueError):
    """Reject invalid or contradictory evidence."""


class EvidenceUnavailable(RuntimeError):
    """Required authoritative service/data could not be reached or interpreted."""


def json_strict(data: bytes | str):
    def unique(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                raise EvidenceError("duplicate JSON key")
            obj[k] = v
        return obj
    def reject_constant(s):
        raise EvidenceError("non-finite JSON constant")
    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=reject_constant)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise EvidenceError("invalid JSON or duplicate property") from exc


def require_keys(obj, keys, name):
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise EvidenceError(f"{name}: unexpected or missing fields")


def iso_time(value):
    if not isinstance(value, str):
        raise EvidenceError("invalid timestamp")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("invalid ISO timestamp") from exc
    if not dt.tzinfo:
        raise EvidenceError("timestamp missing timezone")
    return dt.astimezone(timezone.utc)


def valid_sha(s, kind=SHA):
    return isinstance(s, str) and bool(kind.fullmatch(s))


class StripCrossHostAuthorization(urllib.request.HTTPRedirectHandler):
    """Do not forward GitHub bearer token to artifact-storage redirect hosts."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != "https":
            raise EvidenceUnavailable("untrusted non-TLS GitHub artifact redirect")
        forwarded = super().redirect_request(req, fp, code, msg, headers, newurl)
        if forwarded is not None and urllib.parse.urlsplit(req.full_url).netloc != target.netloc:
            forwarded.remove_header("Authorization")
        return forwarded


class GitHubProvider:
    """Read-only authoritative GitHub API client. Token must be read-only."""
    def __init__(self, token=None, api="https://api.github.com"):
        self.token = token
        self.api = api.rstrip("/")

    def _request(self, path, max_bytes=2 * 1024 * 1024, accept="application/vnd.github+json"):
        headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "quadra-evidence-verify-v77"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(self.api + path, headers=headers)
        try:
            with urllib.request.build_opener(StripCrossHostAuthorization()).open(request, timeout=15) as response:
                # Limit decompression / unbounded API replies.
                body = response.read(max_bytes + 1)
        except (OSError, urllib.error.HTTPError, TimeoutError) as exc:
            raise EvidenceUnavailable("authoritative GitHub API unavailable") from exc
        if len(body) > max_bytes:
            raise EvidenceUnavailable("GitHub response size exceeded")
        return body

    def get_json(self, path):
        try:
            return json_strict(self._request(path))
        except EvidenceError as exc:
            raise EvidenceUnavailable("invalid GitHub API response") from exc

    def pr(self, repo, number):
        return self.get_json(f"/repos/{repo}/pulls/{number}")

    def run(self, repo, run_id):
        return self.get_json(f"/repos/{repo}/actions/runs/{run_id}")

    def job(self, repo, job_id):
        return self.get_json(f"/repos/{repo}/actions/jobs/{job_id}")

    def artifact(self, repo, artifact_id):
        return self.get_json(f"/repos/{repo}/actions/artifacts/{artifact_id}")

    def artifact_zip(self, repo, artifact_id):
        return self._request(f"/repos/{repo}/actions/artifacts/{artifact_id}/zip", max_bytes=MAX_ARTIFACT_BYTES,
                             accept="application/octet-stream")

    def workflow_sha(self, repo, path, commit):
        info = self.get_json(f"/repos/{repo}/contents/{path}?ref={commit}")
        return info.get("sha")


def junit_report(blob: bytes):
    if len(blob) > 2 * 1024 * 1024 or b"<!DOCTYPE" in blob.upper() or b"<!ENTITY" in blob.upper():
        raise EvidenceError("unsafe XML report")
    try:
        root = ET.fromstring(blob)
    except ET.ParseError as exc:
        raise EvidenceError("invalid JUnit XML") from exc
    if root.tag not in {"testsuite", "testsuites"}:
        raise EvidenceError("not JUnit XML")
    cases = root.findall(".//testcase")
    if not cases:
        raise EvidenceError("empty mandatory test suite")
    skipped = sum(len(c.findall("skipped")) for c in cases)
    failures = sum(len(c.findall("failure")) + len(c.findall("error")) for c in cases)
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    if not suites:
        raise EvidenceError("missing JUnit testsuite")
    declared = 0
    for suite in suites:
        try:
            total = int(suite.attrib["tests"])
            if total < 0:
                raise ValueError()
        except (KeyError, ValueError) as exc:
            raise EvidenceError("invalid JUnit test count") from exc
        declared += total
        for label in ("failures", "errors", "skipped"):
            try:
                claimed = int(suite.attrib.get(label, "0"))
            except ValueError as exc:
                raise EvidenceError("invalid JUnit failure counts") from exc
            if claimed != 0:
                raise EvidenceError("JUnit suite declares failures/errors/skips")
    if declared != len(cases):
        raise EvidenceError("JUnit count inconsistent")
    if failures or skipped:
        raise EvidenceError(f"JUnit failed/errors/skipped: {failures}/{skipped}")
    return len(cases)


def recovery_report(blob: bytes, budget: float, minimum=1):
    data = json_strict(blob)
    if not isinstance(data, list) or len(data) < minimum:
        raise EvidenceError("insufficient recovery observations")
    seen = set()
    for item in data:
        require_keys(item, ["scenario", "rto_seconds", "expected_cells", "recovered_cells", "lost_cells", "passed"], "observation")
        if not isinstance(item["scenario"], str) or not re.fullmatch(r"[a-z0-9_-]{1,64}", item["scenario"]):
            raise EvidenceError("invalid scenario")
        if item["scenario"] in seen:
            raise EvidenceError("duplicate recovery scenario")
        seen.add(item["scenario"])
        for key in ("expected_cells", "recovered_cells", "lost_cells"):
            if type(item[key]) is not int or item[key] < 0:
                raise EvidenceError("invalid recovered count")
        rto = item["rto_seconds"]
        if type(rto) not in (int, float) or not (0 <= rto <= budget):
            raise EvidenceError("RTO out of budget")
        if (item["passed"] is not True or item["lost_cells"] != 0 or
                item["expected_cells"] != item["recovered_cells"] or item["expected_cells"] == 0):
            raise EvidenceError("RPO failure or empty recovery")
    return len(data)


def safe_zip_entry(payload: bytes, target: str):
    if (not isinstance(target, str) or target.startswith("/") or ".." in target.split("/")
            or "\\" in target or not target or target.endswith("/")):
        raise EvidenceError("unsafe artifact path")
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise EvidenceError("artifact archive too large")
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            if len(entries) > 64 or not entries:
                raise EvidenceError("unexpected artifact ZIP contents")
            if sum(e.file_size for e in entries) > MAX_ARTIFACT_BYTES:
                raise EvidenceError("artifact expanded size too large")
            names = [e.filename for e in entries]
            if len(names) != len(set(names)) or target not in names:
                raise EvidenceError("missing or duplicated artifact entry")
            for entry in entries:
                if entry.filename.startswith("/") or ".." in entry.filename.split("/") or "\\" in entry.filename:
                    raise EvidenceError("invalid artifact ZIP path")
            content = archive.read(target)
    except (OSError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        raise EvidenceError("corrupt artifact ZIP") from exc
    return content


def validate_policy(policy):
    require_keys(policy, ["schema_version", "repository", "commit_sha", "pr_number", "max_age_hours", "approved_workflows", "controls"], "policy")
    if policy["schema_version"] != SCHEMA_VERSION or not isinstance(policy["repository"], str) or not REPO.fullmatch(policy["repository"]):
        raise EvidenceError("invalid policy identity")
    if not valid_sha(policy["commit_sha"]) or type(policy["pr_number"]) is not int or policy["pr_number"] <= 0:
        raise EvidenceError("invalid candidate")
    if type(policy["max_age_hours"]) is not int or not 1 <= policy["max_age_hours"] <= 720:
        raise EvidenceError("invalid freshness limit")
    if not isinstance(policy["approved_workflows"], dict) or not policy["approved_workflows"]:
        raise EvidenceError("missing trusted workflow pins")
    for path, sha in policy["approved_workflows"].items():
        if (not isinstance(path, str) or not path.startswith(".github/workflows/") or
                not path.endswith((".yml", ".yaml")) or ".." in path.split("/") or not valid_sha(sha)):
            raise EvidenceError("workflow not pinned")
    if not isinstance(policy["controls"], dict) or not policy["controls"]:
        raise EvidenceError("no required controls")
    for cid, cfg in policy["controls"].items():
        if not re.fullmatch(r"[a-z0-9-]{1,48}", cid):
            raise EvidenceError("invalid control ID")
        require_keys(cfg, ["workflow_path", "job_name", "artifact_name", "artifact_path", "type", "minimum", "rto_budget_seconds"], "control policy")
        if cfg["workflow_path"] not in policy["approved_workflows"]:
            raise EvidenceError("control workflow is not trusted")
        if any(not isinstance(cfg[k], str) or not cfg[k] for k in ("job_name", "artifact_name", "artifact_path")):
            raise EvidenceError("invalid control metadata")
        if cfg["type"] not in ("junit", "recovery") or type(cfg["minimum"]) is not int or cfg["minimum"] <= 0:
            raise EvidenceError("invalid control threshold")
        if cfg["type"] == "recovery":
            if type(cfg["rto_budget_seconds"]) not in (int, float) or cfg["rto_budget_seconds"] <= 0:
                raise EvidenceError("invalid recovery budget")
        elif cfg["rto_budget_seconds"] is not None:
            raise EvidenceError("unexpected RTO budget")


def verify(manifest, policy, provider, now=None):
    """Return authoritative limited-scope VERIFIED; throw on rejection/unavailability.

    The caller MUST load policy from a separately protected trust root, not from
    the candidate PR; neither a local policy nor this result is a deployment GO.
    """
    validate_policy(policy)
    require_keys(manifest, ["schema_version", "repository", "commit_sha", "pr_number", "generated_at", "controls"], "manifest")
    for key in ("schema_version", "repository", "commit_sha", "pr_number"):
        if manifest[key] != policy[key]:
            raise EvidenceError("manifest/candidate mismatch: " + key)
    if not isinstance(manifest["controls"], list) or len(manifest["controls"]) != len(policy["controls"]):
        raise EvidenceError("missing or extra evidence controls")
    now = now or datetime.now(timezone.utc)
    generated = iso_time(manifest["generated_at"])
    if generated > now + timedelta(minutes=5) or generated < now - timedelta(hours=policy["max_age_hours"]):
        raise EvidenceError("manifest expired or from future")
    repo, commit = policy["repository"], policy["commit_sha"]
    pr = provider.pr(repo, policy["pr_number"])
    if pr.get("head", {}).get("sha") != commit or pr.get("state") != "open" or pr.get("head", {}).get("repo", {}).get("full_name") != repo:
        raise EvidenceError("candidate PR is not at approved head")
    # GitHub serves file contents at the commit, but trust is pinned externally.
    for path, accepted_sha in policy["approved_workflows"].items():
        if provider.workflow_sha(repo, path, commit) != accepted_sha:
            raise EvidenceError("candidate modified trusted workflow")
    seen = set()
    results = {}
    for entry in manifest["controls"]:
        require_keys(entry, ["control_id", "run_id", "job_id", "artifact_id", "evidence_sha256", "result"], "control evidence")
        cid = entry["control_id"]
        if not isinstance(cid, str) or cid not in policy["controls"] or cid in seen:
            raise EvidenceError("duplicate or unapproved control")
        seen.add(cid)
        if entry["result"] != "PASS" or any(type(entry[k]) is not int or entry[k] < 1 for k in ("run_id", "job_id", "artifact_id")):
            raise EvidenceError("invalid declared result/IDs")
        if not valid_sha(entry["evidence_sha256"], HASH):
            raise EvidenceError("invalid evidence digest")
        cfg = policy["controls"][cid]
        run = provider.run(repo, entry["run_id"])
        if (run.get("id") != entry["run_id"] or run.get("head_sha") != commit or
                run.get("status") != "completed" or run.get("conclusion") != "success" or
                run.get("event") not in ("push", "pull_request") or
                run.get("head_repository", {}).get("full_name") != repo or
                str(run.get("path", "")).removeprefix(repo + "/") != cfg["workflow_path"]):
            raise EvidenceError("GitHub run does not match candidate and policy")
        t = iso_time(run.get("created_at"))
        if t > now + timedelta(minutes=5) or t < now - timedelta(hours=policy["max_age_hours"]):
            raise EvidenceError("run is expired")
        job = provider.job(repo, entry["job_id"])
        if (job.get("id") != entry["job_id"] or job.get("run_id") != entry["run_id"] or
                job.get("name") != cfg["job_name"] or job.get("status") != "completed" or
                job.get("conclusion") != "success" or
                job.get("run_attempt") != run.get("run_attempt")):
            raise EvidenceError("job failed or does not belong to current run attempt")
        artifact = provider.artifact(repo, entry["artifact_id"])
        if (artifact.get("id") != entry["artifact_id"] or artifact.get("expired") is not False or
                artifact.get("name") != cfg["artifact_name"] or
                artifact.get("workflow_run", {}).get("id") != entry["run_id"]):
            raise EvidenceError("artifact is not from matching workflow run")
        payload = safe_zip_entry(provider.artifact_zip(repo, entry["artifact_id"]), cfg["artifact_path"])
        if hashlib.sha256(payload).hexdigest() != entry["evidence_sha256"]:
            raise EvidenceError("artifact digest mismatch")
        if cfg["type"] == "junit":
            count = junit_report(payload)
            if count < cfg["minimum"]:
                raise EvidenceError("insufficient mandatory JUnit cases")
        else:
            count = recovery_report(payload, cfg["rto_budget_seconds"], cfg["minimum"])
        results[cid] = {"cases": count, "run_id": entry["run_id"], "job_id": entry["job_id"], "artifact_id": entry["artifact_id"], "sha256": entry["evidence_sha256"]}
    if seen != set(policy["controls"]):
        raise EvidenceError("missing required control")
    return {"status": "VERIFIED", "scope": "GITHUB_OBSERVED_EVIDENCE", "commit_sha": commit,
            "repository": repo, "pr_number": policy["pr_number"], "controls": results,
            "warning": "Not a signature attestation, approval of tests, branch ruleset audit, or deployment GO"}


def main(argv=None, provider=None):
    parser = argparse.ArgumentParser(description="Fail-closed GitHub-backed evidence verification")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--trusted-policy", required=True)
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)
    import os
    try:
        manifest = json_strict(Path(args.manifest).read_bytes())
        policy = json_strict(Path(args.trusted_policy).read_bytes())
        result = verify(manifest, policy, provider or GitHubProvider(token=os.getenv("GITHUB_TOKEN")))
        code = 0
    except EvidenceUnavailable as exc:
        result = {"status": "UNVERIFIABLE", "reason": str(exc)}
        code = 3
    except (EvidenceError, OSError, KeyError, TypeError, AttributeError) as exc:
        result = {"status": "REJECTED", "reason": str(exc)}
        code = 2
    text = json.dumps(result, sort_keys=True, indent=2)
    print(text)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    return code


if __name__ == "__main__":
    sys.exit(main())

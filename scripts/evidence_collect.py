"""Collect *claims* from GitHub for independent verification.

This collector is intentionally not a trust authority. The verifier re-fetches all
run/job/artifact metadata and bytes, using a trusted out-of-band policy.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

from scripts.evidence_verify import (
    EvidenceError, GitHubProvider, json_strict, safe_zip_entry, validate_policy,
)


def collect(policy: dict, run_ids: dict, provider: GitHubProvider) -> dict:
    validate_policy(policy)
    if set(run_ids) != set(policy["controls"]):
        raise EvidenceError("each required control needs an authorized run ID")
    repo = policy["repository"]
    result = {
        "schema_version": policy["schema_version"], "repository": repo,
        "commit_sha": policy["commit_sha"], "pr_number": policy["pr_number"],
        "generated_at": datetime.now(timezone.utc).isoformat(), "controls": [],
    }
    for control_id, cfg in sorted(policy["controls"].items()):
        run_id = run_ids[control_id]
        if type(run_id) is not int or run_id <= 0:
            raise EvidenceError("invalid run id")
        run = provider.run(repo, run_id)
        if (run.get("head_sha") != policy["commit_sha"] or run.get("conclusion") != "success"
                or run.get("status") != "completed"):
            raise EvidenceError("cannot collect evidence from wrong or incomplete commit")
        jobs = provider.get_json(f"/repos/{repo}/actions/runs/{run_id}/jobs?per_page=100")
        artifacts = provider.get_json(f"/repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100")
        if (not isinstance(jobs, dict) or not isinstance(artifacts, dict)
                or jobs.get("total_count", 0) > 100 or artifacts.get("total_count", 0) > 100):
            raise EvidenceError("partial or unexpected GitHub pagination")
        matching_jobs = [j for j in jobs.get("jobs", []) if j.get("name") == cfg["job_name"]]
        matching_arts = [a for a in artifacts.get("artifacts", []) if a.get("name") == cfg["artifact_name"]]
        if len(matching_jobs) != 1 or len(matching_arts) != 1:
            raise EvidenceError("missing/ambiguous job or artifact")
        job, artifact = matching_jobs[0], matching_arts[0]
        if (job.get("run_id") != run_id or job.get("conclusion") != "success" or
                artifact.get("expired") is not False or
                artifact.get("workflow_run", {}).get("id") != run_id):
            raise EvidenceError("job and artifact are inconsistent")
        blob = safe_zip_entry(provider.artifact_zip(repo, artifact["id"]), cfg["artifact_path"])
        result["controls"].append({
            "control_id": control_id, "run_id": run_id, "job_id": job["id"],
            "artifact_id": artifact["id"],
            "evidence_sha256": hashlib.sha256(blob).hexdigest(), "result": "PASS",
        })
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build UNVERIFIED candidate evidence manifest from GitHub")
    parser.add_argument("--trusted-policy", required=True)
    parser.add_argument("--run-ids", required=True, help="JSON control_id -> GitHub workflow run id")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    policy = json_strict(Path(args.trusted_policy).read_bytes())
    run_ids = json_strict(Path(args.run_ids).read_bytes())
    manifest = collect(policy, run_ids, GitHubProvider(token=os.environ.get("GITHUB_TOKEN")))
    Path(args.output).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("UNVERIFIED MANIFEST GENERATED; must pass independently pinned evidence verifier")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Read-only audit of GitHub effective branch rules.

Does not attempt merges and CANNOT prove enforcement of a non-compliant PR.
A ruleset configuration check is necessary, not sufficient, for CERT-A.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
from scripts.evidence_verify import EvidenceError, EvidenceUnavailable, GitHubProvider


def analyze_rulesets(rulesets, required_checks):
    if not isinstance(rulesets, list):
        raise EvidenceError("unexpected rulesets response")
    for item in rulesets:
        if not isinstance(item, dict):
            continue
        if item.get("target") != "branch" or item.get("enforcement") != "active":
            continue
        conditions = item.get("conditions", {}).get("ref_name", {})
        included = conditions.get("include", [])
        excluded = conditions.get("exclude", [])
        if (not isinstance(included, list) or not isinstance(excluded, list) or
                not ("refs/heads/main" in included or "~DEFAULT_BRANCH" in included) or
                "refs/heads/main" in excluded or item.get("bypass_actors")):
            continue
        rules = item.get("rules")
        if not isinstance(rules, list):
            continue
        by_type = {r.get("type"): r.get("parameters", {}) for r in rules if isinstance(r, dict)}
        pr = by_type.get("pull_request", {})
        checks = by_type.get("required_status_checks", {})
        names = {v.get("context") for v in checks.get("required_status_checks", []) if isinstance(v, dict)}
        if ("deletion" in by_type and "non_fast_forward" in by_type and
                pr.get("required_approving_review_count", 0) >= 1 and
                pr.get("dismiss_stale_reviews_on_push") is True and
                pr.get("require_last_push_approval") is True and
                pr.get("require_code_owner_review") is True and
                required_checks.issubset(names)):
            return {"configuration": "VERIFIED", "ruleset_id": item.get("id"),
                    "checks": sorted(names), "block_test": "NOT_PERFORMED"}
    return {"configuration": "NO-GO", "reason": "No active ruleset satisfies P0 controls"}


def audit(provider, repo: str, required_checks: set[str]) -> dict:
    # Full metadata (including bypass actors) requires privileged read access.
    summaries = provider.get_json(f"/repos/{repo}/rulesets?includes_parents=true&per_page=100")
    if not isinstance(summaries, list):
        raise EvidenceUnavailable("Could not enumerate complete rulesets")
    if len(summaries) == 100:
        raise EvidenceUnavailable("Potentially incomplete rulesets listing")
    details = []
    for item in summaries:
        if not isinstance(item, dict) or not isinstance(item.get("id"), int):
            raise EvidenceUnavailable("Invalid ruleset metadata")
        details.append(provider.get_json(f"/repos/{repo}/rulesets/{item['id']}"))
    result = analyze_rulesets(details, required_checks)
    # Never return VERIFIED (CERT-A) based solely on configuration metadata.
    return {"status": "UNVERIFIABLE", "repository": repo, "branch": "main", **result,
            "reason": "A blocked-merge acceptance test and independent approval are still required"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Read-only, fail-closed GitHub branch governance inspection")
    parser.add_argument("--repository", default="devilskillx-tech/Quantum-Quadra-")
    parser.add_argument("--required-check", action="append", default=["release-gate", "security"])
    parser.add_argument("--output", default="GITHUB_SECURITY_COMPLIANCE_V77.json")
    args = parser.parse_args(argv)
    import re
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        parser.error("invalid repository")
    try:
        result = audit(GitHubProvider(token=os.getenv("GITHUB_TOKEN")), args.repository,
                       set(args.required_check))
    except (EvidenceUnavailable, EvidenceError, OSError, TypeError) as exc:
        result = {"status": "UNVERIFIABLE", "repository": args.repository,
                  "branch": "main", "reason": type(exc).__name__ + ": " + str(exc)}
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "VERIFIED" else 3


if __name__ == "__main__":
    raise SystemExit(main())

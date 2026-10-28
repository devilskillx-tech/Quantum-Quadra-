"""Fail-closed TECHNICAL_PASS aggregator, never a deployment authorization.

CLI always re-verifies GitHub evidence and reads live governance rules. A static JSON
claim cannot generate TECHNICAL_PASS. Governance's blocked-merge proof is not
available through this connector; certification remains fail-closed by default.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
from scripts.evidence_verify import GitHubProvider, verify, json_strict, EvidenceError, EvidenceUnavailable
from scripts.github_governance_verify import audit


def evaluate(evidence: dict, governance: dict, reviewed: bool = False) -> dict:
    reasons = []
    if evidence.get("status") != "VERIFIED":
        reasons.append("Evidence not VERIFIED")
    if evidence.get("scope") != "GITHUB_OBSERVED_EVIDENCE":
        reasons.append("Evidence verification scope mismatch")
    if governance.get("status") != "VERIFIED":
        reasons.append("GitHub governance not verified")
    if governance.get("repository") != evidence.get("repository"):
        reasons.append("Repository mismatch")
    if governance.get("branch") != "main":
        reasons.append("Wrong branch governance")
    if not isinstance(evidence.get("controls"), dict) or not evidence.get("controls"):
        reasons.append("Missing verified controls")
    return {
        "status": "NO-GO" if reasons else "TECHNICAL_PASS",
        "production_go": False, "review_required": True,
        "human_review_seen": bool(reviewed),
        "commit_sha": evidence.get("commit_sha"),
        "reasons": reasons,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Independent live evidence and governance checks; no production GO")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--trusted-policy", required=True)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        manifest = json_strict(Path(args.manifest).read_bytes())
        policy = json_strict(Path(args.trusted_policy).read_bytes())
        provider = GitHubProvider(token=os.getenv("GITHUB_TOKEN"))
        evidence = verify(manifest, policy, provider)
        governance = audit(provider, policy["repository"], {"release-gate", "security"})
        result = evaluate(evidence, governance)
    except (OSError, EvidenceError, EvidenceUnavailable, KeyError, ValueError, TypeError) as exc:
        result = {"status":"NO-GO", "production_go":False,
                  "reasons": [type(exc).__name__+": "+str(exc)]}
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "TECHNICAL_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())

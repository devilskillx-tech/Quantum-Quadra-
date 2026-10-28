"""Normalize known safe recovery scenarios from V7.6 individual JSON measurements.

This prepares material for verification. Trust remains with independent evidence
verification against GitHub artifacts and a protected policy.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from scripts.evidence_verify import EvidenceError, json_strict

ALLOWED_SCENARIOS = frozenset({"sqlite_restore", "sqlite_revocation", "postgres_post_commit", "postgres_revocation"})


def build(directory: Path, scenarios: set[str]) -> bytes:
    if not scenarios or not scenarios.issubset(ALLOWED_SCENARIOS):
        raise EvidenceError("unknown or empty recovery scenarios")
    result=[]
    for scenario in sorted(scenarios):
        path=directory / (scenario + ".json")
        try:
            item=json_strict(path.read_bytes())
        except OSError as exc:
            raise EvidenceError("required recovery evidence missing") from exc
        required={"scenario", "rto_seconds", "rto_budget_seconds", "expected_cells", "recovered_cells", "lost_cells", "passed"}
        if not isinstance(item,dict) or set(item)!=required or item["scenario"]!=scenario:
            raise EvidenceError("unrecognized or invalid recovery observation")
        if type(item["passed"]) is not bool or not item["passed"]:
            raise EvidenceError("failed recovery observation")
        if type(item["rto_budget_seconds"]) not in (int,float) or item["rto_budget_seconds"]<=0:
            raise EvidenceError("invalid recovery budget")
        if type(item["rto_seconds"]) not in (int,float) or not 0<=item["rto_seconds"]<=item["rto_budget_seconds"]:
            raise EvidenceError("recovery outside its objective")
        result.append({key:item[key] for key in ("scenario","rto_seconds","expected_cells","recovered_cells","lost_cells","passed")})
    return (json.dumps(result,sort_keys=True,separators=(",",":"))+"\n").encode()


def main(argv=None):
    p=argparse.ArgumentParser(description="Prepare normalized recovery artifact from required scenarios")
    p.add_argument("--directory",required=True)
    p.add_argument("--scenario",action="append",required=True)
    p.add_argument("--output",required=True)
    args=p.parse_args(argv)
    payload=build(Path(args.directory),set(args.scenario))
    Path(args.output).write_bytes(payload)
    print("Normalized required recovery scenarios:",len(set(args.scenario)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

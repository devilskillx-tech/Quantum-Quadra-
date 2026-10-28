"""EV-01..EV-15: local adversarial fixtures, NOT live GitHub attestations."""
from __future__ import annotations
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
import zipfile
import pytest
from scripts.evidence_verify import (EvidenceError, EvidenceUnavailable, verify,
                                     json_strict, junit_report, recovery_report, safe_zip_entry)

COMMIT = "b" * 40
WORKFLOW_SHA = "a" * 40
REPO = "example/quantum-quadra"
NOW = datetime(2026, 10, 28, 15, 0, tzinfo=timezone.utc)
JUNIT = b'<testsuite tests="2" failures="0" errors="0" skipped="0"><testcase name="case1"/><testcase name="case2"/></testsuite>'
RECOVERY = json.dumps([{"scenario": "sqlite_restore", "rto_seconds": 0.2,
                       "expected_cells": 20, "recovered_cells": 20,
                       "lost_cells": 0, "passed": True}]).encode()


def zip_of(name, data):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, data)
    return buf.getvalue()


class FakeGitHub:
    def __init__(self):
        self.pr_data = {"state": "open", "head": {"sha": COMMIT, "repo": {"full_name": REPO}}}
        self.workflow_data = WORKFLOW_SHA
        self.runs = {}
        self.jobs = {}
        self.artifacts = {}
        self.zips = {}
        self.unavailable = False

    def guard(self):
        if self.unavailable:
            raise EvidenceUnavailable("GitHub unavailable")

    def pr(self, repo, number):
        self.guard()
        return self.pr_data

    def workflow_sha(self, repo, path, commit):
        self.guard()
        return self.workflow_data

    def run(self, repo, run_id):
        self.guard()
        return self.runs[run_id]

    def job(self, repo, job_id):
        self.guard()
        return self.jobs[job_id]

    def artifact(self, repo, artifact_id):
        self.guard()
        return self.artifacts[artifact_id]

    def artifact_zip(self, repo, artifact_id):
        self.guard()
        return self.zips[artifact_id]


def fixture():
    provider = FakeGitHub()
    controls = {
        "unit-tests": {"workflow_path": ".github/workflows/tests.yml", "job_name": "unit-tests",
                       "artifact_name": "unit-report", "artifact_path": "unit.xml", "type": "junit",
                       "minimum": 2, "rto_budget_seconds": None},
        "recovery": {"workflow_path": ".github/workflows/tests.yml", "job_name": "recovery-objectives",
                     "artifact_name": "recovery-report", "artifact_path": "rto.json", "type": "recovery",
                     "minimum": 1, "rto_budget_seconds": 10},
    }
    policy = {"schema_version": "quadra.evidence.v77.1", "repository": REPO,
              "commit_sha": COMMIT, "pr_number": 12, "max_age_hours": 72,
              "approved_workflows": {".github/workflows/tests.yml": WORKFLOW_SHA}, "controls": controls}
    manifest = {"schema_version": policy["schema_version"], "repository": REPO,
                "commit_sha": COMMIT, "pr_number": 12, "generated_at": "2026-10-28T14:00:00Z", "controls": []}
    for i, (cid, cfg) in enumerate(controls.items()):
        blob, filename = ((JUNIT, "unit.xml"), (RECOVERY, "rto.json"))[i]
        run_id, job_id, artifact_id = 100 + i, 200 + i, 300 + i
        provider.runs[run_id] = {"id": run_id, "head_sha": COMMIT, "status": "completed",
                                 "conclusion": "success", "event": "pull_request",
                                 "head_repository": {"full_name": REPO},
                                 "path": ".github/workflows/tests.yml", "created_at": "2026-10-28T14:00:00Z", "run_attempt": 1}
        provider.jobs[job_id] = {"id": job_id, "run_id": run_id, "name": cfg["job_name"],
                                 "status": "completed", "conclusion": "success", "run_attempt": 1}
        provider.artifacts[artifact_id] = {"id": artifact_id, "expired": False,
                                           "name": cfg["artifact_name"], "workflow_run": {"id": run_id}}
        provider.zips[artifact_id] = zip_of(filename, blob)
        manifest["controls"].append({"control_id": cid, "run_id": run_id, "job_id": job_id,
                                     "artifact_id": artifact_id, "evidence_sha256": hashlib.sha256(blob).hexdigest(),
                                     "result": "PASS"})
    return manifest, policy, provider


def attempt(mutator, error=EvidenceError):
    manifest, policy, provider = fixture()
    mutator(manifest, policy, provider)
    with pytest.raises(error):
        verify(manifest, policy, provider, now=NOW)


def test_ev01_forged_pass_in_json_but_real_job_failed():
    attempt(lambda m, p, g: g.jobs[200].update(conclusion="failure"))


def test_ev02_changed_junit_after_generation():
    attempt(lambda m, p, g: g.zips.__setitem__(300, zip_of("unit.xml", JUNIT.replace(b"case1", b"other"))))


def test_ev03_old_run_commit():
    attempt(lambda m, p, g: g.runs[100].update(head_sha="c"*40))


def test_ev04_required_control_missing():
    attempt(lambda m, p, g: m["controls"].pop())


def test_ev05_critical_junit_skipped():
    def mutate(m, p, g):
        altered = b'<testsuite tests="2"><testcase name="one"><skipped/></testcase><testcase name="two"/></testsuite>'
        g.zips[300] = zip_of("unit.xml", altered)
        m["controls"][0]["evidence_sha256"] = hashlib.sha256(altered).hexdigest()
    attempt(mutate)


def test_ev06_partially_executed_workflow():
    attempt(lambda m, p, g: g.runs[100].update(status="in_progress", conclusion=None))


def test_ev07_identity_not_approved_workflow_pin():
    attempt(lambda m, p, g: setattr(g, "workflow_data", "d"*40))


def test_ev08_conflicting_job_id():
    attempt(lambda m, p, g: g.jobs[200].update(run_id=999))


def test_ev09_falsified_artifact_sha():
    attempt(lambda m, p, g: m["controls"][0].update(evidence_sha256="f"*64))


def test_ev10_replay_against_different_pull_request():
    attempt(lambda m, p, g: g.pr_data["head"].update(sha="e"*40))


def test_ev11_authoritative_api_unavailable():
    attempt(lambda m, p, g: setattr(g, "unavailable", True), EvidenceUnavailable)


def test_ev12_unapproved_candidate_verifier_workflow():
    attempt(lambda m, p, g: p["approved_workflows"].update({".github/workflows/tests.yml": "f"*40}))


def test_ev13_rto_exceeded_despite_pass_flag():
    def mutate(m, p, g):
        value = json.loads(RECOVERY)
        value[0]["rto_seconds"] = 15.0
        blob = json.dumps(value).encode()
        g.zips[301] = zip_of("rto.json", blob)
        m["controls"][1]["evidence_sha256"] = hashlib.sha256(blob).hexdigest()
    attempt(mutate)


def test_ev14_manifest_incomplete():
    attempt(lambda m, p, g: m.update(unexpected="unsafe"))


def test_ev15_complete_valid_authenticated_metadata():
    m, p, g = fixture()
    result = verify(m, p, g, now=NOW)
    assert result["status"] == "VERIFIED"
    assert result["scope"] == "GITHUB_OBSERVED_EVIDENCE"
    assert result["controls"]["recovery"]["cases"] == 1


def test_tv01_duplicate_control_id():
    attempt(lambda m, p, g: m["controls"][1].update(control_id="unit-tests"))


def test_tv02_stale_generation():
    attempt(lambda m, p, g: m.update(generated_at="2025-10-28T14:00:00Z"))


def test_tv03_run_attempt_replayed():
    attempt(lambda m, p, g: g.jobs[200].update(run_attempt=2))


def test_tv04_artifact_origin_mismatch():
    attempt(lambda m, p, g: g.artifacts[300]["workflow_run"].update(id=666))


def test_tv05_malicious_zip_traversal():
    attempt(lambda m, p, g: g.zips.__setitem__(300, zip_of("../unit.xml", JUNIT)))


def test_tv06_junit_count_laundered():
    def mutate(m, p, g):
        altered = JUNIT.replace(b'tests="2"', b'tests="3"')
        g.zips[300] = zip_of("unit.xml", altered)
        m["controls"][0]["evidence_sha256"] = hashlib.sha256(altered).hexdigest()
    attempt(mutate)


def test_tv07_duplicate_json_properties():
    with pytest.raises(EvidenceError):
        json_strict('{"result":"FAIL","result":"PASS"}')


def test_tv08_run_path_different():
    attempt(lambda m, p, g: g.runs[100].update(path=".github/workflows/unsafe.yml"))


def test_schema_invalid_non_finite_rto():
    with pytest.raises(EvidenceError):
        recovery_report(b'[{"rto_seconds": NaN}]', budget=10)


def test_report_inconsistent_recovered_count():
    with pytest.raises(EvidenceError):
        recovery_report(json.dumps([{"scenario":"s", "rto_seconds":2, "expected_cells":3,
                                     "recovered_cells":1, "lost_cells":0,"passed":True}]).encode(), 10)


def test_invalid_pr_scope_fork_blocked():
    attempt(lambda m, p, g: g.pr_data["head"]["repo"].update(full_name="attacker/fork"))

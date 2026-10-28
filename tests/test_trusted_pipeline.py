"""Trusted-pipeline component tests. Fixtures do not attest GitHub production state."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import pytest
from scripts.evidence_collect import collect
from scripts.evidence_verify import EvidenceError, EvidenceUnavailable, json_strict, junit_report, verify
from scripts.github_governance_verify import analyze_rulesets, audit
from scripts.certification_gate import evaluate
from scripts.build_recovery_evidence import build
from tests import test_evidence_security as fixtures


class ExtendedFakeGitHub(fixtures.FakeGitHub):
    def get_json(self,path):
        if "/actions/runs/" in path and path.endswith("/jobs?per_page=100"):
            run_id=int(path.split("/actions/runs/")[1].split("/")[0])
            jobs=[x for x in self.jobs.values() if x["run_id"]==run_id]
            return {"total_count":len(jobs),"jobs":jobs}
        if "/actions/runs/" in path and path.endswith("/artifacts?per_page=100"):
            run_id=int(path.split("/actions/runs/")[1].split("/")[0])
            arts=[x for x in self.artifacts.values() if x["workflow_run"]["id"]==run_id]
            return {"total_count":len(arts),"artifacts":arts}
        if path.endswith("/rulesets?includes_parents=true&per_page=100"):
            return [{"id":12}]
        if path.endswith("/rulesets/12"):
            return self.ruleset
        raise AssertionError("unknown mock API path")


def faked():
    manifest, policy, fake = fixtures.fixture()
    remote=ExtendedFakeGitHub()
    remote.__dict__.update(fake.__dict__)
    return manifest,policy,remote


def test_collector_produces_manifest_accepted_after_independent_requery(monkeypatch):
    m,p,f=faked()
    monkeypatch.setattr("scripts.evidence_collect.datetime",_Clock)
    observed=collect(p,{"unit-tests":100,"recovery":101},f)
    assert verify(observed,p,f,now=fixtures.NOW)["status"]=="VERIFIED"


class _Clock:
    @staticmethod
    def now(_):return fixtures.NOW


def test_collector_rejects_missing_required_run():
    _,p,f=faked()
    with pytest.raises(EvidenceError):collect(p,{"unit-tests":100},f)


def test_collector_rejects_ambiguous_job(monkeypatch):
    _,p,f=faked()
    monkeypatch.setattr("scripts.evidence_collect.datetime",_Clock)
    f.jobs[777] = dict(f.jobs[200], id=777)
    with pytest.raises(EvidenceError,match="ambiguous"):
        collect(p,{"unit-tests":100,"recovery":101},f)


def test_junit_declared_error_without_case_is_rejected():
    with pytest.raises(EvidenceError):
        junit_report(b'<testsuite tests="1" errors="1"><testcase name="x"/></testsuite>')


def test_aggregate_recovery_real_shape(tmp_path):
    data={"scenario":"sqlite_restore","rto_seconds":0.01,"rto_budget_seconds":10.0,
          "expected_cells":5,"recovered_cells":5,"lost_cells":0,"passed":True}
    (tmp_path/"sqlite_restore.json").write_text(json.dumps(data))
    blob=build(tmp_path,{"sqlite_restore"})
    assert json_strict(blob)[0]["expected_cells"]==5
    with pytest.raises(EvidenceError):build(tmp_path,{"sqlite_revocation"})
    with pytest.raises(EvidenceError):build(tmp_path,{"unapproved"})


def _rules():
    return {"id":12,"target":"branch","enforcement":"active","bypass_actors":[],
            "conditions":{"ref_name":{"include":["refs/heads/main"],"exclude":[]}},
            "rules":[{"type":"deletion"},{"type":"non_fast_forward"},
                     {"type":"pull_request","parameters":{"required_approving_review_count":1,
                         "dismiss_stale_reviews_on_push":True,"require_last_push_approval":True,
                         "require_code_owner_review":True}},
                     {"type":"required_status_checks","parameters":{"required_status_checks":[
                         {"context":"release-gate"},{"context":"security"}]}}]}


def test_ruleset_configuration_check_does_not_issue_cert_a():
    data=analyze_rulesets([_rules()],{"release-gate","security"})
    assert data["configuration"]=="VERIFIED"
    _,_,provider=faked();provider.ruleset=_rules()
    observation=audit(provider,fixtures.REPO,{"release-gate","security"})
    assert observation["status"]=="UNVERIFIABLE"
    assert observation["configuration"]=="VERIFIED"


def test_ruleset_bypass_is_rejected():
    r=_rules();r["bypass_actors"]=[{"actor_id":1}]
    assert analyze_rulesets([r],{"release-gate","security"})["configuration"]=="NO-GO"


def test_release_gate_requires_real_governance_verified():
    evidence={"status":"VERIFIED","scope":"GITHUB_OBSERVED_EVIDENCE",
              "repository":fixtures.REPO,"commit_sha":fixtures.COMMIT,"controls":{"unit-tests":{}}}
    governance={"repository":fixtures.REPO,"branch":"main","status":"UNVERIFIABLE"}
    assert evaluate(evidence,governance)["status"]=="NO-GO"
    governance["status"]="VERIFIED"
    out=evaluate(evidence,governance)
    assert out["status"]=="TECHNICAL_PASS" and out["production_go"] is False


def test_redirect_scrubs_token_on_cross_host():
    from urllib.request import Request
    from scripts.evidence_verify import StripCrossHostAuthorization
    request=Request('https://api.github.com/repos/example/repo/actions/artifacts/12/zip',
                    headers={'Authorization':'Bearer example-secret','Accept':'application/octet-stream'})
    redirected=StripCrossHostAuthorization().redirect_request(
        request,None,302,'Found',{},'https://example-artifacts.githubusercontent.com/download/123')
    assert redirected.get_header('Authorization') is None
    assert 'Authorization' not in redirected.headers
    assert redirected.full_url.startswith('https://')
    with pytest.raises(EvidenceUnavailable):
        StripCrossHostAuthorization().redirect_request(request,None,302,'Found',{},'http://insecure.invalid/')


def test_gate_cli_cannot_be_tricked_by_unsigned_json_claim(tmp_path):
    import subprocess, sys
    evidence=tmp_path/'forged.json';governance=tmp_path/'governance.json'
    evidence.write_text(json.dumps({"status":"VERIFIED","scope":"GITHUB_OBSERVED_EVIDENCE",
                                    "repository":fixtures.REPO,"controls":{"unit":{}},"commit_sha":fixtures.COMMIT}))
    governance.write_text(json.dumps({"status":"VERIFIED","repository":fixtures.REPO,"branch":"main"}))
    result=subprocess.run([sys.executable,'-m','scripts.certification_gate',
                           '--manifest',str(evidence),'--trusted-policy',str(governance)],
                          cwd=Path(__file__).resolve().parents[1],text=True,capture_output=True)
    assert result.returncode != 0
    assert 'NO-GO' in result.stdout

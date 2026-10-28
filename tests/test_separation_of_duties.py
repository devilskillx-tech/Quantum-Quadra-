"""Policy-layer test: grants are synthetic, not a real GitHub authorization audit."""
from __future__ import annotations
import copy
import json
import subprocess
import sys
from pathlib import Path
import pytest
from scripts.separation_of_duties import assess, DutyPolicyError, CAPABILITIES, ROLES, EXPECTED
from scripts.certification_gate import evaluate

SHA = 'a' * 40
REPO = 'devilskillx-tech/Quantum-Quadra-'


def snapshot():
    people=[]
    assignments={}
    for idx, (role, grant) in enumerate(EXPECTED.items()):
        ident=f'account:{role}'
        assignments[role]=ident
        people.append({'id':ident, 'human_id':f'person:{idx}',
                       'kind':'human' if role in ('independent_reviewer','deployment_authorizer',
                                                'ruleset_administrator') else 'service',
                       'capabilities':[grant], 'groups':[]})
    return {'schema_version':1, 'repository':REPO, 'commit_sha':SHA,
            'principals':people, 'groups':[], 'assignments':assignments}


def actor(data, role):
    return next(p for p in data['principals'] if p['id'] == data['assignments'][role])


def test_disjoint_permissions_remain_unverified_not_go():
    result=assess(snapshot())
    assert result['status']=='UNVERIFIABLE'
    assert result['modeled_separation']=='PASS_UNATTESTED'
    assert not result['violations']
    assert 'Independent live GitHub effective-permissions audit' in result['requires']


@pytest.mark.parametrize('role,added,expected', [
    ('candidate_author','verifier_write','CROSS_TRUST_CONTROL'),
    ('evidence_producer','policy_write','CROSS_TRUST_CONTROL'),
    ('candidate_author','ruleset_admin','CROSS_TRUST_CONTROL'),
    ('candidate_author','grant_permissions','CROSS_TRUST_CONTROL'),
    ('independent_reviewer','trusted_workflow_write','REVIEWER_TRUST_ADMIN'),
    ('deployment_authorizer','policy_write','DEPLOYER_TRUST_ADMIN'),
    ('ruleset_administrator','ruleset_bypass','BYPASS_CAPABILITY'),
])
def test_shared_effective_privilege_fails(role,added,expected):
    data=snapshot()
    actor(data,role)['capabilities'].append(added)
    report=assess(data)
    assert report['status']=='NO-GO'
    assert expected in {v['code'] for v in report['violations']}


def test_two_accounts_same_human_detected():
    data=snapshot()
    actor(data,'verifier_maintainer')['human_id']=actor(data,'candidate_author')['human_id']
    report=assess(data)
    assert 'CROSS_TRUST_CONTROL' in {v['code'] for v in report['violations']}


def test_inherited_group_permissions_are_effective():
    data=snapshot()
    data['groups']=[{'id':'github-team:admin', 'capabilities':['ruleset_admin']}]
    actor(data,'candidate_author')['groups'].append('github-team:admin')
    assert 'CROSS_TRUST_CONTROL' in {v['code'] for v in assess(data)['violations']}


def test_group_with_both_permissions_is_rejected_even_if_unassigned():
    data=snapshot()
    data['groups']=[{'id':'shared-trust-zone','capabilities':['candidate_write', 'policy_write']}]
    assert 'GROUP_CROSS_TRUST' in {v['code'] for v in assess(data)['violations']}


def test_self_approval_hidden_behind_multiple_accounts_is_rejected():
    data=snapshot()
    actor(data,'independent_reviewer')['human_id']=actor(data,'evidence_producer')['human_id']
    assert 'ROLE_SELF_APPROVAL' in {v['code'] for v in assess(data)['violations']}


@pytest.mark.parametrize('mutation', [
    lambda x: x.update(schema_version=2),
    lambda x: x.update(commit_sha='abc'),
    lambda x: x['assignments'].pop('ruleset_administrator'),
    lambda x: x['principals'][0].update(capabilities=['not_a_permission']),
    lambda x: x['principals'][0].update(groups=['unknown-group']),
    lambda x: x['principals'].append(copy.deepcopy(x['principals'][0])),
    lambda x: x.update(untrusted_extra='PASS'),
    lambda x: x['principals'][0].update(human_id=''),
    lambda x: x['principals'][0].update(capabilities=['candidate_write','candidate_write']),
])
def test_invalid_or_incomplete_claim_rejected(mutation):
    data=snapshot()
    mutation(data)
    with pytest.raises(DutyPolicyError):assess(data)


def test_service_account_must_not_authorize_deployment():
    data=snapshot()
    actor(data,'deployment_authorizer')['kind']='service'
    assert 'HUMAN_ROLE_REQUIRED' in {v['code'] for v in assess(data)['violations']}


def test_missing_capability_for_assigned_role_is_rejected():
    data=snapshot()
    actor(data,'independent_reviewer')['capabilities']=[]
    assert 'MISSING_ROLE_PERMISSION' in {v['code'] for v in assess(data)['violations']}


def test_gateway_rejects_unattested_sod_even_when_other_signals_claim_pass():
    data=snapshot()
    evidence={'status':'VERIFIED','scope':'GITHUB_OBSERVED_EVIDENCE', 'repository':REPO,
              'commit_sha':SHA,'controls':{'one':{'status':'VERIFIED'}}}
    gov={'repository':REPO,'branch':'main','status':'VERIFIED'}
    result=evaluate(evidence,gov,duties=assess(data))
    assert result['status']=='NO-GO' and result['production_go'] is False
    assert any('separation of duties' in s for s in result['reasons'])


def test_gate_rejects_stale_so_d_attestation():
    evidence={'status':'VERIFIED','scope':'GITHUB_OBSERVED_EVIDENCE', 'repository':REPO,
              'commit_sha':SHA,'controls':{'one':{}}}
    gov={'repository':REPO,'branch':'main','status':'VERIFIED'}
    duties={'status':'VERIFIED','effective_permissions':'INDEPENDENTLY_ATTESTED',
            'repository':REPO,'commit_sha':'b'*40}
    assert evaluate(evidence,gov,duties=duties)['status']=='NO-GO'


def test_offline_cli_can_never_output_verified(tmp_path):
    path=tmp_path/'untrusted.json'
    path.write_text(json.dumps(snapshot()))
    r=subprocess.run([sys.executable,'-m','scripts.separation_of_duties','--snapshot',str(path)],
                     cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True)
    assert r.returncode!=0
    assert json.loads(r.stdout)['status']=='UNVERIFIABLE'
    path.write_text('{}')
    r=subprocess.run([sys.executable,'-m','scripts.separation_of_duties','--snapshot',str(path)],
                     cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True)
    assert r.returncode!=0
    assert json.loads(r.stdout)['status']=='NO-GO'

"""Synthetic VRC fixtures; no live GitHub permissions or approvals asserted."""
import copy
import pytest
from scripts.minimum_privilege_cut import solve
from scripts.authority_what_if import assess, applied, AuthorityModelError
from scripts.remediation_certificate_build import build, digest
from scripts.remediation_certificate_verify import verify
from scripts.remediation_effective_state_verify import verify_observed

SHA='b'*40


def fixture():
    graph={
        'schema_version':1,'repository':'devilskillx-tech/Quantum-Quadra-',
        'principals':[{'id':v,'human_id':h} for v,h in
                      [('author','h-author'),('verifier','h-verifier'),('reviewer1','h-reviewer1'),
                       ('reviewer2','h-reviewer2'),('recovery','h-recovery')]],
        'groups':[{'id':'author-team','members':['author']}],
        'grants':[
            {'id':name,'subject':subject,'capability':cap,'removable':modifiable,'cost':cost}
            for name,subject,cap,modifiable,cost in [
                ('g_author','author','candidate_write',False,3),
                ('g_trust_excess','author-team','verifier_write',True,2),
                ('g_verifier','verifier','verifier_write',False,3),
                ('g_postgres','recovery','restore_postgres',False,5),
                ('g_sqlite','recovery','restore_sqlite',False,5),
                ('g_ci','recovery','release_gate',False,5),
                ('g_evidence','verifier','evidence_verify',False,5),
                ('g_review1','reviewer1','review_approve',False,5),
                ('g_review2','reviewer2','review_approve',False,5),
                ('g_ineffective','recovery','read_history',True,1),
            ]],
    }
    policy={
        'schema_version':1,
        'forbidden_pairs':[['candidate_write','verifier_write'],['candidate_write','review_approve']],
        'required':[
            {'id':'disaster_recovery','all_of':['restore_postgres','restore_sqlite']},
            {'id':'trusted_ci','all_of':['release_gate','evidence_verify']},
            {'id':'independent_review','quorum':{'capability':'review_approve','min_distinct_humans':2}},
        ],
        'protected_grants':['g_postgres','g_sqlite','g_ci','g_evidence','g_review1','g_review2'],
        'max_revoke':2,
    }
    return graph,policy


def certified():
    graph,policy=fixture()
    plan=solve(graph,policy)
    cert=build(graph,policy,plan,SHA,'approved-test-source')
    return graph,policy,plan,cert


def reseal(cert):
    cert['certificate_sha256']=digest({k:v for k,v in cert.items() if k!='certificate_sha256'})
    return cert


def accept(cert, graph=None, policy=None, sha=SHA, source='approved-test-source'):
    graph0,policy0=fixture()
    return verify(cert,graph if graph is not None else graph0,
                  policy if policy is not None else policy0,sha,source)


def test_vrc01_positive_minimum_and_model_verified():
    graph,policy,plan,cert=certified()
    assert plan['status']=='OPTIMAL' and plan['plan']=={'revoke':['g_trust_excess']} and plan['cost']==2
    result=accept(cert)
    assert result['status']=='MODEL_VERIFIED'
    assert result['production_go'] is False and result['scope']=='SYNTHETIC_MODEL_ONLY'


def test_vrc02_wrong_graph_digest():
    graph,policy,plan,cert=certified()
    cert['graph_sha256']='0'*64
    assert accept(reseal(cert))['status']=='REJECTED'


def test_vrc03_policy_replacement():
    graph,policy,plan,cert=certified()
    policy['forbidden_pairs'].append(['restore_postgres','candidate_write'])
    assert accept(cert,graph,policy)['status']=='REJECTED'


def test_vrc04_plan_substitution():
    graph,policy,plan,cert=certified()
    cert['plan']={'revoke':['g_ineffective']}
    cert['plan_sha256']=digest(cert['plan'])
    cert['solver_cost']=1
    assert 'INVARIANT_FAILED' in accept(reseal(cert))['reason']


def test_vrc05_risk_residual():
    graph,policy=fixture()
    assert assess(graph,policy,[])['status']=='FAIL'


def test_vrc06_indirect_identity_conflict_survives():
    graph,policy=fixture()
    graph['principals'][1]['human_id']='h-author'
    assert solve(graph,policy)['status']=='UNSAT'


def test_vrc07_recovery_must_survive():
    graph,policy=fixture()
    graph['grants'][3]['removable']=True
    policy['protected_grants'].remove('g_postgres')
    with pytest.raises(AuthorityModelError):
        applied(graph,policy,['g_postgres','g_trust_excess','g_ineffective'])
    assert assess(graph,policy,['g_postgres','g_trust_excess'])['status']=='FAIL'


def test_vrc08_false_producer_identity_claim():
    graph,policy,plan,cert=certified()
    cert['source_id']='candidate-controlled'
    assert accept(reseal(cert))['status']=='REJECTED'


def test_vrc09_old_commit_replay():
    graph,policy,plan,cert=certified()
    assert accept(cert,sha='c'*40)['status']=='REJECTED'


def test_vrc10_claimed_pass_without_real_remediation():
    graph,policy,plan,cert=certified()
    cert['solver_claim']='OPTIMAL'
    cert['plan']={'revoke':[]}
    cert['plan_sha256']=digest(cert['plan'])
    cert['solver_cost']=0
    assert 'INVARIANT_FAILED' in accept(reseal(cert))['reason']


def test_vrc11_missing_external_inputs():
    *_,cert=certified()
    assert verify(cert,None,None,SHA,None)['status']=='UNVERIFIABLE'


def test_vrc12_fake_optimality():
    graph,policy,plan,cert=certified()
    cert['plan']={'revoke':['g_ineffective','g_trust_excess']}
    cert['plan_sha256']=digest(cert['plan'])
    cert['solver_cost']=3
    assert 'OPTIMALITY_CLAIM_FALSE' in accept(reseal(cert))['reason']


def test_vrc13_observed_changed_after_plan_is_no_go():
    graph,policy,plan,cert=certified()
    post=applied(graph,policy,plan['plan']['revoke'])
    post['grants'].append({'id':'backdoor','subject':'author','capability':'verifier_write','removable':True,'cost':1})
    obs={'source_id':'fake-test','application_id':'test-change','commit_sha':SHA,'graph':post}
    result=verify_observed(cert,accept(cert),graph,policy,obs,
                           independently_authenticated=True,independently_approved=True)
    assert result['status']=='NO-GO'


def test_vrc14_unattested_observed_state_stays_unverifiable():
    graph,policy,plan,cert=certified()
    post=applied(graph,policy,plan['plan']['revoke'])
    obs={'source_id':'fixture','application_id':'test-change','commit_sha':SHA,'graph':post}
    assert verify_observed(cert,accept(cert),graph,policy,obs)['status']=='UNVERIFIABLE'


def test_vrc15_synthetic_observed_consistency_never_production_verified():
    graph,policy,plan,cert=certified()
    post=applied(graph,policy,plan['plan']['revoke'])
    obs={'source_id':'fixture','application_id':'test-change','commit_sha':SHA,'graph':post}
    status=verify_observed(cert,accept(cert),graph,policy,obs,
                           independently_authenticated=True,independently_approved=True)
    assert status['status']=='OBSERVED_MODEL_CONSISTENT'
    assert status['production_go'] is False


def test_unknown_field_in_graph_rejected():
    graph,policy=fixture()
    graph['hidden_admin']='yes'
    with pytest.raises(AuthorityModelError):
        solve(graph,policy)


def test_group_nested_inheritance_and_cycle():
    graph,policy=fixture()
    graph['groups']=[{'id':'a','members':['b']},{'id':'b','members':['author']}]
    graph['grants'][1]['subject']='a'
    assert solve(graph,policy)['plan']['revoke']==['g_trust_excess']
    graph['groups'][1]['members'].append('a')
    assert solve(graph,policy)['plan']['revoke']==['g_trust_excess']


def test_quorum_rejection_for_only_one_reviewer():
    graph,policy=fixture()
    graph['principals'][3]['human_id']='h-reviewer1'
    assert solve(graph,policy)['status']=='UNSAT'


def test_no_revocation_safe_graph():
    graph,policy=fixture()
    graph['grants']=[g for g in graph['grants'] if g['id']!='g_trust_excess']
    assert solve(graph,policy)['plan']=={'revoke':[]}


def test_tampered_certificate_without_reseal_rejected():
    *_,cert=certified()
    cert['solver_cost']=200
    assert accept(cert)['reason']=='CERTIFICATE_TAMPERED'


def test_protected_grant_cannot_be_removed():
    graph,policy=fixture()
    with pytest.raises(AuthorityModelError):
        applied(graph,policy,['g_postgres'])


def test_unsupported_solver_claim_rejected():
    *_,cert=certified()
    cert['solver_claim']='SUPER_OPTIMAL'
    assert accept(reseal(cert))['reason']=='UNSUPPORTED_SOLVER_CLAIM'


def test_no_external_observation_cannot_approve():
    graph,policy,plan,cert=certified()
    assert verify_observed(cert,accept(cert),graph,policy,None)['status']=='UNVERIFIABLE'


def test_plan_cannot_reassign_rights():
    graph,policy=fixture()
    with pytest.raises(AuthorityModelError):
        applied(graph,policy,{'transfer_to':'another_actor'})


def test_bounds_refuse_unsupported_exact_optimum():
    graph,policy=fixture()
    for i in range(17):
        graph['grants'].append({'id':f'z{i}','subject':'recovery','capability':'read_history','removable':True,'cost':1})
    assert solve(graph,policy)['status']=='UNVERIFIABLE'


def test_stage_two_rejects_wrong_commit_even_with_claimed_authentication():
    graph,policy,plan,cert=certified()
    obs={'source_id':'test','application_id':'test-change','commit_sha':'a'*40,
         'graph':applied(graph,policy,plan['plan']['revoke'])}
    assert verify_observed(cert,accept(cert),graph,policy,obs,
                           independently_authenticated=True,independently_approved=True)['status']=='NO-GO'


def test_stage_two_rejects_unrelated_reassignment_even_if_safe():
    graph,policy,plan,cert=certified()
    observed=applied(graph,policy,plan['plan']['revoke'])
    observed['grants'][2]['subject']='reviewer2'
    obs={'source_id':'test','application_id':'test-change','commit_sha':SHA,'graph':observed}
    assert verify_observed(cert,accept(cert),graph,policy,obs,
                           independently_authenticated=True,independently_approved=True)['status']=='NO-GO'


def test_cli_offline_certificate_roundtrip(tmp_path):
    import json,sys,subprocess
    graph,policy=fixture()
    p1,p2,p3=[tmp_path/n for n in ('graph.json','policy.json','cert.json')]
    p1.write_text(json.dumps(graph));p2.write_text(json.dumps(policy))
    cwd=str(__import__('pathlib').Path(__file__).resolve().parents[1])
    common=['--graph',str(p1),'--policy',str(p2),'--sha',SHA,'--source-id','approved-test-source']
    build_cmd=[sys.executable,'-m','scripts.remediation_cli','build',*common,'--output',str(p3)]
    b=subprocess.run(build_cmd,cwd=cwd,capture_output=True,text=True)
    assert b.returncode==0,b.stderr
    v=subprocess.run([sys.executable,'-m','scripts.remediation_cli','verify',*common,
                      '--certificate',str(p3)],cwd=cwd,capture_output=True,text=True)
    assert v.returncode==0,v.stderr
    assert json.loads(v.stdout)['status']=='MODEL_VERIFIED'
    assert json.loads(v.stdout)['production_go'] is False

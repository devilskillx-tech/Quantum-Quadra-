from scripts.formal_mutation_runner import MUTATIONS,evaluate,explore
from scripts.state_bound_certification import evaluate as verify_dual


def test_baseline_bounded():
    r=explore(max_depth=12)
    assert r['status']=='BOUNDED_PASS'
    assert r['states']>=9


def test_mutation_suite():
    r=evaluate()
    assert r['status']=='PASS',r['errors']
    assert len(r['mutants'])==8


def test_each_mutant_targeted_property():
    for name,property_name in MUTATIONS.items():
        r=explore(name)
        assert r['status']=='COUNTEREXAMPLE'
        assert r['property']==property_name
        assert r['trace']


def test_untrusted_cert_e_cannot_grant_go():
    model={'candidate_commit_sha':'a'*40,'policy_sha256':'b'*64,'certificate_sha256':'c'*64}
    stage_one={'status':'MODEL_VERIFIED','certificate_sha256':'c'*64,'scope':'SYNTHETIC_MODEL_ONLY'}
    stage_two={'status':'OBSERVED_MODEL_CONSISTENT'}
    result=verify_dual(model,stage_one,stage_two,expected_commit='a'*40,
              expected_policy='b'*64,operator_approved=True,governance_verified=True,source_trust_attested=True)
    assert result['status']=='NO-GO' and result['production_go'] is False
    assert 'PROTECTED_INDEPENDENT_CERT_E_AUTHORITY_NOT_DEPLOYED' in result['reasons']


def test_bad_sha_or_policy_refused():
    r=verify_dual({}, {}, {}, expected_commit='a'*40,expected_policy='b'*64)
    assert 'CANDIDATE_MISMATCH' in r['reasons']
    assert 'POLICY_MISMATCH' in r['reasons']

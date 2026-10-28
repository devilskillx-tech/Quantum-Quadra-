"""Stage-two verifier: a dry-run contract, NOT a live GitHub permissions attestor.

An authenticated, independently operated source adapter is REQUIRED before real
observed-state compliance can be established. No such adapter ships here.
"""
from __future__ import annotations
from scripts.authority_what_if import assess, applied, validate, AuthorityModelError
from scripts.remediation_certificate_build import digest


def verify_observed(certificate: dict, model_result: dict, approved_graph: dict,
                    approved_policy: dict, observation: dict | None,
                    *, independently_authenticated: bool = False,
                    independently_approved: bool = False) -> dict:
    """Validate claimed after-state; never assert real-world VERIFIED from a JSON blob.

    Both flags are *caller claims* and are not independently provable here;
    production callers must use external authenticators rather than setting
    them based on certificate content. The resulting status is always modeled.
    """
    def result(status, reason):
        return {'status':status,'production_go':False,'reason':reason}
    if model_result.get('status')!='MODEL_VERIFIED':
        return result('NO-GO','STAGE_ONE_NOT_MODEL_VERIFIED')
    if observation is None or not independently_authenticated or not independently_approved:
        return result('UNVERIFIABLE','LIVE_SOURCE_AND_INDEPENDENT_APPROVAL_NOT_ESTABLISHED')
    try:
        if not isinstance(observation,dict) or set(observation)!={'source_id','commit_sha','graph','application_id'}:
            return result('NO-GO','INVALID_OBSERVATION')
        if observation['commit_sha']!=certificate['candidate_commit_sha']:
            return result('NO-GO','STALE_CANDIDATE')
        # Strict match of the entire post-change graph, including identities,
        # group memberships and grants, rather than only confirming some paths.
        expected=applied(approved_graph,approved_policy,certificate['plan']['revoke'])
        actual=observation['graph']
        validate(actual,approved_policy)
        if digest(actual)!=digest(expected):
            return result('NO-GO','OBSERVED_STATE_DIFFERS_FROM_APPROVED_PLAN')
        sim=assess(actual,approved_policy,[])
        if sim['status']!='PASS':
            return result('NO-GO','POST_APPLICATION_POLICY_VIOLATION')
        # This is a consistency check, not proof the source adapter is trusted.
        return {'status':'OBSERVED_MODEL_CONSISTENT','production_go':False,
                'reason':'INDEPENDENT_LIVE_AUTHENTICATION_REQUIRED_FOR_REAL_CERTIFICATION',
                'source_id':observation['source_id'],'post_graph_sha256':digest(actual),
                'application_id':observation['application_id']}
    except (AuthorityModelError,ValueError,TypeError,KeyError) as exc:
        return result('NO-GO','INVALID_OBSERVED_STATE:'+type(exc).__name__)

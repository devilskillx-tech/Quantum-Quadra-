"""Model-certificate verifier, intentionally separate from the MPC optimizer.

A verified model certificate is NEVER evidence of real GitHub permissions and
must never be used as production approval. Trusted graph/policy must originate
outside the candidate's control for the verification to have any meaning.
"""
from __future__ import annotations
from itertools import combinations
from math import comb
from scripts.authority_what_if import validate, assess, AuthorityModelError
from scripts.remediation_certificate_build import digest

MAX_VERIFY_VARIABLES = 16
MAX_VERIFY_SUBSETS = 20000


def verify(certificate: dict, trusted_graph: dict | None, trusted_policy: dict | None,
           expected_sha: str, expected_source_id: str | None = None) -> dict:
    def fail(status: str, why: str) -> dict:
        return {'status':status, 'production_go':False,'reason':why}
    if trusted_graph is None or trusted_policy is None or expected_source_id is None:
        return fail('UNVERIFIABLE','MISSING_INDEPENDENT_TRUSTED_INPUT')
    try:
        validate(trusted_graph,trusted_policy)
        fields={'schema_version','repository','candidate_commit_sha','source_id','source_kind',
                'graph_sha256','policy_sha256','plan','plan_sha256',
                'solver_claim','solver_cost','certificate_sha256'}
        if not isinstance(certificate,dict) or set(certificate)!=fields or certificate['schema_version']!=1:
            return fail('REJECTED','INVALID_CERTIFICATE_SCHEMA')
        if certificate['repository']!=trusted_graph['repository'] or certificate['candidate_commit_sha']!=expected_sha:
            return fail('REJECTED','WRONG_REPOSITORY_OR_CANDIDATE')
        if certificate['source_id']!=expected_source_id or certificate['source_kind']!='SYNTHETIC_MODEL':
            return fail('REJECTED','WRONG_SOURCE_BINDING')
        if certificate['graph_sha256']!=digest(trusted_graph) or certificate['policy_sha256']!=digest(trusted_policy):
            return fail('REJECTED','GRAPH_OR_POLICY_DIGEST_MISMATCH')
        if certificate['certificate_sha256']!=digest({k:v for k,v in certificate.items() if k!='certificate_sha256'}):
            return fail('REJECTED','CERTIFICATE_TAMPERED')
        plan=certificate['plan']
        if not isinstance(plan,dict) or set(plan)!={'revoke'} or not isinstance(plan['revoke'],list) or plan['revoke']!=sorted(set(plan['revoke'])):
            return fail('REJECTED','INVALID_PLAN')
        if certificate['plan_sha256']!=digest(plan):
            return fail('REJECTED','PLAN_DIGEST_MISMATCH')
        if certificate['solver_claim']!='OPTIMAL' or type(certificate['solver_cost']) is not int:
            return fail('REJECTED','UNSUPPORTED_SOLVER_CLAIM')
        # Recompute all operational and separation invariants from trusted
        # inputs; never accept solver/What-If PASS claims.
        result=assess(trusted_graph,trusted_policy,plan['revoke'])
        if result['status']!='PASS':
            return fail('REJECTED','SECURITY_OR_CONTINUITY_INVARIANT_FAILED:'+'|'.join(result['failures']))
        costs={g['id']:g['cost'] for g in trusted_graph['grants']}
        actual_cost=sum(costs[gid] for gid in plan['revoke'])
        if certificate['solver_cost']!=actual_cost:
            return fail('REJECTED','COST_MISMATCH')
        candidates=sorted(g['id'] for g in trusted_graph['grants'] if g['removable'] and g['id'] not in trusted_policy['protected_grants'])
        if len(candidates)>MAX_VERIFY_VARIABLES or sum(comb(len(candidates),n) for n in range(min(trusted_policy['max_revoke'],len(candidates))+1))>MAX_VERIFY_SUBSETS:
            return fail('UNVERIFIABLE','INDEPENDENT_EXHAUSTIVE_VERIFICATION_LIMIT')
        expected_score=(actual_cost,len(plan['revoke']),tuple(plan['revoke']))
        # Independent exhaustive minimization; includes empty plan.
        for n in range(min(trusted_policy['max_revoke'],len(candidates))+1):
            for subset in combinations(candidates,n):
                score=(sum(costs[x] for x in subset),len(subset),subset)
                if score<expected_score and assess(trusted_graph,trusted_policy,list(subset))['status']=='PASS':
                    return fail('REJECTED','OPTIMALITY_CLAIM_FALSE')
        return {'status':'MODEL_VERIFIED','production_go':False,
                'scope':'SYNTHETIC_MODEL_ONLY','certificate_sha256':certificate['certificate_sha256'],
                'graph_sha256':certificate['graph_sha256'],'policy_sha256':certificate['policy_sha256'],
                'candidate_commit_sha':expected_sha,'plan':plan,'cost':actual_cost}
    except (AuthorityModelError,KeyError,TypeError,ValueError) as exc:
        return fail('REJECTED','INVALID_CERTIFICATE_OR_MODEL:'+type(exc).__name__)

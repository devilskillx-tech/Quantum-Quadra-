"""Read-only binding of simulated model and observed-state certificates.

Never decides production GO. Source auth cannot be inferred from JSON claims.
"""
from __future__ import annotations
from scripts.remediation_certificate_build import digest


def evaluate(model_cert: dict, model_result: dict, effective_result: dict,
             *, expected_commit: str, expected_policy: str,
             operator_approved: bool=False, governance_verified: bool=False,
             source_trust_attested: bool=False) -> dict:
    reasons=[]
    if not isinstance(model_result,dict) or model_result.get('status')!='MODEL_VERIFIED':
        reasons.append('MODEL_NOT_VERIFIED')
    if not isinstance(model_cert,dict) or model_cert.get('candidate_commit_sha')!=expected_commit:
        reasons.append('CANDIDATE_MISMATCH')
    if model_cert.get('policy_sha256') != expected_policy:
        reasons.append('POLICY_MISMATCH')
    if model_cert.get('certificate_sha256') != model_result.get('certificate_sha256'):
        reasons.append('MODEL_CERTIFICATE_BINDING_MISMATCH')
    # This bundle has no authorized GitHub observer. A locally supplied result
    # can validate model consistency ONLY and can NEVER issue CERT-E.
    if not isinstance(effective_result,dict) or effective_result.get('status')!='OBSERVED_MODEL_CONSISTENT':
        reasons.append('OBSERVED_MODEL_INCONSISTENT')
    if not source_trust_attested:
        reasons.append('LIVE_SOURCE_AUTHENTICATION_MISSING')
    # Even caller-provided booleans cannot prove independence of cert authority:
    reasons.append('PROTECTED_INDEPENDENT_CERT_E_AUTHORITY_NOT_DEPLOYED')
    if not governance_verified:
        reasons.append('GITHUB_GOVERNANCE_NOT_VERIFIED')
    if not operator_approved:
        reasons.append('HUMAN_APPROVAL_MISSING')
    return {'status':'NO-GO','production_go':False,'reasons':reasons,
            'model_scope':model_result.get('scope') if isinstance(model_result,dict) else None,
            'candidate_commit_sha':expected_commit}

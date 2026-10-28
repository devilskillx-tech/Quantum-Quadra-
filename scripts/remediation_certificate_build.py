"""Untrusted certificate builder. Its claims grant no privileges or GO."""
from __future__ import annotations
import hashlib
import json
from scripts.authority_what_if import validate, identifier


def canonical(data: object) -> bytes:
    return json.dumps(data,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')


def digest(data: object) -> str:
    return hashlib.sha256(canonical(data)).hexdigest()


def build(graph: dict, policy: dict, solver: dict, commit_sha: str, source_id: str) -> dict:
    validate(graph,policy)
    identifier(source_id,'source id')
    if not isinstance(commit_sha,str) or len(commit_sha)!=40 or any(c not in '0123456789abcdef' for c in commit_sha):
        raise ValueError('invalid candidate sha')
    if solver.get('status') != 'OPTIMAL' or not isinstance(solver.get('plan'),dict):
        raise ValueError('only plans with exact search result can be packaged')
    revoke=solver['plan'].get('revoke')
    if not isinstance(revoke,list) or revoke!=sorted(set(revoke)):
        raise ValueError('invalid proposed revocation set')
    core={'schema_version':1,'repository':graph['repository'],'candidate_commit_sha':commit_sha,
          'source_id':source_id,'source_kind':'SYNTHETIC_MODEL',
          'graph_sha256':digest(graph),'policy_sha256':digest(policy),
          'plan':{'revoke':revoke},'plan_sha256':digest({'revoke':revoke}),
          'solver_claim':'OPTIMAL','solver_cost':solver['cost']}
    return {**core,'certificate_sha256':digest(core)}

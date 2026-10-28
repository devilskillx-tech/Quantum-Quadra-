"""Bounded exact MPC for *synthetic* authority graphs; read-only and no GO."""
from __future__ import annotations

from itertools import combinations
from math import comb
from scripts.authority_what_if import validate, AuthorityModelError

MAX_EXACT_VARIABLES = 16
MAX_SUBSETS = 20000


def solve(graph: dict, policy: dict) -> dict:
    validate(graph,policy)
    # Optimization evaluates feasibility using an internal independent routine;
    # the VRC checker uses authority_what_if instead of trusting this result.
    from scripts.authority_what_if import assess
    candidates=sorted(g['id'] for g in graph['grants'] if g['removable'] and g['id'] not in policy['protected_grants'])
    if len(candidates)>MAX_EXACT_VARIABLES or sum(comb(len(candidates), n) for n in range(min(policy['max_revoke'], len(candidates))+1))>MAX_SUBSETS:
        return {'status':'UNVERIFIABLE','plan':None,'reason':'EXACT_SEARCH_LIMIT'}
    weights={g['id']:g['cost'] for g in graph['grants']}
    best=None
    # Explicitly verify every subset permitted by max_revoke, including empty.
    for size in range(min(policy['max_revoke'],len(candidates))+1):
        for subset in combinations(candidates,size):
            score=(sum(weights[x] for x in subset),len(subset),subset)
            if best and score>=best[0]:
                continue
            if assess(graph,policy,list(subset))['status']=='PASS':
                best=(score,list(subset))
    if best is None:
        return {'status':'UNSAT','plan':None,'reason':'NO_FEASIBLE_REVOKE_ONLY_PLAN'}
    return {'status':'OPTIMAL','plan':{'revoke':best[1]},'cost':best[0][0],
            'reason':'EXHAUSTIVE_SYNTHETIC_SEARCH','evaluated_grant_count':len(candidates)}

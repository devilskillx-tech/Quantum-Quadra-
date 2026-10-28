"""Independent, bounded model evaluator for authority-remediation plans.

This evaluator proves only synthetic-model properties. It has no GitHub write
permissions, does not establish source provenance, and cannot grant deployment GO.
"""
from __future__ import annotations

from collections import defaultdict
import re
from typing import Any

ID_RE = re.compile(r'^[A-Za-z0-9_./:@-]{1,120}$')
MAX_GRANTS = 48
MAX_ACTORS = 100


class AuthorityModelError(ValueError):
    pass


def identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise AuthorityModelError(f'invalid {label}')
    return value


def _unique(seq: list[str], label: str) -> None:
    if len(set(seq)) != len(seq):
        raise AuthorityModelError(f'duplicate {label}')


def validate(graph: dict, policy: dict) -> None:
    """Reject unknown fields and incomplete/ambiguous synthetic inventories."""
    if not isinstance(graph, dict) or set(graph) != {'schema_version','repository','principals','groups','grants'}:
        raise AuthorityModelError('invalid graph fields')
    if graph['schema_version'] != 1 or type(graph['schema_version']) is not int:
        raise AuthorityModelError('invalid graph version')
    repo = identifier(graph['repository'], 'repository')
    if repo.count('/') != 1:
        raise AuthorityModelError('invalid repository')
    people = graph['principals']
    if not isinstance(people, list) or not people or len(people) > MAX_ACTORS:
        raise AuthorityModelError('invalid principal inventory')
    identities = {}
    for p in people:
        if not isinstance(p, dict) or set(p) != {'id','human_id'}:
            raise AuthorityModelError('invalid principal')
        pid = identifier(p['id'], 'principal id')
        if pid in identities:
            raise AuthorityModelError('duplicate principal')
        identities[pid] = identifier(p['human_id'], 'human identity')
    groups = graph['groups']
    if not isinstance(groups, list) or len(groups) > MAX_ACTORS:
        raise AuthorityModelError('invalid groups')
    group_ids = set()
    for g in groups:
        if not isinstance(g, dict) or set(g) != {'id','members'}:
            raise AuthorityModelError('invalid group')
        gid = identifier(g['id'], 'group id')
        if gid in group_ids or gid in identities:
            raise AuthorityModelError('duplicate group id')
        group_ids.add(gid)
    for g in groups:
        if not isinstance(g['members'], list) or any(not isinstance(v,str) or v not in identities | dict.fromkeys(group_ids) for v in g['members']):
            raise AuthorityModelError('unknown group member')
        _unique(g['members'], 'group member')
    grants = graph['grants']
    if not isinstance(grants, list) or len(grants) > MAX_GRANTS:
        raise AuthorityModelError('invalid grant inventory')
    ids = set()
    for x in grants:
        if not isinstance(x, dict) or set(x) != {'id','subject','capability','removable','cost'}:
            raise AuthorityModelError('invalid grant')
        gid = identifier(x['id'], 'grant id')
        if gid in ids:
            raise AuthorityModelError('duplicate grant')
        ids.add(gid)
        subject = identifier(x['subject'], 'grant subject')
        if subject not in identities and subject not in group_ids:
            raise AuthorityModelError('unknown grant subject')
        identifier(x['capability'], 'capability')
        if type(x['removable']) is not bool or type(x['cost']) is not int or not (1 <= x['cost'] <= 10000):
            raise AuthorityModelError('invalid grant cost or removability')
    if not isinstance(policy,dict) or set(policy) != {'schema_version','forbidden_pairs','required','protected_grants','max_revoke'}:
        raise AuthorityModelError('invalid policy fields')
    if policy['schema_version'] != 1 or type(policy['schema_version']) is not int:
        raise AuthorityModelError('invalid policy version')
    pairs = policy['forbidden_pairs']
    if not isinstance(pairs,list) or not pairs or len(pairs)>32:
        raise AuthorityModelError('invalid forbidden pairs')
    for pair in pairs:
        if not isinstance(pair,list) or len(pair)!=2 or pair[0]==pair[1]:
            raise AuthorityModelError('invalid forbidden pair')
        for item in pair:
            identifier(item, 'forbidden capability')
    req = policy['required']
    if not isinstance(req,list) or not req or len(req)>32:
        raise AuthorityModelError('invalid required workflows')
    requirement_ids=[]
    for r in req:
        if not isinstance(r,dict) or 'id' not in r:
            raise AuthorityModelError('invalid requirement')
        requirement_ids.append(identifier(r['id'], 'requirement id'))
        if set(r)=={'id','all_of'}:
            if not isinstance(r['all_of'],list) or not r['all_of']:
                raise AuthorityModelError('empty all_of')
            for cap in r['all_of']:
                identifier(cap,'required capability')
        elif set(r)=={'id','quorum'}:
            q=r['quorum']
            if not isinstance(q,dict) or set(q)!={'capability','min_distinct_humans'}:
                raise AuthorityModelError('invalid quorum')
            identifier(q['capability'],'quorum capability')
            if type(q['min_distinct_humans']) is not int or not (2<=q['min_distinct_humans']<=MAX_ACTORS):
                raise AuthorityModelError('invalid quorum size')
        else:
            raise AuthorityModelError('unsupported requirement')
    _unique(requirement_ids, 'requirement id')
    protected=policy['protected_grants']
    if not isinstance(protected,list) or any(v not in ids for v in protected):
        raise AuthorityModelError('unknown protected grant')
    _unique(protected,'protected grants')
    if type(policy['max_revoke']) is not int or not (0<=policy['max_revoke']<=MAX_GRANTS):
        raise AuthorityModelError('invalid max_revoke')


def applied(graph: dict, policy: dict, revoke: list[str]) -> dict:
    validate(graph,policy)
    if not isinstance(revoke,list) or any(not isinstance(x,str) for x in revoke):
        raise AuthorityModelError('invalid revoke plan')
    _unique(revoke,'revoke id')
    if len(revoke)>policy['max_revoke']:
        raise AuthorityModelError('maximum revocations exceeded')
    grants={g['id']:g for g in graph['grants']}
    for gid in revoke:
        if gid not in grants or not grants[gid]['removable'] or gid in policy['protected_grants']:
            raise AuthorityModelError('unknown/non-removable/protected grant')
    return {**graph,'grants':[dict(g) for g in graph['grants'] if g['id'] not in set(revoke)]}


def assess(graph: dict, policy: dict, revoke: list[str]) -> dict:
    """Independently recompute effective rights and all security invariants."""
    after=applied(graph,policy,revoke)
    member_of=defaultdict(set)
    for group in after['groups']:
        for member in group['members']:
            member_of[member].add(group['id'])
    people={p['id']:p['human_id'] for p in after['principals']}
    human_rights=defaultdict(set)
    for pid,human in people.items():
        subjects={pid}
        frontier=[pid]
        while frontier:
            current=frontier.pop()
            for gid in member_of.get(current, ()):
                if gid not in subjects:
                    subjects.add(gid)
                    frontier.append(gid)
        for grant in after['grants']:
            if grant['subject'] in subjects:
                human_rights[human].add(grant['capability'])
    failures=[]
    risk_paths=[]
    for pair in policy['forbidden_pairs']:
        for human, caps in sorted(human_rights.items()):
            if set(pair).issubset(caps):
                risk_paths.append({'human_id':human,'capabilities':pair})
                failures.append('FORBIDDEN_CO_CONTROL:'+human+':'+','.join(pair))
    for req in policy['required']:
        if 'all_of' in req:
            union=set().union(*human_rights.values()) if human_rights else set()
            missing=set(req['all_of'])-union
            if missing:
                failures.append('MISSING_CRITICAL_WORKFLOW:'+req['id']+':'+','.join(sorted(missing)))
        else:
            q=req['quorum']
            holders={h for h,c in human_rights.items() if q['capability'] in c}
            if len(holders)<q['min_distinct_humans']:
                failures.append('INSUFFICIENT_INDEPENDENT_QUORUM:'+req['id'])
    return {'status':'PASS' if not failures else 'FAIL','failures':sorted(failures),
            'risk_paths':risk_paths,'removed_grants':sorted(revoke),
            'remaining_grant_ids':sorted(g['id'] for g in after['grants'])}

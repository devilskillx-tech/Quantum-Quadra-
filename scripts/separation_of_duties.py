"""Fail-closed separation-of-duties *model* audit for QUANTUM QUADRA.

IMPORTANT: A user/candidate-supplied snapshot cannot certify actual GitHub
permissions. This evaluator finds modeled overlaps; even a clean model remains
UNVERIFIABLE until an independent administrator confirms effective grants,
organizational identity linking, branch enforcement and a blocked-merge probe.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from scripts.evidence_verify import json_strict

VERSION = 1
CAPABILITIES = frozenset({
    'candidate_write', 'evidence_publish', 'verifier_write', 'policy_write',
    'trusted_workflow_write', 'ruleset_admin', 'ruleset_bypass',
    'review_approve', 'deploy_authorize', 'grant_permissions',
})
ROLES = (
    'candidate_author', 'evidence_producer', 'verifier_maintainer',
    'policy_maintainer', 'trusted_workflow_maintainer',
    'independent_reviewer', 'deployment_authorizer', 'ruleset_administrator',
)
EXPECTED = {
    'candidate_author': 'candidate_write',
    'evidence_producer': 'evidence_publish',
    'verifier_maintainer': 'verifier_write',
    'policy_maintainer': 'policy_write',
    'trusted_workflow_maintainer': 'trusted_workflow_write',
    'independent_reviewer': 'review_approve',
    'deployment_authorizer': 'deploy_authorize',
    'ruleset_administrator': 'ruleset_admin',
}
UNTRUSTED = frozenset({'candidate_write', 'evidence_publish'})
TRUSTED = frozenset({'verifier_write', 'policy_write', 'trusted_workflow_write',
                     'ruleset_admin', 'ruleset_bypass', 'review_approve',
                     'deploy_authorize', 'grant_permissions'})
PROTECTED = frozenset({'verifier_write', 'policy_write', 'trusted_workflow_write',
                        'ruleset_admin', 'ruleset_bypass', 'grant_permissions'})


class DutyPolicyError(ValueError):
    pass


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 200 or value.strip() != value:
        raise DutyPolicyError(f'{field} must be a nonempty identifier')
    return value


def _caps(value: Any, field: str) -> set[str]:
    if not isinstance(value, list) or any(not isinstance(c, str) or c not in CAPABILITIES for c in value):
        raise DutyPolicyError(f'{field} contains unknown or invalid capability')
    if len(value) != len(set(value)):
        raise DutyPolicyError(f'{field} contains duplicate capability')
    return set(value)


def assess(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Report modeled violations; NEVER assert real-world independent VERIFICATION.

    All principals and grants must be fully enumerated by an independently
    obtained snapshot before anyone may use this analysis for an actual GO.
    This function does not authenticate the source or the human/alias mapping.
    """
    if not isinstance(snapshot, dict) or set(snapshot) != {'schema_version', 'repository', 'commit_sha', 'principals', 'groups', 'assignments'}:
        raise DutyPolicyError('Unexpected or missing top-level fields')
    if type(snapshot['schema_version']) is not int or snapshot['schema_version'] != VERSION:
        raise DutyPolicyError('Unsupported schema version')
    repo = _string(snapshot['repository'], 'repository')
    if '/' not in repo or len(repo.split('/')) != 2:
        raise DutyPolicyError('Invalid repository')
    sha = _string(snapshot['commit_sha'], 'commit_sha')
    if len(sha) != 40 or any(c not in '0123456789abcdef' for c in sha):
        raise DutyPolicyError('Invalid full commit SHA')
    people, groups, violations = {}, {}, []
    raw_people, raw_groups = snapshot['principals'], snapshot['groups']
    if not isinstance(raw_people, list) or not raw_people or len(raw_people) > 200:
        raise DutyPolicyError('Invalid principal inventory')
    if not isinstance(raw_groups, list) or len(raw_groups) > 200:
        raise DutyPolicyError('Invalid group inventory')
    for g in raw_groups:
        if not isinstance(g, dict) or set(g) != {'id', 'capabilities'}:
            raise DutyPolicyError('Invalid group record')
        gid = _string(g['id'], 'group.id')
        if gid in groups:
            raise DutyPolicyError('Duplicate group id')
        groups[gid] = _caps(g['capabilities'], f'group:{gid}')
    for p in raw_people:
        if not isinstance(p, dict) or set(p) != {'id', 'human_id', 'kind', 'capabilities', 'groups'}:
            raise DutyPolicyError('Invalid principal record')
        pid, human = _string(p['id'], 'principal.id'), _string(p['human_id'], 'principal.human_id')
        if pid in people:
            raise DutyPolicyError('Duplicate principal id')
        if p['kind'] not in ('human', 'service'):
            raise DutyPolicyError('Unknown principal kind')
        if not isinstance(p['groups'], list) or len(p['groups']) != len(set(p['groups'])):
            raise DutyPolicyError('Invalid group memberships')
        if any(g not in groups for g in p['groups']):
            raise DutyPolicyError('Unknown group membership')
        rights = _caps(p['capabilities'], pid)
        for gid in p['groups']:
            rights |= groups[gid]
        people[pid] = {'human_id': human, 'kind': p['kind'], 'rights': rights}
    assignments = snapshot['assignments']
    if not isinstance(assignments, dict) or set(assignments) != set(ROLES):
        raise DutyPolicyError('Missing/unknown mandatory separation role')
    for role, pid in assignments.items():
        if pid not in people:
            raise DutyPolicyError(f'Missing actor for {role}')
        if EXPECTED[role] not in people[pid]['rights']:
            violations.append({'code':'MISSING_ROLE_PERMISSION', 'role':role, 'principal':pid})
        if role in ('independent_reviewer','deployment_authorizer','ruleset_administrator') and people[pid]['kind'] != 'human':
            violations.append({'code':'HUMAN_ROLE_REQUIRED', 'role':role, 'principal':pid})
    # Detect shared control even when the same individual has multiple GitHub identities.
    by_human: dict[str, set[str]] = {}
    for person in people.values():
        by_human.setdefault(person['human_id'], set()).update(person['rights'])
    for human, rights in sorted(by_human.items()):
        if rights & UNTRUSTED and rights & TRUSTED:
            violations.append({'code':'CROSS_TRUST_CONTROL', 'identity':human,
                               'untrusted':sorted(rights & UNTRUSTED), 'trusted':sorted(rights & TRUSTED)})
        if 'review_approve' in rights and rights & PROTECTED:
            violations.append({'code':'REVIEWER_TRUST_ADMIN', 'identity':human,
                               'protected':sorted(rights & PROTECTED)})
        if 'deploy_authorize' in rights and rights & PROTECTED:
            violations.append({'code':'DEPLOYER_TRUST_ADMIN', 'identity':human,
                               'protected':sorted(rights & PROTECTED)})
        if 'ruleset_bypass' in rights:
            violations.append({'code':'BYPASS_CAPABILITY', 'identity':human})
    # An organizational account with common membership across trust boundaries
    # constitutes shared control, even if actor IDs appear different.
    for gid, rights in sorted(groups.items()):
        if rights & UNTRUSTED and rights & TRUSTED:
            violations.append({'code':'GROUP_CROSS_TRUST', 'group':gid})
    # Role separation is in addition to capability checks (even if grants incomplete).
    boundary_roles = ('candidate_author', 'evidence_producer')
    approval_roles = ('independent_reviewer', 'deployment_authorizer')
    for a in boundary_roles:
        for b in approval_roles:
            if people[assignments[a]]['human_id'] == people[assignments[b]]['human_id']:
                violations.append({'code':'ROLE_SELF_APPROVAL', 'roles':[a,b]})
    return {'status':'NO-GO' if violations else 'UNVERIFIABLE',
            'modeled_separation':'FAIL' if violations else 'PASS_UNATTESTED',
            'repository':repo, 'commit_sha':sha,
            'principal_count':len(people), 'group_count':len(groups),
            'violations':violations,
            'requires':['Independent live GitHub effective-permissions audit',
                        'Identity alias verification by trusted administrator',
                        'Active branch ruleset and non-compliant merge-block proof',
                        'Independent human review tied to exact commit']}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='Fail-closed modeled separation-of-duties audit; never grants GO')
    p.add_argument('--snapshot', required=True, help='Administrative snapshot; not automatically trusted')
    p.add_argument('--output')
    args = p.parse_args(argv)
    try:
        result = assess(json_strict(Path(args.snapshot).read_bytes()))
    except (OSError, ValueError, TypeError) as exc:
        result = {'status':'NO-GO', 'modeled_separation':'INVALID',
                  'violations':[{'code':'INVALID_SNAPSHOT', 'reason':str(exc)}]}
    body = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + '\n'
    if args.output:
        Path(args.output).write_text(body, encoding='utf-8')
    print(body, end='')
    return 2 if result['status'] == 'NO-GO' else 3  # no offline positive exit


if __name__ == '__main__':
    raise SystemExit(main())

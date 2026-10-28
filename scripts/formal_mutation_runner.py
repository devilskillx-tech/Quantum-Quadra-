"""Executable *bounded Python abstraction* and mutation sensitivity test.

This is NOT TLA+/TLC model checking and not a proof of the production code.
It complements formal/AtomicRevocation.tla. Intended for deterministic CI.
"""
from __future__ import annotations
import argparse
import json
from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class State:
    requested: bool = False
    authorized: bool = False
    local: bool = False
    outbox: bool = False
    anchored: bool = False
    anchor_checked: bool = False
    acknowledged: bool = False
    recovering: bool = False
    effects: int = 0
    unsafe_used: bool = False
    unauthorized_effect: bool = False


def invariants(s: State) -> list[str]:
    failures = []
    if s.acknowledged and (not s.anchored or not s.anchor_checked):
        failures.append('NO_PREMATURE_ACK')
    if s.local and not s.outbox:
        failures.append('OUTBOX_CONSISTENCY')
    if s.effects > 1:
        failures.append('IDEMPOTENCE')
    if s.unsafe_used:
        failures.append('NO_RESURRECTION')
    if s.unauthorized_effect:
        failures.append('AUTHORIZATION')
    return failures


def successors(s: State, mutation: str | None = None) -> list[tuple[str, State]]:
    actions = []
    if not s.requested:
        actions += [('AuthorizedRequest', replace(s,requested=True,authorized=True)),
                    ('UnauthorizedRequest', replace(s,requested=True,authorized=False))]
    if s.requested and not s.local and not s.anchored and (s.authorized or mutation=='unauthorized_commit'):
        actions.append(('Commit',replace(s,local=True,outbox=mutation!='drop_outbox', effects=1,
                                         unauthorized_effect=not s.authorized)))
    if s.local and s.outbox and not s.anchored:
        actions.append(('Publish',replace(s,anchored=True)))
    if s.anchored and not s.anchor_checked:
        actions.append(('VerifyAnchor',replace(s,anchor_checked=True)))
    if s.local and not s.acknowledged and (s.anchor_checked or mutation in ('premature_ack','skip_anchor_check')):
        if mutation=='premature_ack' or s.anchored:
            actions.append(('Confirm',replace(s,acknowledged=True)))
    if s.local and s.requested:
        actions.append(('RetryCommit',replace(s,effects=s.effects+(1 if mutation=='duplicate_effect' else 0))))
    if s.anchored and s.local and not s.recovering:
        actions.append(('RestoreOld',replace(s,local=False,outbox=False,acknowledged=False,
                            recovering=mutation!='unsafe_restore')))
    if s.anchored and s.recovering:
        actions.append(('Reconcile',replace(s,local=mutation!='false_reconcile',outbox=mutation!='false_reconcile',
                                            recovering=False)))
    if s.anchored and not s.local:
        allowed = not s.recovering or mutation=='allow_during_recovery'
        if allowed and not s.unsafe_used:
            actions.append(('AttemptUse',replace(s,unsafe_used=True)))
    return actions


MUTATIONS = {
    'premature_ack':'NO_PREMATURE_ACK',
    'skip_anchor_check':'NO_PREMATURE_ACK',
    'duplicate_effect':'IDEMPOTENCE',
    'drop_outbox':'OUTBOX_CONSISTENCY',
    'unsafe_restore':'NO_RESURRECTION',
    'allow_during_recovery':'NO_RESURRECTION',
    'false_reconcile':'NO_RESURRECTION',
    'unauthorized_commit':'AUTHORIZATION',
}


def explore(mutation: str | None = None, max_depth: int = 12) -> dict:
    initial=State()
    queue=deque([(initial, [])])
    visited={initial}
    transitions=0
    while queue:
        state, trace=queue.popleft()
        issues=invariants(state)
        if issues:
            return {'status':'COUNTEREXAMPLE','property':issues[0], 'trace':trace,
                    'states':len(visited),'transitions':transitions,'mutation':mutation}
        if len(trace)>=max_depth:
            continue
        for action, nxt in successors(state, mutation):
            transitions+=1
            if nxt not in visited:
                visited.add(nxt)
                queue.append((nxt,trace+[action]))
    return {'status':'BOUNDED_PASS','states':len(visited),'transitions':transitions,
            'depth':max_depth,'mutation':mutation}


def evaluate(max_depth:int=12) -> dict:
    baseline=explore(None,max_depth)
    mutants={m:explore(m,max_depth) for m in MUTATIONS}
    failures=[]
    if baseline['status']!='BOUNDED_PASS':
        failures.append('BASELINE_FAILURE')
    for mutant, expected in MUTATIONS.items():
        r=mutants[mutant]
        if r['status']!='COUNTEREXAMPLE' or r.get('property')!=expected:
            failures.append('MUTATION_SURVIVED_OR_WRONG_PROPERTY:'+mutant)
    return {'status':'PASS' if not failures else 'FAIL','scope':'BOUNDED_PYTHON_ABSTRACTION_NOT_TLC',
            'baseline':baseline,'mutants':mutants,'errors':failures}


def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument('--max-depth',type=int,default=12)
    args=p.parse_args(argv)
    if args.max_depth<4 or args.max_depth>30: p.error('max-depth must be 4..30')
    result=evaluate(args.max_depth)
    print(json.dumps(result,indent=2))
    return 0 if result['status']=='PASS' else 2


if __name__=='__main__': raise SystemExit(main())

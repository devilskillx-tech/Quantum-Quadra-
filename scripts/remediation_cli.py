"""Offline VRC CLI; prints model-only results, cannot authorize GitHub changes."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from scripts.evidence_verify import json_strict
from scripts.minimum_privilege_cut import solve
from scripts.remediation_certificate_build import build
from scripts.remediation_certificate_verify import verify
from scripts.authority_what_if import assess, AuthorityModelError


def _load(path: str) -> dict:
    return json_strict(Path(path).read_bytes())


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description='VRC offline synthetic model only (never production GO)')
    parser.add_argument('mode',choices=['plan','what-if','build','verify'])
    parser.add_argument('--graph',required=True,help='Synthetic graph, NOT authenticated live permissions')
    parser.add_argument('--policy',required=True,help='Offline policy; verify requires independently approved copy')
    parser.add_argument('--sha',required=True,help='Full candidate commit SHA')
    parser.add_argument('--source-id',required=True)
    parser.add_argument('--certificate',help='Untrusted VRC input for verification')
    parser.add_argument('--output')
    args=parser.parse_args(argv)
    try:
        graph,policy=_load(args.graph),_load(args.policy)
        plan=solve(graph,policy) if args.mode!='verify' else None
        if args.mode=='plan':
            result={'status':'MODEL_PLAN_'+plan['status'],'production_go':False,'solver':plan}
        elif args.mode=='what-if':
            if plan['status']!='OPTIMAL':
                result={'status':'UNVERIFIABLE','production_go':False,'solver':plan}
            else:
                result={'status':'SYNTHETIC_SIMULATION_ONLY','production_go':False,
                        'analysis':assess(graph,policy,plan['plan']['revoke'])}
        elif args.mode=='build':
            result=build(graph,policy,plan,args.sha,args.source_id)
        else:
            if not args.certificate:
                raise ValueError('--certificate is required for verification')
            result=verify(_load(args.certificate),graph,policy,args.sha,args.source_id)
    except (ValueError,TypeError,KeyError,OSError,AuthorityModelError) as exc:
        result={'status':'NO-GO','production_go':False,'reason':type(exc).__name__+':'+str(exc)}
    payload=json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+'\n'
    if args.output:
        Path(args.output).write_text(payload,encoding='utf-8')
    print(payload,end='')
    # Even successful model verification is explicitly NOT a production GO;
    # CLI success only represents the offline unit of work requested.
    return 2 if result.get('status') in ('NO-GO','REJECTED','UNVERIFIABLE') else 0


if __name__=='__main__':
    raise SystemExit(main())

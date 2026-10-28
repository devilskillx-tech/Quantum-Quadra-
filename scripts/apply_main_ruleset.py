"""Dry-run GitHub ruleset. --apply requires an explicit operator action and admin token.

Ruleset cannot be activated from ChatGPT's currently available GitHub connector.
Owner must run this on a trusted workstation or Codex with approved token.
"""
import argparse
import json
import os
import urllib.error
import urllib.request

REPO='devilskillx-tech/Quantum-Quadra-'
RULESET={
    'name':'QUADRA main — release and security gates',
    'target':'branch',
    'enforcement':'active',
    'bypass_actors':[],
    'conditions':{'ref_name':{'include':['refs/heads/main'],'exclude':[]}},
    'rules':[
        {'type':'deletion'},
        {'type':'non_fast_forward'},
        {'type':'pull_request','parameters':{
            'dismiss_stale_reviews_on_push':True,
            'require_code_owner_review':True,
            'required_approving_review_count':1,
            'require_last_push_approval':True,
            'required_review_thread_resolution':True,
            'allowed_merge_methods':['merge','squash','rebase']}},
        {'type':'required_status_checks','parameters':{
            'strict_required_status_checks_policy':True,
            'required_status_checks':[
                {'context':'release-gate'},
                {'context':'security'}]}}
    ]
}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--apply',action='store_true')
    p.add_argument('--repository',default=REPO)
    args=p.parse_args()
    if args.repository!=REPO:
        p.error('Explicit repository mismatch: refusing update')
    if not args.apply:
        print(json.dumps(RULESET,indent=2,ensure_ascii=False))
        print('DRY RUN: no GitHub rule has been activated')
        return
    token=os.environ.get('GITHUB_TOKEN')
    if not token:
        p.error('GITHUB_TOKEN with repository administration permissions required')
    endpoint='https://api.github.com/repos/'+args.repository+'/rulesets'
    request=urllib.request.Request(endpoint,json.dumps(RULESET).encode(),method='POST',headers={
        'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json',
        'X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(request,timeout=20) as response:
            data=json.load(response)
    except urllib.error.HTTPError as exc:
        raise SystemExit(f'NO-GO: ruleset activation failed (HTTP {exc.code})') from exc
    print('Created ruleset',data.get('id'),'for',args.repository)
    print('Verify effective protection in GitHub Settings > Rules > Rulesets')

if __name__=='__main__':main()

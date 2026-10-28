"""CLI entrypoint, no unsafe implicit operations."""
import argparse
import base64
import json
import os
import secrets
import tempfile
import uuid
from .store import QuadraStore
from .search import LocalSemanticModel

def main(argv=None):
    p=argparse.ArgumentParser(prog='quadra',description='QUANTUM QUADRA reconstructed sources')
    p.add_argument('--db',default=os.environ.get('QUADRA_EDGE_DB','./quadra.db'))
    sub=p.add_subparsers(dest='cmd',required=True)
    sub.add_parser('generate-key')
    sub.add_parser('selftest')
    sub.add_parser('status')
    sub.add_parser('verify')
    b=sub.add_parser('benchmark');b.add_argument('--dataset',required=True);b.add_argument('--k',type=int,default=10);b.add_argument('--mode',choices=['bm25','hybrid'],default='bm25');b.add_argument('--model-path')
    dl=sub.add_parser('sync-requeue-dead');dl.add_argument('--scope',required=True);dl.add_argument('--confirm-local-operator',action='store_true')
    mi=sub.add_parser('migrate-audit-anchor');mi.add_argument('--confirm-local-operator',action='store_true')
    sub.add_parser('init')
    w=sub.add_parser('write');w.add_argument('--scope',required=True);w.add_argument('--key',required=True);w.add_argument('--payload',required=True)
    r=sub.add_parser('read');r.add_argument('--scope',required=True);r.add_argument('--id',required=True)
    t=sub.add_parser('revoke');t.add_argument('--scope',required=True);t.add_argument('--id',required=True)
    sr=sub.add_parser('search');sr.add_argument('--scope',required=True);sr.add_argument('--query',required=True);sr.add_argument('--mode',choices=['bm25','hybrid'],default='bm25')
    cr=sub.add_parser('rotate');cr.add_argument('--scope',required=True)
    co=sub.add_parser('consolidate');co.add_argument('--scope',required=True);co.add_argument('--key',required=True)
    si=sub.add_parser('sync-init');si.add_argument('--dsn',required=True);si.add_argument('--confirm-local-operator',action='store_true')
    sy=sub.add_parser('sync-push');sy.add_argument('--dsn',required=True);sy.add_argument('--scope',required=True)
    sp=sub.add_parser('sync-pull');sp.add_argument('--dsn',required=True);sp.add_argument('--scope',required=True)
    sv=sub.add_parser('serve');sv.add_argument('--host',default='127.0.0.1');sv.add_argument('--port',type=int,default=8000)
    a=p.parse_args(argv)
    if a.cmd=='generate-key':
        print(base64.b64encode(secrets.token_bytes(32)).decode());return 0
    if a.cmd=='selftest':
        key=secrets.token_bytes(32);scope=str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as tmp:
            with QuadraStore(os.path.join(tmp,'test.db'),key) as store:
                cid=store.put(scope,'health',{'a':{'x':5}})
                assert store.read(scope,cid)['payload']['a']['x']==5
                assert store.search(scope,'health')[0]['cell_id']==cid
                assert store.rotate_dek(scope)==2
                assert store.read(scope,cid)['payload']['a']['x']==5
                store.transition(scope,cid,'REVOKED')
                assert store.verify_all()['valid']
        print('SELFTEST OK (SQLite local uniquement)');return 0
    if a.cmd=='benchmark':
        from .benchmark import evaluate_file
        result=evaluate_file(a.dataset,a.k,a.mode,a.model_path)
        print(json.dumps(result,indent=2,ensure_ascii=False));return 0
    if a.cmd=='migrate-audit-anchor':
        if not a.confirm_local_operator: p.error('migrate-audit-anchor exige --confirm-local-operator')
        with QuadraStore(a.db, allow_legacy_audit_migration=True) as store:
            result=store.verify_all()
        print(json.dumps(result,ensure_ascii=False));return 0 if result['valid'] else 1
    if a.cmd=='sync-requeue-dead':
        if not a.confirm_local_operator: p.error('sync-requeue-dead exige --confirm-local-operator')
        from .sync import requeue_dead
        with QuadraStore(a.db) as store: count=requeue_dead(store,a.scope)
        print(json.dumps({'requeued':count}));return 0
    if a.cmd=='serve':
        import uvicorn
        from .api import create_app
        uvicorn.run(create_app(),host=a.host,port=a.port);return 0
    if a.cmd.startswith('sync-'):
        if a.cmd=='sync-init' and not a.confirm_local_operator:
            p.error('sync-init exige --confirm-local-operator')
        try: import psycopg2
        except ImportError as exc: p.error('Installer l’extra [postgres]')
        from .sync import init_core,push_outbox,pull_core
        pg=psycopg2.connect(a.dsn,connect_timeout=5)
        try:
            if a.cmd=='sync-init':init_core(pg);result={'schema':'initialisé'}
            else:
                with QuadraStore(a.db) as store:
                    result=(push_outbox(store,pg,a.scope) if a.cmd=='sync-push' else pull_core(store,pg,a.scope))
        finally:pg.close()
        print(json.dumps(result,ensure_ascii=False));return 0
    with QuadraStore(a.db) as store:
        if a.cmd=='status':result=store.status()
        elif a.cmd=='verify':result=store.verify_all()
        elif a.cmd=='init':result={'initialized':a.db}
        elif a.cmd=='write':result={'cell_id':store.put(a.scope,a.key,json.loads(a.payload))}
        elif a.cmd=='read':result=store.read(a.scope,a.id)
        elif a.cmd=='revoke':result={'revision':store.transition(a.scope,a.id,'REVOKED')}
        elif a.cmd=='search':
            model=LocalSemanticModel(os.environ['QUADRA_SEMANTIC_MODEL_PATH']) if a.mode=='hybrid' and os.getenv('QUADRA_SEMANTIC_MODEL_PATH') else None
            result=store.search(a.scope,a.query,mode=a.mode,semantic=model)
        elif a.cmd=='rotate':result={'new_version':store.rotate_dek(a.scope)}
        elif a.cmd=='consolidate':result={'cell_id':store.consolidate_extractively(a.scope,a.key)}
        else:raise AssertionError(a.cmd)
        print(json.dumps(result,indent=2,ensure_ascii=False))
    return 0

if __name__=='__main__':
    raise SystemExit(main())

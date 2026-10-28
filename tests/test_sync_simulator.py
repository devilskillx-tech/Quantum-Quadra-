"""Behavioral PostgreSQL simulator. Does NOT certify a real PostgreSQL deployment."""
import copy
import secrets
import uuid
import pytest
from quantum_quadra.store import QuadraStore, QuadraError
from quantum_quadra.sync import push_outbox, pull_core
from quantum_quadra.crypto import encrypt, canonical, aad_for


class SimulatedPG:
    def __init__(self):
        self.committed={'keys':{},'cells':{},'receipts':{}}
        self.work=copy.deepcopy(self.committed)
        self.answer=None
        self.fail_next_commit=False
        self.commits=0
    def cursor(self): return self
    def __enter__(self): return self
    def __exit__(self,*a): pass
    def execute(self,sql,args=()):
        normalized=' '.join(sql.lower().split())
        self.answer=None
        if normalized.startswith('select 1 from quadra_sync_receipts'):
            self.answer=(1,) if args[0] in self.work['receipts'] else None
        elif normalized.startswith('select cell_id,scope_id,memory_kind,logical_key,creator_type,status') and 'for update' in normalized:
            r=self.work['cells'].get(args[0])
            names=('cell_id','scope_id','memory_kind','logical_key','creator_type','status',
                   'key_version','revision','payload_sha256','encrypted_payload','importance','created_at')
            self.answer=tuple(r.get(n) for n in names) if r else None
        elif normalized.startswith('select wrapped_dek from quadra_scope_keys'):
            v=self.work['keys'].get((str(args[0]),int(args[1])))
            self.answer=(v,) if v else None
        elif normalized.startswith('insert into quadra_scope_keys'):
            self.work['keys'][(str(args[0]),int(args[1]))]=bytes(args[2])
        elif normalized.startswith('insert into quadra_core_cells'):
            names=('cell_id','scope_id','memory_kind','logical_key','creator_type','status',
                   'key_version','revision','payload_sha256','encrypted_payload','importance','created_at')
            self.work['cells'][str(args[0])]=dict(zip(names,args))
        elif normalized.startswith('insert into quadra_sync_receipts'):
            self.work['receipts'][str(args[0])]=tuple(args)
        elif normalized.startswith('select version,wrapped_dek from quadra_scope_keys'):
            self.answer=sorted([(v,wrap) for (sid,v),wrap in self.work['keys'].items() if sid==str(args[0])])
        elif 'from quadra_core_cells where scope_id=%s order by updated_at desc' in normalized:
            names=('cell_id','scope_id','memory_kind','logical_key','creator_type','status',
                   'key_version','revision','payload_sha256','encrypted_payload','importance','created_at')
            self.answer=[tuple(c[n] for n in names) for c in self.work['cells'].values()
                         if str(c['scope_id'])==str(args[0])][:int(args[1])]
        else:
            raise NotImplementedError('SQL non simulé : '+normalized[:110])
        return self
    def fetchone(self):return self.answer
    def fetchall(self):return self.answer or []
    def commit(self):
        if self.fail_next_commit:
            self.fail_next_commit=False
            raise ConnectionError('panne simulée AVANT commit PostgreSQL')
        self.committed=copy.deepcopy(self.work);self.commits+=1
    def rollback(self):self.work=copy.deepcopy(self.committed)


@pytest.fixture
def peers(tmp_path):
    key=secrets.token_bytes(32);scope=str(uuid.uuid4());pg=SimulatedPG()
    with QuadraStore(str(tmp_path/'a.db'),key) as a, QuadraStore(str(tmp_path/'b.db'),key) as b:
        yield a,b,pg,scope


def test_two_device_push_pull(peers):
    a,b,pg,scope=peers
    cid=a.put(scope,'canonical',{'truth':'alpha'})
    assert push_outbox(a,pg,scope)['pushed']==1
    assert pull_core(b,pg,scope)['pulled']==1
    assert b.read(scope,cid)['payload']=={'truth':'alpha'}


def test_replay_after_commit_before_local_ack(peers):
    a,b,pg,scope=peers
    cid=a.put(scope,'canonical',{'truth':'alpha'})
    def crash(_): raise ConnectionError('after remote commit, before local acknowledgement')
    first=push_outbox(a,pg,scope,after_core_commit=crash)
    assert first['failed']==1 and len(pg.committed['receipts'])==1
    a.db.execute("UPDATE q_outbox SET next_attempt_at='1970-01-01T00:00:00+00:00'")
    a.db.commit()
    second=push_outbox(a,pg,scope)
    assert second['pushed']==1
    assert len(pg.committed['receipts'])==1 and len(pg.committed['cells'])==1
    assert a.status(scope)['pending_events']==0


def test_failure_before_remote_commit_rolls_back(peers):
    a,b,pg,scope=peers
    a.put(scope,'a',{'n':1})
    pg.fail_next_commit=True
    assert push_outbox(a,pg,scope)['failed']==1
    assert pg.committed['cells']=={} and pg.committed['receipts']=={}


def test_remote_revocation_propagates_and_is_terminal(peers):
    a,b,pg,scope=peers
    cid=a.put(scope,'a',{'x':1})
    push_outbox(a,pg,scope)
    pull_core(b,pg,scope)
    assert b.read(scope,cid)['payload']=={'x':1}
    a.transition(scope,cid,'REVOKED')
    assert push_outbox(a,pg,scope)['failed']==0
    assert pull_core(b,pg,scope)['pulled']==1
    with pytest.raises(QuadraError):b.read(scope,cid)
    assert b.verify_all(scope)['valid']


def test_pull_does_not_overwrite_pending_local_edit(peers):
    a,b,pg,scope=peers
    cid=a.put(scope,'a',{'x':1});push_outbox(a,pg,scope);pull_core(b,pg,scope)
    b.transition(scope,cid,'ARCHIVED')
    a.transition(scope,cid,'REVOKED');push_outbox(a,pg,scope)
    result=pull_core(b,pg,scope)
    assert result['skipped']==1
    assert b.read(scope,cid,allow_inactive=True)['status']=='ARCHIVED'


def test_same_revision_new_nonce_does_not_conflict(peers):
    a,b,pg,scope=peers
    cid=a.put(scope,'a',{'x':1});push_outbox(a,pg,scope);pull_core(b,pg,scope)
    with b.transaction():
        row=b.db.execute('SELECT * FROM q_cells WHERE cell_id=?',(cid,)).fetchone()
        key,_=b._key(scope,row['key_version'])
        new_blob=encrypt(key,canonical({'x':1}),aad_for(dict(row)))
        b.db.execute('UPDATE q_cells SET encrypted_payload=? WHERE cell_id=?',(new_blob,cid))
        b._event(cid,'UPSERT',1)
    assert push_outbox(b,pg,scope)['pushed']==1
    assert pg.committed['cells'][cid]['encrypted_payload']!=new_blob


def test_remote_ciphertext_corruption_does_not_get_acknowledged(peers):
    a,b,pg,scope=peers
    cid=a.put(scope,'a',{'x':1});push_outbox(a,pg,scope)
    bad=pg.work['cells'][cid]['encrypted_payload'];pg.work['cells'][cid]['encrypted_payload']=bad[:-1]+bytes([bad[-1]^1]);pg.commit()
    b.put(scope,'new',{'payload':True})
    result=push_outbox(b,pg,scope)
    # Unrelated new cell can still be pushed; the corrupted remote one fails to pull.
    with pytest.raises(Exception):pull_core(b,pg,scope)

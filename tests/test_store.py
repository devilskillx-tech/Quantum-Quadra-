import os
import uuid
import secrets
import sqlite3
import pytest
from quantum_quadra import QuadraStore, QuadraError, IntegrityError
from quantum_quadra.cli import main
from quantum_quadra.search import bm25_scores

@pytest.fixture
def ctx(tmp_path):
    scope=str(uuid.uuid4())
    with QuadraStore(str(tmp_path/'q.db'),secrets.token_bytes(32)) as store:
        yield store,scope

def test_write_read_nested(ctx):
    s,scope=ctx
    cid=s.put(scope,'alpha',{'nested':{'value':['one',42]}})
    assert s.read(scope,cid)['payload']['nested']['value']==['one',42]
    assert s.verify_all()['valid']

def test_same_payload_unique_ids(ctx):
    s,scope=ctx
    assert s.put(scope,'a',{'a':1})!=s.put(scope,'a',{'a':1})

def test_scope_isolation(ctx):
    s,scope=ctx
    cid=s.put(scope,'secret',{'secret':'private'})
    with pytest.raises(KeyError):s.read(str(uuid.uuid4()),cid)
    assert s.search(str(uuid.uuid4()),'private')==[]

def test_status_tamper_detected(ctx):
    s,scope=ctx
    cid=s.put(scope,'a',{'x':'z'})
    s.transition(scope,cid,'REVOKED')
    s.db.execute("UPDATE q_cells SET status='ACTIVE' WHERE cell_id=?",(cid,));s.db.commit()
    with pytest.raises(IntegrityError):s.read(scope,cid)
    assert not s.verify_all()['valid']

def test_ciphertext_tamper(ctx):
    s,scope=ctx
    cid=s.put(scope,'a',{'x':1})
    blob=s.db.execute('SELECT encrypted_payload FROM q_cells WHERE cell_id=?',(cid,)).fetchone()[0]
    damaged=blob[:-1]+bytes([blob[-1]^1])
    s.db.execute('UPDATE q_cells SET encrypted_payload=? WHERE cell_id=?',(damaged,cid));s.db.commit()
    with pytest.raises(IntegrityError):s.read(scope,cid)

def test_revocation_is_terminal(ctx):
    s,scope=ctx
    cid=s.put(scope,'a',{'x':1})
    s.transition(scope,cid,'REVOKED')
    with pytest.raises(QuadraError):s.transition(scope,cid,'ARCHIVED')
    with pytest.raises(QuadraError):s.read(scope,cid)

def test_key_rotation(ctx):
    s,scope=ctx
    cid=s.put(scope,'a',{'x':1})
    assert s.rotate_dek(scope)==2
    assert s.read(scope,cid)['payload']=={'x':1}
    assert s.verify_all()['valid']

def test_rollback_on_bad_rotation(ctx,monkeypatch):
    s,scope=ctx
    cid=s.put(scope,'a',{'x':1})
    import quantum_quadra.store as mod
    monkeypatch.setattr(mod,'encrypt',lambda *args,**kwargs:(_ for _ in ()).throw(ValueError('boom')))
    with pytest.raises(ValueError):s.rotate_dek(scope)
    assert s.db.execute('SELECT key_version FROM q_cells WHERE cell_id=?',(cid,)).fetchone()[0]==1

def test_restart_key(ctx):
    s,scope=ctx
    cid=s.put(scope,'a',{'x':1})
    with QuadraStore(s.path,s.kek) as reopened:
        assert reopened.read(scope,cid)['payload']=={'x':1}
    with pytest.raises(IntegrityError):QuadraStore(s.path,secrets.token_bytes(32))

def test_lexical_search(ctx):
    s,scope=ctx
    s.put(scope,'fruit',{'text':'pommes et poires'})
    s.put(scope,'animals',{'text':'chiens et chats'})
    assert s.search(scope,'pommes')[0]['logical_key']=='fruit'
    assert s.search(scope,'des termes absents')==[]

def test_no_fake_semantics(ctx):
    s,scope=ctx
    s.put(scope,'a',{'q':'alpha'})
    with pytest.raises(RuntimeError,match='modèle'):s.search(scope,'alpha',mode='hybrid')

def test_consolidation_provenance(ctx):
    s,scope=ctx
    ids=[s.put(scope,'key',{'episode':i}) for i in range(3)]
    cid=s.consolidate_extractively(scope,'key')
    assert cid is not None
    payload=s.read(scope,cid)['payload']
    assert [r['cell_id'] for r in payload['sources']]==ids
    assert all(s.read(scope,x)['status']=='ACTIVE' for x in ids)

def test_audit_deletion_detected(ctx):
    s,scope=ctx
    s.put(scope,'a',{'x':1})
    s.db.execute('DELETE FROM q_audit');s.db.commit()
    assert not s.verify_all()['valid']

def test_audit_edit_detected(ctx):
    s,scope=ctx
    s.put(scope,'a',{'x':1})
    s.db.execute("UPDATE q_audit SET action='FAKE' WHERE seq=1");s.db.commit()
    assert not s.verify_audit()['valid']

def test_outbox_persists(ctx):
    s,scope=ctx
    s.put(scope,'a',{'x':1})
    assert s.status(scope)['pending_events']==1

def test_sqlite_integrity(ctx):
    s,scope=ctx
    for i in range(10):s.put(scope,str(i),{'i':i})
    assert s.db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'

def test_cli_smoke():
    assert main(['selftest'])==0

def test_bm25_order():
    score=bm25_scores('alpha',['alpha alpha','beta beta'])
    assert score[0]>score[1]

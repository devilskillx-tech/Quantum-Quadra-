"""V7.4 tests are deterministic; PostgreSQL tests using a simulator are NOT live integration tests."""
import json
import os
import secrets
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from quantum_quadra.store import QuadraStore, IntegrityError
from quantum_quadra.sync import (allow_remote_advance, SyncConflict, MAX_SYNC_ATTEMPTS,
                                 _lease, push_outbox, requeue_dead)
from quantum_quadra.benchmark import evaluate
from quantum_quadra.cli import main


@pytest.fixture
def context(tmp_path):
    key=secrets.token_bytes(32);scope=str(uuid.uuid4())
    with QuadraStore(str(tmp_path/'test.db'),key) as db:
        yield db,scope


def test_audit_tail_deletion_detected(context):
    db,scope=context
    db.put(scope,'a',{'n':1});db.put(scope,'b',{'n':2})
    db.db.execute('DELETE FROM q_audit WHERE seq=(SELECT MAX(seq) FROM q_audit)')
    db.db.commit()
    result=db.verify_audit()
    assert result['valid'] is False and result['reason']=='audit_head_mismatch'


def test_audit_complete_deletion_detected(context):
    db,scope=context
    db.put(scope,'a',{'n':1});db.db.execute('DELETE FROM q_audit');db.db.commit()
    assert db.verify_audit()['valid'] is False


def test_audit_anchor_edit_detected(context):
    db,scope=context
    db.put(scope,'a',{'n':1})
    db.db.execute("UPDATE q_meta SET value=? WHERE name='audit_anchor_v1'",('garbage',))
    db.db.commit()
    assert db.verify_audit()['reason']=='invalid_audit_anchor'


def test_audit_migration_legacy_db(tmp_path):
    path=str(tmp_path/'migrate.db');key=secrets.token_bytes(32);scope=str(uuid.uuid4())
    with QuadraStore(path,key) as db:
        cid=db.put(scope,'rule',{'nested':{'true':True}})
        db.db.execute("DELETE FROM q_meta WHERE name='audit_anchor_v1'");db.db.commit()
    with pytest.raises(IntegrityError): QuadraStore(path,key)
    with QuadraStore(path,key,allow_legacy_audit_migration=True) as db:
        assert db.read(scope,cid)['payload']['nested']['true']
        assert db.verify_all()['valid']


def test_audit_migration_rejects_corrupt_history(tmp_path):
    path=str(tmp_path/'bad.db');key=secrets.token_bytes(32);scope=str(uuid.uuid4())
    with QuadraStore(path,key) as db:
        db.put(scope,'rule',{'p':1})
        db.db.execute("DELETE FROM q_meta WHERE name='audit_anchor_v1'")
        db.db.execute("UPDATE q_audit SET action='BAD'")
        db.db.commit()
    with pytest.raises(IntegrityError): QuadraStore(path,key,allow_legacy_audit_migration=True)


def test_audit_anchor_deleted_cannot_be_recreated_silently(tmp_path):
    path=str(tmp_path/'remove.db');key=secrets.token_bytes(32);scope=str(uuid.uuid4())
    with QuadraStore(path,key) as db:
        db.put(scope,'a',{'p':1});db.put(scope,'b',{'p':2})
        db.db.execute("DELETE FROM q_audit WHERE seq=(SELECT MAX(seq) FROM q_audit)")
        db.db.execute("DELETE FROM q_meta WHERE name='audit_anchor_v1'")
        db.db.commit()
    with pytest.raises(IntegrityError,match='Ancre'):
        QuadraStore(path,key)


def test_missing_master_marker_fails_closed(tmp_path):
    path=str(tmp_path/'no-marker.db');key=secrets.token_bytes(32);scope=str(uuid.uuid4())
    with QuadraStore(path,key) as db:
        db.put(scope,'a',{'p':1})
        db.db.execute("DELETE FROM q_meta WHERE name='key_marker'")
        db.db.commit()
    with pytest.raises(IntegrityError,match='Marqueur'):
        QuadraStore(path,key)


def test_audit_scope_counts_not_leaked(context):
    db,scope=context
    other=str(uuid.uuid4());db.put(scope,'a',{'x':1});db.put(other,'b',{'x':2})
    scoped=db.verify_all(scope)
    assert scoped['checked']==1 and scoped['audit']=={'valid':True}


def test_reject_nan_importance(context):
    db,scope=context
    for value in (float('nan'),float('inf'),float('-inf'),-0.1,1.01):
        with pytest.raises(ValueError): db.put(scope,'x',{'x':1},importance=value)


def test_parallel_search_and_writes_are_serialized(context):
    db,scope=context
    def work(i):
        cid=db.put(scope,f'key-{i}',{'text':f'alpha-{i}'})
        assert db.read(scope,cid)['payload']['text']==f'alpha-{i}'
        db.search(scope,'alpha',limit=2)
    with ThreadPoolExecutor(max_workers=6) as executor:
        list(executor.map(work,range(48)))
    assert db.verify_all()['valid']


def record(**changes):
    result={'cell_id':str(uuid.uuid4()),'scope_id':str(uuid.uuid4()),'revision':1,
            'status':'ACTIVE','payload_sha256':'a'*64,'memory_kind':'EPISODIC',
            'logical_key':'x','creator_type':'HUMAN'}
    result.update(changes);return result


def test_identical_revision_random_ciphertext_no_conflict():
    local=record();remote=dict(local)
    assert allow_remote_advance(remote,local) is False


def test_changed_revision_same_number_is_conflict():
    local=record();remote=dict(local,payload_sha256='b'*64)
    with pytest.raises(SyncConflict): allow_remote_advance(remote,local)


def test_no_remote_resurrection():
    local=record(revision=3,status='ACTIVE');remote=dict(local,revision=2,status='REVOKED')
    with pytest.raises(SyncConflict): allow_remote_advance(remote,local)


def test_scope_collision_blocked():
    local=record();remote=dict(local,scope_id=str(uuid.uuid4()))
    with pytest.raises(SyncConflict): allow_remote_advance(remote,local)


def test_lease_prevents_duplicate_claim(context):
    db,scope=context
    db.put(scope,'a',{'x':1})
    first=_lease(db,scope,10)
    assert len(first)==1
    assert _lease(db,scope,10)==[]


class BrokenPostgres:
    def cursor(self):raise ConnectionError('simulated outage')
    def rollback(self):pass


def test_poison_event_dead_letter_and_operator_requeue(context):
    db,scope=context
    db.put(scope,'a',{'x':1})
    for attempt in range(MAX_SYNC_ATTEMPTS):
        result=push_outbox(db,BrokenPostgres(),scope)
        assert result['failed']==1
        db.db.execute("UPDATE q_outbox SET next_attempt_at='1970-01-01T00:00:00+00:00'")
        db.db.commit()
    assert db.status(scope)['dead_events']==1
    assert db.status(scope)['pending_events']==0
    assert push_outbox(db,BrokenPostgres(),scope)['failed']==0
    assert requeue_dead(db,scope)==1
    assert db.status(scope)['pending_events']==1


def test_benchmark_scope_and_metrics():
    scope=str(uuid.uuid4());other=str(uuid.uuid4())
    dataset={'documents':[{'id':'a','scope':scope,'text':'alpha alpha'} ,
                          {'id':'b','scope':scope,'text':'beta beta'},
                          {'id':'c','scope':other,'text':'alpha alpha'}],
             'queries':[{'text':'alpha','scope':scope,'relevant':['a']}]}
    result=evaluate(dataset,k=2)
    assert result['queries_evaluated']==1
    assert result['metrics']['recall_at_k']==1.0
    assert result['per_query'][0]['retrieved_ids']==['a']
    dataset['queries'][0]['relevant']=['c']
    with pytest.raises(ValueError,match='inter-scopes'): evaluate(dataset)


def test_benchmark_cli(tmp_path,capsys):
    scope='s1'
    dataset={'documents':[{'id':'x','scope':scope,'text':'canon sha256'}],
             'queries':[{'text':'sha256','scope':scope,'relevant':['x']}]}
    path=tmp_path/'eval.json';path.write_text(json.dumps(dataset),encoding='utf-8')
    assert main(['benchmark','--dataset',str(path),'--k','1'])==0
    assert json.loads(capsys.readouterr().out)['metrics']['ndcg_at_k']==1.0


def test_hybrid_rejects_missing_model():
    dataset={'documents':[{'id':'x','scope':'s1','text':'hi'}],
             'queries':[{'text':'hi','scope':'s1','relevant':['x']}]}
    with pytest.raises(RuntimeError):evaluate(dataset,mode='hybrid')

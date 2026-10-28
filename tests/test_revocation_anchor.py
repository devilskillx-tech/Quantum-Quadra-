import json
import sqlite3
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from quantum_quadra.revocation_anchor import RevocationLedger, ExternalWitness, IntegrityError, sign, canonical, verify_event
from quadra_all import demo_rollback

@pytest.fixture
def session(tmp_path):
    issuer=Ed25519PrivateKey.generate()
    key=Ed25519PrivateKey.generate()
    witness=ExternalWitness(tmp_path/'remote.sqlite',key,issuer.public_key())
    ledger=RevocationLedger(tmp_path/'edge.sqlite',issuer,witness,key.public_key())
    yield issuer,key,witness,ledger
    ledger.close();witness.close()


def test_anchor_and_revoke(session):
    _,_,w,l=session
    assert l.verify_and_status()['status']=='UNVERIFIABLE'
    l.revoke('A','req-1')
    assert not l.certificate_usable('A')
    assert l.send_pending()[0]['sequence']==1
    assert l.verify_and_status()['status']=='VERIFIED'
    assert not l.certificate_usable('A')
    assert l.certificate_usable('B')


def test_idempotent_replay(session):
    _,_,w,l=session
    a=l.revoke('A','req-1')
    assert a==l.revoke('A','req-1')
    assert len(l.send_pending())==1
    assert len(l.send_pending())==0
    assert w.latest()['sequence']==1


def test_collision_rejected(session):
    _,_,w,l=session
    l.revoke('A','req')
    with pytest.raises(IntegrityError): l.revoke('B','req')


def test_unauthentic_event_rejected(session):
    _,_,w,l=session
    r=l.revoke('A','req')
    r['event']['certificate_id']='B'
    with pytest.raises(IntegrityError):w.publish(r)


def test_unknown_issuer_rejected(session):
    _,_,w,l=session
    r=l.revoke('A','req')
    body=r['event']
    r['issuer_signature']=sign(Ed25519PrivateKey.generate(),body)
    assert not verify_event(r,l.pub)


def test_wrong_checkpoint_signature(session):
    _,_,w,l=session
    l.revoke('A','req');l.send_pending()
    w.db.execute("UPDATE checkpoints SET signature=?",('invalid',))
    assert l.verify_and_status()['status']=='REJECTED'
    assert not l.certificate_usable('B')


def test_local_event_tampering(session):
    _,_,w,l=session
    l.revoke('A','req');l.send_pending()
    l.db.execute("UPDATE events SET record=? WHERE sequence=1",('{}',))
    assert l.verify_and_status()['status']=='REJECTED'


def test_archive_fork_rejected(session):
    _,_,w,l=session
    l.revoke('A','req');l.send_pending()
    w.db.execute("UPDATE archive SET record=? WHERE sequence=1",('{}',))
    assert l.verify_and_status()['status']=='REJECTED'


def test_pending_until_anchor(session):
    _,_,w,l=session
    l.revoke('A','req')
    assert l.db.execute("SELECT status FROM outbox").fetchone()[0]=='PENDING'
    assert l.verify_and_status()['status']=='UNVERIFIABLE'
    l.send_pending()
    assert l.db.execute("SELECT status FROM outbox").fetchone()[0]=='CONFIRMED'


def test_missed_receipt_retry(session):
    _,_,w,l=session
    r=l.revoke('A','req')
    w.publish(r) # Simulates external commit followed by lost response.
    assert l.db.execute("SELECT status FROM outbox").fetchone()[0]=='PENDING'
    receipts=l.send_pending()
    assert len(receipts)==1
    assert w.latest()['sequence']==1


def test_two_revocations(session):
    _,_,w,l=session
    l.revoke('A','a');l.revoke('B','b')
    assert len(l.send_pending())==2
    assert w.latest()['sequence']==2
    assert l.verify_and_status()['status']=='VERIFIED'


def test_reordering_rejected(session):
    _,_,w,l=session
    l.revoke('A','a');l.revoke('B','b')
    second=json.loads(l.db.execute('SELECT record FROM events WHERE sequence=2').fetchone()[0])
    with pytest.raises(IntegrityError): w.publish(second)


def test_real_sqlite_snapshot_rollback():
    result=demo_rollback()
    assert result['status']=='PASS'
    assert result['rollback_status']=='RECOVERY_REQUIRED'
    assert result['revoked_certificate_accepted'] is False


def test_checkpoint_must_cover_record(session):
    _,_,w,l=session
    record=l.revoke('A','a')
    receipt=w.publish(record)
    assert w.includes(record,receipt)
    tampered=dict(record, event_hash='f'*64)
    assert not w.includes(tampered,receipt)


def test_truncated_local_journal_detected(session):
    _,_,w,l=session
    l.revoke('A','a');l.revoke('B','b');l.send_pending()
    l.db.execute('DELETE FROM outbox WHERE event_id=?',('b',))
    l.db.execute('DELETE FROM events WHERE event_id=?',('b',))
    assert l.verify_and_status()['status']=='RECOVERY_REQUIRED'
    assert not l.certificate_usable('B')
    assert l.reconcile()['status']=='VERIFIED'
    assert not l.certificate_usable('B')

"""Release-blocking local security and durability checks (no PostgreSQL required)."""
import os
import secrets
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from quantum_quadra.store import QuadraStore, IntegrityError, QuadraError
from quantum_quadra.sync import _lease, requeue_dead, MAX_SYNC_ATTEMPTS, push_outbox


def test_wrong_key_and_tampered_scope_envelope_fail_closed(tmp_path):
    path = str(tmp_path / 'test.db')
    master = secrets.token_bytes(32)
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    with QuadraStore(path, master) as store:
        aid = store.put(a, 'identity-a', {'secret': 'a'})
        bid = store.put(b, 'identity-b', {'secret': 'b'})
        with pytest.raises(KeyError):
            store.read(a, bid)
        with store.transaction():
            store.db.execute('UPDATE q_cells SET scope_id=? WHERE cell_id=?', (a, bid))
        with pytest.raises(IntegrityError):
            store.read(a, bid)
        assert store.read(a, aid)['payload']['secret'] == 'a'
    with pytest.raises(IntegrityError):
        QuadraStore(path, secrets.token_bytes(32))


def test_audit_tail_truncation_fails_closed_on_reopen(tmp_path):
    path = str(tmp_path / 'audit.db')
    key = secrets.token_bytes(32)
    scope = str(uuid.uuid4())
    with QuadraStore(path, key) as db:
        db.put(scope, 'one', {'x': 1})
        db.put(scope, 'two', {'x': 2})
        db.db.execute('DELETE FROM q_audit WHERE seq=(SELECT MAX(seq) FROM q_audit)')
        db.db.commit()
        assert not db.verify_audit()['valid']
    with pytest.raises(IntegrityError):
        QuadraStore(path, key)


def test_atomic_rollback_on_failing_audit(tmp_path, monkeypatch):
    key = secrets.token_bytes(32)
    scope = str(uuid.uuid4())
    with QuadraStore(str(tmp_path / 'rollback.db'), key) as db:
        def fail(*_args):
            raise RuntimeError('injected audit failure')
        monkeypatch.setattr(db, '_audit', fail)
        with pytest.raises(RuntimeError, match='injected audit'):
            db.put(scope, 'must-not-exist', {'x': 1})
        assert db.db.execute('SELECT COUNT(*) FROM q_cells').fetchone()[0] == 0
        assert db.db.execute('SELECT COUNT(*) FROM q_outbox').fetchone()[0] == 0
        assert db.verify_audit()['valid']


def test_concurrent_lease_claims_exactly_once(tmp_path):
    scope = str(uuid.uuid4())
    with QuadraStore(str(tmp_path / 'lease.db'), secrets.token_bytes(32)) as db:
        ids = [db.put(scope, f'key-{i}', {'n': i}) for i in range(40)]
        def lease(_):
            return [row['event_id'] for row in _lease(db, scope, 6)]
        with ThreadPoolExecutor(max_workers=10) as pool:
            batches = list(pool.map(lease, range(10)))
        flattened = [eid for batch in batches for eid in batch]
        assert len(flattened) == 40
        assert len(set(flattened)) == 40
        assert len(ids) == 40
        assert _lease(db, scope, 1) == []


def test_terminal_state_prevents_resurrection_even_after_rotation(tmp_path):
    scope = str(uuid.uuid4())
    with QuadraStore(str(tmp_path / 'terminal.db'), secrets.token_bytes(32)) as db:
        cell = db.put(scope, 'term', {'x': 1})
        assert db.transition(scope, cell, 'REVOKED') == 2
        db.rotate_dek(scope)
        with pytest.raises(QuadraError):
            db.read(scope, cell)
        with pytest.raises(QuadraError):
            db.transition(scope, cell, 'ARCHIVED')
        assert db.read(scope, cell, allow_inactive=True)['status'] == 'REVOKED'
        assert db.verify_all()['valid']


def test_dead_event_not_retried_automatically(tmp_path):
    scope = str(uuid.uuid4())
    with QuadraStore(str(tmp_path / 'dead.db'), secrets.token_bytes(32)) as db:
        db.put(scope, 'poison', {'x': 1})
        with db.transaction():
            db.db.execute("UPDATE q_outbox SET state='DEAD', attempts=?", (MAX_SYNC_ATTEMPTS,))
        assert _lease(db, scope, 100) == []
        assert db.status(scope)['dead_events'] == 1
        assert requeue_dead(db, scope) == 1
        assert len(_lease(db, scope, 100)) == 1

"""CT-07, CT-08, CT-10 and CT-11: tests without PostgreSQL required."""
import os
import secrets
import sqlite3
import uuid
from pathlib import Path

import pytest
from quantum_quadra.store import QuadraStore, IntegrityError, QuadraError
from quantum_quadra.sync import allow_remote_advance, SyncConflict


def test_ct08_backup_restore_sqlite_preserves_outbox_and_audit(tmp_path):
    key = secrets.token_bytes(32)
    scope = str(uuid.uuid4())
    primary = tmp_path / "primary.db"
    backup = tmp_path / "backup.db"
    with QuadraStore(str(primary), key) as store:
        cid = store.put(scope, "document", {"nested": {"evidence": "verified"}})
        store.transition(scope, cid, "REVOKED")
        with sqlite3.connect(str(backup)) as destination:
            store.db.backup(destination)
    with QuadraStore(str(backup), key) as restored:
        assert restored.verify_all()["valid"]
        assert restored.status(scope)["pending_events"] == 2
        assert restored.read(scope, cid, allow_inactive=True)["status"] == "REVOKED"
        assert restored.read(scope, cid, allow_inactive=True)["payload"]["nested"] == {"evidence": "verified"}
        with pytest.raises(QuadraError):
            restored.read(scope, cid)


def test_ct08_backup_during_aborted_write_does_not_include_partial_data(tmp_path, monkeypatch):
    key = secrets.token_bytes(32)
    scope = str(uuid.uuid4())
    with QuadraStore(str(tmp_path / "db.sqlite"), key) as store:
        store.put(scope, "ok", {"ok": True})
        original = store._audit
        def injected(*args, **kwargs):
            raise RuntimeError("failure before commit")
        monkeypatch.setattr(store, "_audit", injected)
        with pytest.raises(RuntimeError):
            store.put(scope, "should-rollback", {"ok": False})
        monkeypatch.setattr(store, "_audit", original)
        with sqlite3.connect(str(tmp_path / "snapshot.db")) as snapshot:
            store.db.backup(snapshot)
    with QuadraStore(str(tmp_path / "snapshot.db"), key) as restored:
        assert restored.verify_all()["valid"]
        assert restored.status(scope)["cells"] == 1
        assert restored.status(scope)["pending_events"] == 1


def test_ct10_wrong_key_rejected_without_modifying_restored_backup(tmp_path):
    scope = str(uuid.uuid4())
    key = secrets.token_bytes(32)
    path = tmp_path / "db.sqlite"
    with QuadraStore(str(path), key) as store:
        cell = store.put(scope, "sensitive", {"protected": True})
    with pytest.raises(IntegrityError):
        QuadraStore(str(path), secrets.token_bytes(32))
    with QuadraStore(str(path), key) as store:
        assert store.read(scope, cell)["payload"]["protected"] is True
        assert store.verify_all()["valid"]


def test_ct07_ciphertext_tamper_never_returns_corrupted_memory(tmp_path):
    scope = str(uuid.uuid4())
    with QuadraStore(str(tmp_path / "db.sqlite"), secrets.token_bytes(32)) as store:
        cid = store.put(scope, "test", {"secret": "private"})
        row = store.db.execute("SELECT encrypted_payload FROM q_cells WHERE cell_id=?", (cid,)).fetchone()
        blob = bytes(row[0]); modified = blob[:-1] + bytes([blob[-1] ^ 0x01])
        with store.transaction():
            store.db.execute("UPDATE q_cells SET encrypted_payload=? WHERE cell_id=?", (modified, cid))
        with pytest.raises(IntegrityError):
            store.read(scope, cid)


def test_ct11_tail_delete_detected_by_persisted_audit_anchor(tmp_path):
    key = secrets.token_bytes(32)
    path = tmp_path / "audit.sqlite"
    with QuadraStore(str(path), key) as store:
        scope = str(uuid.uuid4())
        store.put(scope, "one", {"n": 1})
        store.put(scope, "two", {"n": 2})
        with store.transaction():
            store.db.execute("DELETE FROM q_audit WHERE seq=(SELECT max(seq) FROM q_audit)")
        assert not store.verify_all()["valid"]
    with pytest.raises(IntegrityError):
        QuadraStore(str(path), key)


def test_ct06_conflict_invariants_are_explicit():
    import uuid
    cid, scope = str(uuid.uuid4()), str(uuid.uuid4())
    base = dict(cell_id=cid, scope_id=scope, status="ACTIVE",revision=1,
                payload_sha256="0"*64, memory_kind="EPISODIC", logical_key="k",creator_type="HUMAN")
    assert allow_remote_advance(dict(base),dict(base)) is False
    with pytest.raises(SyncConflict):
        allow_remote_advance({**base, "revision": 2}, base)
    with pytest.raises(SyncConflict):
        allow_remote_advance({**base, "status": "REVOKED", "revision": 2},
                             {**base, "revision": 3, "status": "ACTIVE"})

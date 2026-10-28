"""Real PostgreSQL integration tests: run with QUADRA_TEST_PG_DSN, isolated test DB only.

Do not point this suite at production. CI creates an ephemeral PostgreSQL service.
"""
import os
import secrets
import uuid
import pytest
from quantum_quadra.store import QuadraStore, QuadraError
from quantum_quadra.sync import init_core, push_outbox, pull_core


@pytest.fixture
def live(tmp_path):
    dsn=os.getenv('QUADRA_TEST_PG_DSN')
    if not dsn: pytest.skip('QUADRA_TEST_PG_DSN absent : PostgreSQL réel non testé ici')
    import psycopg2  # CI must FAIL, not skip, if the PostgreSQL dependency is missing
    pg=psycopg2.connect(dsn,connect_timeout=5)
    init_core(pg)
    scope=str(uuid.uuid4());master=secrets.token_bytes(32)
    with QuadraStore(str(tmp_path/'a.db'),master) as a, QuadraStore(str(tmp_path/'b.db'),master) as b:
        try: yield a,b,pg,scope
        finally:
            pg.rollback()
            with pg.cursor() as cur:
                cur.execute('DELETE FROM quadra_sync_receipts WHERE scope_id=%s',(scope,))
                cur.execute('DELETE FROM quadra_core_cells WHERE scope_id=%s',(scope,))
                cur.execute('DELETE FROM quadra_scope_keys WHERE scope_id=%s',(scope,))
            pg.commit()
            pg.close()


def test_live_postgres_two_devices_and_terminal_revocation(live):
    a,b,pg,scope=live
    cid=a.put(scope,'key',{'nested':{'proof':'valid'}})
    assert push_outbox(a,pg,scope)['pushed']==1
    assert pull_core(b,pg,scope)['pulled']==1
    assert b.read(scope,cid)['payload']['nested']['proof']=='valid'
    a.transition(scope,cid,'REVOKED')
    assert push_outbox(a,pg,scope)['failed']==0
    assert pull_core(b,pg,scope)['pulled']==1
    with pytest.raises(QuadraError): b.read(scope,cid)


def test_live_postgres_replay_after_remote_commit(live):
    a,b,pg,scope=live
    a.put(scope,'crash',{'number':42})
    def crash(_): raise ConnectionError('crash after postgres commit')
    assert push_outbox(a,pg,scope,after_core_commit=crash)['failed']==1
    a.db.execute("UPDATE q_outbox SET next_attempt_at='1970-01-01T00:00:00+00:00'")
    a.db.commit()
    assert push_outbox(a,pg,scope)['pushed']==1
    with pg.cursor() as cur:
        cur.execute('SELECT COUNT(*) FROM quadra_sync_receipts WHERE scope_id=%s',(scope,))
        assert cur.fetchone()[0]==1
    pg.commit()


def test_live_postgres_remote_tamper_does_not_pull(live):
    a,b,pg,scope=live
    cid=a.put(scope,'tamper',{'value':'secret'})
    push_outbox(a,pg,scope)
    with pg.cursor() as cur:
        cur.execute('SELECT encrypted_payload FROM quadra_core_cells WHERE cell_id=%s',(cid,))
        blob=bytes(cur.fetchone()[0]);bad=blob[:-1]+bytes([blob[-1]^1])
        cur.execute('UPDATE quadra_core_cells SET encrypted_payload=%s WHERE cell_id=%s',(bad,cid))
    pg.commit()
    with pytest.raises(Exception):pull_core(b,pg,scope)
    assert b.status(scope)['cells']==0


def test_live_postgres_connection_loss_before_commit_replays_safely(live):
    """Actually close an open PostgreSQL socket before commit; DB must roll back."""
    import psycopg2
    a, b, pg, scope = live
    cid = a.put(scope, 'network-cut', {'number': 81})
    separate = psycopg2.connect(os.environ['QUADRA_TEST_PG_DSN'], connect_timeout=5)

    class DropConnectionAtCommit:
        def cursor(self):
            return separate.cursor()
        def commit(self):
            separate.close()   # PostgreSQL aborts the uncommitted transaction
            raise ConnectionError('injected socket close before commit')
        def rollback(self):
            if not separate.closed:
                separate.rollback()

    failed = push_outbox(a, DropConnectionAtCommit(), scope)
    assert failed['failed'] == 1
    assert a.status(scope)['pending_events'] == 1
    with pg.cursor() as cur:
        cur.execute('SELECT COUNT(*) FROM quadra_core_cells WHERE cell_id=%s', (cid,))
        assert cur.fetchone()[0] == 0
    pg.commit()
    a.db.execute("UPDATE q_outbox SET next_attempt_at='1970-01-01T00:00:00+00:00'")
    a.db.commit()
    assert push_outbox(a, pg, scope)['pushed'] == 1
    assert pull_core(b, pg, scope)['pulled'] == 1
    assert b.read(scope, cid)['payload']['number'] == 81


def test_live_postgres_conflicting_terminal_states_never_overwrite(live):
    """One device archives while another revokes: conflict must be reported."""
    from quantum_quadra.sync import SyncConflict
    a, b, pg, scope = live
    cid = a.put(scope, 'status-conflict', {'x': 1})
    assert push_outbox(a, pg, scope)['pushed'] == 1
    assert pull_core(b, pg, scope)['pulled'] == 1
    a.transition(scope, cid, 'REVOKED')
    b.transition(scope, cid, 'ARCHIVED')
    assert push_outbox(a, pg, scope)['failed'] == 0
    attempt = push_outbox(b, pg, scope)
    assert attempt['failed'] == 1 and attempt['conflicts'] == 1
    with pg.cursor() as cur:
        cur.execute('SELECT status,revision FROM quadra_core_cells WHERE cell_id=%s', (cid,))
        assert cur.fetchone() == ('REVOKED', 2)
    pg.commit()
    assert b.read(scope, cid, allow_inactive=True)['status'] == 'ARCHIVED'

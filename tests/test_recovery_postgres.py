"""Live PostgreSQL recovery gates, never run on production."""
import os, secrets, uuid
from time import perf_counter
import pytest
from quantum_quadra.recovery import observe
from quantum_quadra.store import QuadraStore
from quantum_quadra.sync import init_core,push_outbox,pull_core


@pytest.fixture
def live(tmp_path):
    dsn=os.getenv('QUADRA_TEST_PG_DSN')
    if not dsn:
        if os.getenv('QUADRA_REQUIRE_LIVE_PG')=='1':pytest.fail('Live PostgreSQL is required')
        pytest.skip('PostgreSQL not configured')
    import psycopg2
    if psycopg2.extensions.parse_dsn(dsn).get('dbname')!='quadra_test':
        pytest.fail('Only quadra_test is authorized')
    pg=psycopg2.connect(dsn,connect_timeout=5)
    init_core(pg)
    scope=str(uuid.uuid4());key=secrets.token_bytes(32)
    try:yield pg,scope,key,tmp_path
    finally:
        pg.rollback()
        with pg.cursor() as cur:
            cur.execute('DELETE FROM quadra_sync_receipts WHERE scope_id=%s',(scope,))
            cur.execute('DELETE FROM quadra_core_cells WHERE scope_id=%s',(scope,))
            cur.execute('DELETE FROM quadra_scope_keys WHERE scope_id=%s',(scope,))
        pg.commit();pg.close()


def test_post_commit_failure_replay_rto_rpo(live):
    pg,scope,key,root=live
    with QuadraStore(str(root/'edge.db'),key) as src:
        cid=src.put(scope,'durable',{'x':1})
        def crash(_):raise ConnectionError('simulated post-commit failure')
        assert push_outbox(src,pg,scope,after_core_commit=crash)['failed']==1
        with src.transaction():
            src.db.execute("UPDATE q_outbox SET next_attempt_at='1970-01-01T00:00:00+00:00'")
        start=perf_counter()
        assert push_outbox(src,pg,scope)['pushed']==1
        with QuadraStore(str(root/'second.db'),key) as other:
            assert pull_core(other,pg,scope)['pulled']==1
            recovered=int(other.read(scope,cid)['payload']=={'x':1})
            assert other.verify_all()['valid']
        with pg.cursor() as cur:
            cur.execute('SELECT COUNT(*) FROM quadra_sync_receipts WHERE scope_id=%s',(scope,))
            assert cur.fetchone()[0]==1
        pg.commit()
    observe('postgres_post_commit',start,1,recovered,float(os.getenv('QUADRA_RTO_PG_SECONDS','20'))).require_pass()


def test_revocation_remains_terminal_during_rehydrate(live):
    pg,scope,key,root=live
    with QuadraStore(str(root/'edge.db'),key) as src:
        cid=src.put(scope,'terminal',{'x':1});src.transition(scope,cid,'REVOKED')
        assert push_outbox(src,pg,scope)['failed']==0
    start=perf_counter()
    with QuadraStore(str(root/'second.db'),key) as other:
        assert pull_core(other,pg,scope)['pulled']==1
        recovered=int(other.read(scope,cid,allow_inactive=True)['status']=='REVOKED')
    observe('postgres_revocation',start,1,recovered,float(os.getenv('QUADRA_RTO_PG_SECONDS','20'))).require_pass()

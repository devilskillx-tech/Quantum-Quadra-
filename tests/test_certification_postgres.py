"""CT-03/CT-04: true PostgreSQL and optional Toxiproxy fault injection.

Failures must be reproduced against disposable test infrastructure only.
QUADRA_REQUIRE_LIVE_PG=1 prevents silent skips in release CI.
"""
from concurrent.futures import ThreadPoolExecutor
import os
import secrets
import uuid
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import json

import pytest
from quantum_quadra.store import QuadraStore
from quantum_quadra.sync import init_core, push_outbox, pull_core


def _connect(dsn):
    import psycopg2
    return psycopg2.connect(dsn, connect_timeout=5)


@pytest.fixture
def live_cluster(tmp_path):
    dsn = os.getenv('QUADRA_TEST_PG_DSN')
    if not dsn:
        if os.getenv('QUADRA_REQUIRE_LIVE_PG') == '1':
            pytest.fail('QUADRA_TEST_PG_DSN is mandatory for this job')
        pytest.skip('Disposable PostgreSQL is not available')
    pg = _connect(dsn)
    init_core(pg)
    scope = str(uuid.uuid4())
    master = secrets.token_bytes(32)
    try:
        yield {'dsn': dsn, 'pg': pg, 'scope': scope, 'master': master, 'path': str(tmp_path/'edge.db')}
    finally:
        pg.rollback()
        with pg.cursor() as cur:
            cur.execute('DELETE FROM quadra_sync_receipts WHERE scope_id=%s', (scope,))
            cur.execute('DELETE FROM quadra_core_cells WHERE scope_id=%s', (scope,))
            cur.execute('DELETE FROM quadra_scope_keys WHERE scope_id=%s', (scope,))
        pg.commit()
        pg.close()


def test_ct04_two_real_workers_single_receipt(live_cluster):
    cfg = live_cluster
    scope, key, path = cfg['scope'], cfg['master'], cfg['path']
    with QuadraStore(path, key) as store:
        cid = store.put(scope, 'parallel', {'number': 1})
        event_id = store.db.execute('SELECT event_id FROM q_outbox').fetchone()[0]

    def worker(_):
        with QuadraStore(path, key) as store:
            with _connect(cfg['dsn']) as pg:
                return push_outbox(store, pg, scope)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(worker, range(2)))
    assert sum(r['pushed'] for r in results) == 1, results
    assert sum(r['failed'] for r in results) == 0, results
    with QuadraStore(path, key) as store:
        assert store.status(scope)['pending_events'] == 0
        assert store.verify_all()['valid']
    with cfg['pg'].cursor() as cur:
        cur.execute('SELECT COUNT(*) FROM quadra_sync_receipts WHERE event_id=%s', (event_id,))
        assert cur.fetchone()[0] == 1
        cur.execute('SELECT COUNT(*) FROM quadra_core_cells WHERE cell_id=%s', (cid,))
        assert cur.fetchone()[0] == 1
    cfg['pg'].commit()


def _api(method, path, body=None):
    endpoint = os.environ['QUADRA_TOXIPROXY_API'].rstrip('/') + path
    data = json.dumps(body).encode('utf-8') if body is not None else None
    req = Request(endpoint, data=data, method=method,
                  headers={'Content-Type': 'application/json'})
    with urlopen(req, timeout=7) as resp:
        return json.loads(resp.read() or b'{}')


def test_ct03_live_proxy_partition_then_recovery(live_cluster):
    """Real socket partition at connection boundary, followed by recovery.

    This checks connectivity loss and durable outbox, NOT arbitrary packet drop
    or a partition at every point inside a PostgreSQL transaction.
    """
    if not os.getenv('QUADRA_TOXIPROXY_API'):
        if os.getenv('QUADRA_REQUIRE_TOXIPROXY') == '1':
            pytest.fail('QUADRA_TOXIPROXY_API is mandatory for fault-injection job')
        pytest.skip('Toxiproxy not available')
    import psycopg2
    cfg = live_cluster
    proxy_name = 'quadra-' + uuid.uuid4().hex[:12]
    listen_port = 8666
    # CI uses one fault job per runner, so the listening port is dedicated.
    _api('POST', '/proxies', {'name': proxy_name,
                              'listen': f'0.0.0.0:{listen_port}',
                              'upstream': 'postgres:5432'})
    try:
        proxy_dsn = f'host=127.0.0.1 port={listen_port} dbname=quadra_test user=quadra_test password=quadra_test_password connect_timeout=2'
        with QuadraStore(cfg['path'], cfg['master']) as store:
            cid = store.put(cfg['scope'], 'during-outage', {'n': 3})
            _api('POST', f'/proxies/{proxy_name}', {'enabled': False})
            with pytest.raises(psycopg2.OperationalError):
                _connect(proxy_dsn)
            assert store.status(cfg['scope'])['pending_events'] == 1
            assert store.read(cfg['scope'], cid)['payload']['n'] == 3
            _api('POST', f'/proxies/{proxy_name}', {'enabled': True})
            with _connect(proxy_dsn) as pg:
                result = push_outbox(store, pg, cfg['scope'])
            assert result['pushed'] == 1, result
            assert store.status(cfg['scope'])['pending_events'] == 0
        with cfg['pg'].cursor() as cur:
            cur.execute('SELECT count(*) FROM quadra_core_cells WHERE cell_id=%s', (cid,))
            assert cur.fetchone()[0] == 1
        cfg['pg'].commit()
    finally:
        _api('DELETE', f'/proxies/{proxy_name}')

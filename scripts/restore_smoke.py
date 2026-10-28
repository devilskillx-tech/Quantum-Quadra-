"""Smoke test of complete SQLite backup and PostgreSQL dump/restore.

Steps:
  python scripts/restore_smoke.py prepare --workdir /tmp/quadra-restore
  # The CI workflow runs pg_dump and pg_restore between these steps.
  python scripts/restore_smoke.py verify --workdir /tmp/quadra-restore

Never use with production or non-disposable PostgreSQL credentials.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import sqlite3
import uuid

from quantum_quadra.store import QuadraStore
from quantum_quadra.sync import init_core, push_outbox, pull_core


def connection(variable):
    import psycopg2
    dsn = os.environ[variable]
    # Hard-fail rather than dumping/restoring any unintended database.
    expected = 'quadra_restore' if variable == 'QUADRA_RESTORE_TEST_DSN' else 'quadra_test'
    if psycopg2.extensions.parse_dsn(dsn).get('dbname') != expected:
        raise RuntimeError(f'Only disposable {expected} database is allowed')
    return psycopg2.connect(dsn, connect_timeout=5)


def prepare(workdir):
    key = secrets.token_bytes(32)
    scope = str(uuid.uuid4())
    with connection('QUADRA_TEST_PG_DSN') as pg:
        init_core(pg)
        with QuadraStore(str(workdir / 'original.db'), key) as store:
            cell = store.put(scope, 'restore-canary', {'nested': {'verified': True}})
            # Capture backup *before* acknowledgment so replay is necessary.
            with sqlite3.connect(str(workdir / 'snapshot.db')) as snap:
                store.db.backup(snap)
            result = push_outbox(store, pg, scope)
            assert result['pushed'] == 1, result
            assert store.status(scope)['pending_events'] == 0
    state = {'key': base64.b64encode(key).decode('ascii'), 'scope': scope, 'cell': cell}
    target = workdir / 'state.json'
    target.write_text(json.dumps(state), encoding='utf-8')
    target.chmod(0o600)
    print('PREPARE_OK: encrypted Core and SQLite snapshot with pending outbox')


def verify(workdir):
    state = json.loads((workdir / 'state.json').read_text(encoding='utf-8'))
    key = base64.b64decode(state['key'])
    scope, cell = state['scope'], state['cell']
    with connection('QUADRA_RESTORE_TEST_DSN') as pg:
        with pg.cursor() as cur:
            cur.execute('SELECT count(*) FROM quadra_sync_receipts WHERE cell_id=%s', (cell,))
            assert cur.fetchone()[0] == 1
        pg.commit()
        with QuadraStore(str(workdir / 'snapshot.db'), key) as old:
            assert old.verify_all()['valid']
            assert old.status(scope)['pending_events'] == 1
            assert old.read(scope, cell)['payload']['nested']['verified'] is True
            result = push_outbox(old, pg, scope)
            assert result['pushed'] == 1, result
            assert old.status(scope)['pending_events'] == 0
            assert old.verify_all()['valid']
        with pg.cursor() as cur:
            cur.execute('SELECT count(*) FROM quadra_sync_receipts WHERE cell_id=%s', (cell,))
            assert cur.fetchone()[0] == 1
        pg.commit()
        with QuadraStore(str(workdir / 'second-edge.db'), key) as other:
            result = pull_core(other, pg, scope)
            assert result['pulled'] == 1, result
            assert other.read(scope, cell)['payload']['nested']['verified'] is True
            assert other.verify_all()['valid']
    print('RESTORE_OK: PostgreSQL dump/restore, SQLite backup, replay and remote rehydration')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('prepare', 'verify'))
    parser.add_argument('--workdir', required=True)
    args = parser.parse_args()
    workdir = Path(args.workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    (prepare if args.action == 'prepare' else verify)(workdir)


if __name__ == '__main__':
    main()

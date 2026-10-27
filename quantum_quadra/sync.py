"""Postgres encrypted replication: at-least-once delivery with server receipts.

Not validated against a live Postgres server in this reconstruction.
Only use with TLS-authenticated PostgreSQL credentials and a trusted device.
"""
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from .crypto import unwrap_dek
from .store import IntegrityError, QuadraError, QuadraStore

CORE_SCHEMA = (Path(__file__).resolve().parent / 'postgres.sql')

class SyncConflict(QuadraError):
    pass


def init_core(pg_connection, sql_file: str | None = None):
    source = Path(sql_file) if sql_file else CORE_SCHEMA
    sql = source.read_text(encoding='utf-8')
    try:
        with pg_connection.cursor() as cur:
            cur.execute(sql)
        pg_connection.commit()
    except Exception:
        pg_connection.rollback()
        raise


def bootstrap_scope_keys(store: QuadraStore, pg_connection, scope_id: str):
    """Copy wrapped keys into Edge. Requires the SAME authorized master key."""
    with pg_connection.cursor() as cur:
        cur.execute('SELECT version,wrapped_dek FROM quadra_scope_keys WHERE scope_id=%s ORDER BY version', (scope_id,))
        rows=cur.fetchall()
    if not rows:
        return 0
    with store.transaction():
        for version,wrapped in rows:
            # Reject keys which cannot be authenticated with this device's KEK.
            unwrap_dek(store.kek,scope_id,int(version),bytes(wrapped))
            existing=store.db.execute('SELECT wrapped FROM q_keys WHERE scope_id=? AND version=?',
                                      (scope_id,int(version))).fetchone()
            if existing is not None and bytes(existing[0])!=bytes(wrapped):
                # Equivalent cryptographic keys can be wrapped with different nonces.
                old=unwrap_dek(store.kek,scope_id,int(version),bytes(existing[0]))
                new=unwrap_dek(store.kek,scope_id,int(version),bytes(wrapped))
                if old!=new: raise SyncConflict('Scope DEK incompatible')
            if existing is None:
                store.db.execute('INSERT INTO q_keys(scope_id,version,wrapped,is_active) VALUES(?,?,?,0)',
                                 (scope_id,int(version),bytes(wrapped)))
        # Only new scopes may adopt remote active key; never deactivate a locally active key
        active=store.db.execute('SELECT 1 FROM q_keys WHERE scope_id=? AND is_active=1',(scope_id,)).fetchone()
        if active is None:
            store.db.execute('UPDATE q_keys SET is_active=1 WHERE scope_id=? AND version=?',
                             (scope_id,max(int(v) for v,_ in rows)))
    return len(rows)


def _lease(store: QuadraStore,scope_id: str,limit: int):
    now=store.now()
    until=(datetime.now(timezone.utc)+timedelta(seconds=90)).isoformat()
    with store.transaction():
        store.db.execute("UPDATE q_outbox SET state='PENDING',locked_until=NULL WHERE state='LEASED' AND locked_until<?",(now,))
        rows=store.db.execute("SELECT o.* FROM q_outbox o JOIN q_cells c ON c.cell_id=o.cell_id "
                              "WHERE c.scope_id=? AND o.state='PENDING' AND o.next_attempt_at<=? "
                              "ORDER BY o.created_at,o.event_id LIMIT ?",(scope_id,now,limit)).fetchall()
        for row in rows:
            store.db.execute("UPDATE q_outbox SET state='LEASED',locked_until=? WHERE event_id=? AND state='PENDING'",
                             (until,row['event_id']))
    return [dict(row) for row in rows]


def push_outbox(store: QuadraStore,pg_connection,scope_id: str,limit: int=50,after_core_commit=None):
    """A remote receipt and updated ciphertext commit atomically.
    A failure after remote commit is retried and deduplicated by event_id.
    """
    if not 1<=limit<=1000: raise ValueError('limit invalide')
    stats={'pushed':0,'failed':0,'conflicts':0}
    for event in _lease(store,scope_id,limit):
        cid=event['cell_id'];eid=event['event_id']
        try:
            row=store.db.execute('SELECT * FROM q_cells WHERE cell_id=? AND scope_id=?',(cid,scope_id)).fetchone()
            if row is None: raise KeyError('Cellule locale introuvable')
            # Detect state tampering before transfer.
            store._decode(row)
            r=dict(row)
            wrap=store.db.execute('SELECT wrapped FROM q_keys WHERE scope_id=? AND version=?',
                                  (scope_id,r['key_version'])).fetchone()
            if wrap is None: raise IntegrityError('Clé chiffrée manquante')
            with pg_connection.cursor() as cur:
                cur.execute('SELECT 1 FROM quadra_sync_receipts WHERE event_id=%s',(eid,))
                seen=cur.fetchone()
                if not seen:
                    cur.execute('SELECT revision,status,encrypted_payload FROM quadra_core_cells WHERE cell_id=%s FOR UPDATE',(cid,))
                    old=cur.fetchone()
                    # An event always carries latest local snapshot (historical events are receipts only).
                    if old and (int(old[0])>r['revision'] or (int(old[0])==r['revision'] and bytes(old[2])!=r['encrypted_payload'])):
                        raise SyncConflict('Révision concurrente ou régression')
                    cur.execute('SELECT wrapped_dek FROM quadra_scope_keys WHERE scope_id=%s AND version=%s',
                                (scope_id,r['key_version']))
                    old_wrap=cur.fetchone()
                    if old_wrap is not None:
                        server_dek=unwrap_dek(store.kek,scope_id,r['key_version'],bytes(old_wrap[0]))
                        local_dek=unwrap_dek(store.kek,scope_id,r['key_version'],bytes(wrap[0]))
                        if server_dek!=local_dek:
                            raise SyncConflict('Clés de scope divergentes')
                    else:
                        cur.execute('INSERT INTO quadra_scope_keys(scope_id,version,wrapped_dek) VALUES(%s,%s,%s)',
                                    (scope_id,r['key_version'],bytes(wrap[0])))
                    cur.execute('''INSERT INTO quadra_core_cells
                    (cell_id,scope_id,memory_kind,logical_key,creator_type,status,key_version,
                     revision,payload_sha256,encrypted_payload,importance,created_at)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (cell_id) DO UPDATE SET
                        status=EXCLUDED.status,key_version=EXCLUDED.key_version,
                        revision=EXCLUDED.revision,payload_sha256=EXCLUDED.payload_sha256,
                        encrypted_payload=EXCLUDED.encrypted_payload,importance=EXCLUDED.importance,
                        updated_at=now()''',
                        (cid,scope_id,r['memory_kind'],r['logical_key'],r['creator_type'],r['status'],
                         r['key_version'],r['revision'],r['payload_sha256'],r['encrypted_payload'],
                         r['importance'],r['created_at']))
                    cur.execute('INSERT INTO quadra_sync_receipts(event_id,cell_id,scope_id,revision) VALUES(%s,%s,%s,%s)',
                                (eid,cid,scope_id,r['revision']))
            pg_connection.commit()
            if after_core_commit: after_core_commit(eid)
            with store.transaction():
                store.db.execute("UPDATE q_outbox SET state='ACK',locked_until=NULL,error=NULL WHERE event_id=? AND state='LEASED'",(eid,))
            stats['pushed']+=1
        except Exception as exc:
            pg_connection.rollback()
            stats['failed']+=1
            if isinstance(exc,SyncConflict): stats['conflicts']+=1
            with store.transaction():
                attempt=int(event['attempts'])+1
                delay=min(3600,2**min(attempt,10))
                retry_at=(datetime.now(timezone.utc)+timedelta(seconds=delay)).isoformat()
                store.db.execute("UPDATE q_outbox SET state='PENDING', attempts=?,next_attempt_at=?,"
                                 "locked_until=NULL,error=? WHERE event_id=?",
                                 (attempt,retry_at,str(exc)[:160],eid))
    return stats


def pull_core(store: QuadraStore,pg_connection,scope_id: str,limit: int=100):
    """Fail-closed pull. Never overwrite unsynchronized local changes."""
    if not 1<=limit<=1000: raise ValueError('limit invalide')
    bootstrap_scope_keys(store,pg_connection,scope_id)
    with pg_connection.cursor() as cur:
        cur.execute('''SELECT cell_id,scope_id,memory_kind,logical_key,creator_type,status,
        key_version,revision,payload_sha256,encrypted_payload,importance,created_at
        FROM quadra_core_cells WHERE scope_id=%s ORDER BY updated_at DESC LIMIT %s''',(scope_id,limit))
        rows=cur.fetchall()
    total=0;skipped=0
    columns=('cell_id','scope_id','memory_kind','logical_key','creator_type','status','key_version',
             'revision','payload_sha256','encrypted_payload','importance','created_at')
    for values in rows:
        record=dict(zip(columns,values))
        record['cell_id']=str(record['cell_id']);record['scope_id']=str(record['scope_id'])
        record['encrypted_payload']=bytes(record['encrypted_payload'])
        record['created_at']=str(record['created_at'])
        # Authentication against AAD before any local overwrite.
        from .crypto import decrypt,aad_for,digest,unwrap_dek
        keyrow=store.db.execute('SELECT wrapped FROM q_keys WHERE scope_id=? AND version=?',
            (scope_id,record['key_version'])).fetchone()
        if keyrow is None: raise IntegrityError('Clé distante absente')
        dek=unwrap_dek(store.kek,scope_id,record['key_version'],keyrow[0])
        data=decrypt(dek,record['encrypted_payload'],aad_for(record))
        if digest(data)!=record['payload_sha256']: raise IntegrityError('Hash distant invalide')
        with store.transaction():
            pending=store.db.execute("SELECT 1 FROM q_outbox WHERE cell_id=? AND state!='ACK' LIMIT 1",
                                     (record['cell_id'],)).fetchone()
            local=store.db.execute('SELECT * FROM q_cells WHERE cell_id=?',(record['cell_id'],)).fetchone()
            if pending or (local and local['revision']>=record['revision']):
                skipped+=1;continue
            if local and local['scope_id']!=scope_id: raise SyncConflict('Collision inter-scope')
            if local:
                store._decode(local)
                store.db.execute('''UPDATE q_cells SET status=?,key_version=?,revision=?,payload_sha256=?,
                encrypted_payload=?,importance=? WHERE cell_id=?''',
                (record['status'],record['key_version'],record['revision'],record['payload_sha256'],
                 record['encrypted_payload'],record['importance'],record['cell_id']))
            else:
                store.db.execute('''INSERT INTO q_cells(cell_id,scope_id,memory_kind,logical_key,creator_type,
                status,key_version,revision,payload_sha256,encrypted_payload,importance,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',tuple(record[c] for c in columns))
            store._audit('CORE_PULL',record['cell_id'])
            total+=1
    return {'pulled':total,'skipped':skipped}

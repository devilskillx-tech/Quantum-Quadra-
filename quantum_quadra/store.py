"""Encrypted local-first SQLite memory store with fail-closed state authentication."""
import hashlib
import math
from functools import wraps
import hmac
import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from .crypto import (canonical, digest, aad_for, encrypt, decrypt, wrap_dek,
                     unwrap_dek, master_key_from_env)
from .search import flatten, rank

VALID_KINDS = {"SEMANTIC", "EPISODIC", "PROCEDURAL", "EVIDENCE", "ARTIFACT"}
VALID_STATUSES = {"ACTIVE", "SUPERSEDED", "REVOKED", "ARCHIVED"}

class QuadraError(Exception):
    pass

class IntegrityError(QuadraError):
    pass

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS q_meta(name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS q_keys(
  scope_id TEXT NOT NULL, version INTEGER NOT NULL CHECK(version>0),
  wrapped BLOB NOT NULL, is_active INTEGER NOT NULL CHECK(is_active IN (0,1)),
  PRIMARY KEY(scope_id,version)
);
CREATE TABLE IF NOT EXISTS q_cells(
  cell_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, memory_kind TEXT NOT NULL,
  logical_key TEXT NOT NULL, creator_type TEXT NOT NULL, status TEXT NOT NULL,
  key_version INTEGER NOT NULL, revision INTEGER NOT NULL CHECK(revision>0),
  payload_sha256 TEXT NOT NULL, encrypted_payload BLOB NOT NULL,
  importance REAL NOT NULL, created_at TEXT NOT NULL,
  last_retrieved_at TEXT, retrieval_count INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(scope_id,key_version) REFERENCES q_keys(scope_id,version)
);
CREATE INDEX IF NOT EXISTS idx_cells_scope_status ON q_cells(scope_id,status);
CREATE TABLE IF NOT EXISTS q_outbox(
  event_id TEXT PRIMARY KEY, cell_id TEXT NOT NULL, op TEXT NOT NULL,
  revision INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'PENDING',
  attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT,
  next_attempt_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00+00:00',
  error TEXT, created_at TEXT NOT NULL,
  FOREIGN KEY(cell_id) REFERENCES q_cells(cell_id)
);
CREATE INDEX IF NOT EXISTS idx_outbox_state ON q_outbox(state,next_attempt_at);
CREATE TABLE IF NOT EXISTS q_audit(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, cell_id TEXT, action TEXT NOT NULL,
  ts TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
"""

def synchronized(method):
    """Serialize access to the shared SQLite connection, including readers."""
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapped


class QuadraStore:
    def __init__(self, path: str, master_key: bytes | None = None, *, allow_legacy_audit_migration=False):
        self.path = str(path)
        self.allow_legacy_audit_migration=allow_legacy_audit_migration
        self.kek = master_key if master_key is not None else master_key_from_env()
        if len(self.kek) != 32:
            raise ValueError("Clé maître de 32 octets requise")
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.db = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)
        self._verify_master()

    @synchronized
    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @staticmethod
    def now():
        return datetime.now(timezone.utc).isoformat()

    @contextmanager
    def transaction(self):
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    def _verify_master(self):
        marker = hmac.new(self.kek, b"QUADRA-v73-reconstructed-master-verification", hashlib.sha256).hexdigest()
        with self.transaction():
            row = self.db.execute("SELECT value FROM q_meta WHERE name='key_marker'").fetchone()
            if row and not hmac.compare_digest(row[0], marker):
                raise IntegrityError("Mauvaise clé maître pour cette base")
            if row is None:
                existing_data=any(self.db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                                  for table in ('q_cells','q_keys','q_audit'))
                if existing_data:
                    raise IntegrityError('Marqueur de clé absent sur une base déjà utilisée')
                self.db.execute("INSERT INTO q_meta(name,value) VALUES('key_marker',?)", (marker,))
            # Legacy upgrades are explicit: silently recreating a missing audit
            # anchor would allow bypass after deleting both the tail and anchor.
            anchor = self.db.execute("SELECT value FROM q_meta WHERE name='audit_anchor_v1'").fetchone()
            if anchor is None:
                if row is not None and not self.allow_legacy_audit_migration:
                    raise IntegrityError('Ancre d’audit manquante : migration explicite nécessaire')
                count = self.db.execute("SELECT COUNT(*) FROM q_audit").fetchone()[0]
                tail = self.db.execute("SELECT hash FROM q_audit ORDER BY seq DESC LIMIT 1").fetchone()
                if not count and self.db.execute("SELECT COUNT(*) FROM q_cells").fetchone()[0]:
                    raise IntegrityError("Journal d'audit absent : migration refusée")
                if count and not self._verify_audit_chain_only()['valid']:
                    raise IntegrityError("Journal d'audit invalide : migration refusée")
                self._set_audit_anchor(count, tail[0] if tail else '0'*64)
        if not self.verify_audit()['valid']:
            raise IntegrityError('Journal d’audit invalide à l’ouverture')

    def _key(self, scope_id: str, version: int | None = None):
        if version is None:
            row = self.db.execute(
                "SELECT version,wrapped FROM q_keys WHERE scope_id=? AND is_active=1 ORDER BY version DESC LIMIT 1",
                (scope_id,)).fetchone()
        else:
            row = self.db.execute("SELECT version,wrapped FROM q_keys WHERE scope_id=? AND version=?",
                                  (scope_id,version)).fetchone()
        if row:
            return unwrap_dek(self.kek,scope_id,row['version'],row['wrapped']), row['version']
        if version is not None:
            raise IntegrityError("Version de clé manquante")
        dek = os.urandom(32)
        self.db.execute("INSERT INTO q_keys(scope_id,version,wrapped,is_active) VALUES(?,1,?,1)",
                        (scope_id,wrap_dek(self.kek,scope_id,1,dek)))
        return dek, 1

    def _set_audit_anchor(self, count: int, tail: str):
        data = {"count": count, "tail": tail}
        signature = hmac.new(self.kek, b"QUADRA-AUDIT-ANCHOR-v1\x00" + canonical(data),
                             hashlib.sha256).hexdigest()
        self.db.execute("INSERT INTO q_meta(name,value) VALUES('audit_anchor_v1',?) "
                        "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                        (canonical({**data, "mac": signature}).decode('utf-8'),))

    def _audit(self, action: str, cell_id: str | None):
        row = self.db.execute("SELECT hash FROM q_audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row['hash'] if row else "0" * 64
        ts = self.now()
        record = canonical([prev,cell_id,action,ts])
        entry_hash = hmac.new(self.kek,record,hashlib.sha256).hexdigest()
        self.db.execute("INSERT INTO q_audit(cell_id,action,ts,prev_hash,hash) VALUES(?,?,?,?,?)",
                        (cell_id,action,ts,prev,entry_hash))
        count = self.db.execute("SELECT COUNT(*) FROM q_audit").fetchone()[0]
        self._set_audit_anchor(count, entry_hash)

    @staticmethod
    def _row_dict(row):
        return dict(row)

    def _decode(self, row):
        r = dict(row)
        try:
            dek,_ = self._key(r['scope_id'],r['key_version'])
            data = decrypt(dek,r['encrypted_payload'],aad_for(r))
            if digest(data) != r['payload_sha256']:
                raise IntegrityError("Payload hash invalide")
            return json.loads(data)
        except (ValueError,KeyError,json.JSONDecodeError) as exc:
            raise IntegrityError("Enveloppe invalide") from exc
        except Exception as exc:
            from cryptography.exceptions import InvalidTag
            if isinstance(exc,InvalidTag):
                raise IntegrityError("Authentification AES-GCM invalide") from exc
            raise

    def put(self,scope_id: str,logical_key: str,payload: dict,
            memory_kind="EPISODIC",creator_type="HUMAN",importance=0.5):
        if memory_kind not in VALID_KINDS or not logical_key or not isinstance(payload,dict):
            raise ValueError("Paramètres de cellule invalides")
        uuid.UUID(str(scope_id))
        if not math.isfinite(float(importance)) or not 0.0 <= float(importance) <= 1.0:
            raise ValueError("importance doit être un nombre fini entre 0 et 1")
        data = canonical(payload)
        cid = str(uuid.uuid4())
        row = dict(cell_id=cid,scope_id=str(scope_id),memory_kind=memory_kind,
                   logical_key=logical_key,creator_type=creator_type,status="ACTIVE",
                   key_version=0,revision=1,payload_sha256=digest(data))
        with self.transaction():
            dek,ver=self._key(row['scope_id']);row['key_version']=ver
            blob=encrypt(dek,data,aad_for(row))
            self.db.execute("INSERT INTO q_cells(cell_id,scope_id,memory_kind,logical_key,creator_type,status,"
                "key_version,revision,payload_sha256,encrypted_payload,importance,created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (cid,row['scope_id'],memory_kind,logical_key,creator_type,'ACTIVE',ver,1,
                 row['payload_sha256'],blob,max(0,min(1,float(importance))),self.now()))
            self._event(cid,"UPSERT",1)
            self._audit("UPSERT",cid)
        return cid

    def _event(self,cid,op,rev):
        self.db.execute("INSERT INTO q_outbox(event_id,cell_id,op,revision,created_at)"
                        " VALUES(?,?,?,?,?)",(str(uuid.uuid4()),cid,op,rev,self.now()))

    @synchronized
    def read(self,scope_id,cell_id,allow_inactive=False):
        row=self.db.execute("SELECT * FROM q_cells WHERE scope_id=? AND cell_id=?",(str(scope_id),cell_id)).fetchone()
        if row is None:
            raise KeyError("Cellule inexistante dans ce scope")
        payload=self._decode(row)  # detect invalid status before checking ACTIVE
        if row['status']!='ACTIVE' and not allow_inactive:
            raise QuadraError("Cellule non active")
        return {**{k:row[k] for k in ("cell_id","scope_id","memory_kind","logical_key","status","revision","importance")},"payload":payload}

    def transition(self,scope_id,cell_id,new_status):
        if new_status not in VALID_STATUSES-{"ACTIVE"}:
            raise ValueError("Transition refusée")
        with self.transaction():
            row=self.db.execute("SELECT * FROM q_cells WHERE scope_id=? AND cell_id=?",
                                (str(scope_id),cell_id)).fetchone()
            if row is None:
                raise KeyError(cell_id)
            if row['status']!='ACTIVE':
                raise QuadraError("État terminal : pas de réactivation implicite")
            payload=self._decode(row)
            r=dict(row);r['status']=new_status;r['revision']+=1
            dek,_=self._key(str(scope_id),r['key_version'])
            blob=encrypt(dek,canonical(payload),aad_for(r))
            self.db.execute("UPDATE q_cells SET status=?,revision=?,encrypted_payload=? WHERE cell_id=?",
                            (new_status,r['revision'],blob,cell_id))
            self._event(cell_id,new_status,r['revision'])
            self._audit(new_status,cell_id)
        return r['revision']

    @synchronized
    def search(self,scope_id,query,limit=5,mode="bm25",semantic=None):
        if not 1 <= limit <= 100:
            raise ValueError("limit hors de [1,100]")
        rows=self.db.execute("SELECT * FROM q_cells WHERE scope_id=? AND status='ACTIVE'",
                             (str(scope_id),)).fetchall()
        docs=[self._decode(row) for row in rows]
        texts=[row['logical_key']+' '+flatten(doc) for row,doc in zip(rows,docs)]
        scores=rank(query,texts,mode,semantic)
        ranked=sorted(((score,i) for i,score in enumerate(scores) if score>0),reverse=True)[:limit]
        return [dict(cell_id=rows[i]['cell_id'],logical_key=rows[i]['logical_key'],
                     memory_kind=rows[i]['memory_kind'],score=round(score,5),payload=docs[i])
                for score,i in ranked]

    @synchronized
    def consolidate_extractively(self,scope_id,logical_key,min_episodes=3):
        if min_episodes<2: raise ValueError("min_episodes doit être >= 2")
        rows=self.db.execute("SELECT * FROM q_cells WHERE scope_id=? AND logical_key=? "
            "AND memory_kind='EPISODIC' AND status='ACTIVE' ORDER BY created_at,cell_id",
            (str(scope_id),logical_key)).fetchall()
        if len(rows)<min_episodes:return None
        items=[dict(cell_id=row['cell_id'],payload=self._decode(row)) for row in rows]
        payload={"method":"extractive-not-generative","sources":items,"source_count":len(items)}
        return self.put(scope_id,logical_key+':consolidation',payload,memory_kind='SEMANTIC',
                        creator_type='QUADRA')

    def rotate_dek(self,scope_id):
        """Atomic re-encryption: old versions retained for reference/recovery."""
        with self.transaction():
            old_key,old_ver=self._key(str(scope_id))
            new_ver=old_ver+1;new_key=os.urandom(32)
            rows=self.db.execute("SELECT * FROM q_cells WHERE scope_id=?",(str(scope_id),)).fetchall()
            decoded=[(row,self._decode(row)) for row in rows]
            self.db.execute("UPDATE q_keys SET is_active=0 WHERE scope_id=?",(str(scope_id),))
            self.db.execute("INSERT INTO q_keys(scope_id,version,wrapped,is_active) VALUES(?,?,?,1)",
                            (str(scope_id),new_ver,wrap_dek(self.kek,str(scope_id),new_ver,new_key)))
            for row, payload in decoded:
                r=dict(row);r['key_version']=new_ver
                encrypted=encrypt(new_key,canonical(payload),aad_for(r))
                self.db.execute("UPDATE q_cells SET key_version=?,encrypted_payload=? WHERE cell_id=?",
                                (new_ver,encrypted,row['cell_id']))
                # Events store refs, so sync snapshots must be generated at sending time.
            self._audit('ROTATE_DEK',None)
        return new_ver

    @synchronized
    def verify_all(self,scope_id=None):
        clause="WHERE scope_id=?" if scope_id else ""
        rows=self.db.execute(f"SELECT * FROM q_cells {clause}", (str(scope_id),) if scope_id else ()).fetchall()
        errors=[]
        for row in rows:
            try:self._decode(row)
            except Exception as exc:errors.append(dict(cell_id=row['cell_id'],error=str(exc)))
        audit=self.verify_audit()
        # Global audit log cannot be selectively verified; avoid leaking the
        # activity count of other scopes through a scope-restricted endpoint.
        if scope_id is not None:
            audit={"valid":audit['valid']}
        return {"valid":not errors and audit['valid'],"checked":len(rows),"errors":errors,"audit":audit}

    def _verify_audit_chain_only(self):
        previous = '0'*64
        count = 0
        last_seq = 0
        for row in self.db.execute('SELECT * FROM q_audit ORDER BY seq'):
            if int(row['seq']) != last_seq + 1:
                return {"valid": False, "checked": count, "reason": "audit_sequence_gap"}
            expected = hmac.new(self.kek,
                                canonical([previous,row['cell_id'],row['action'],row['ts']]),
                                hashlib.sha256).hexdigest()
            if row['prev_hash'] != previous or not hmac.compare_digest(expected,row['hash']):
                return {"valid": False, "checked": count, "broken_seq": row['seq']}
            previous = row['hash']
            count += 1
            last_seq = row['seq']
        return {"valid": True, "checked": count, "tail": previous}

    @synchronized
    def verify_audit(self):
        report = self._verify_audit_chain_only()
        if not report['valid']:
            return report
        anchor = self.db.execute("SELECT value FROM q_meta WHERE name='audit_anchor_v1'").fetchone()
        if anchor is None:
            return {"valid": False, "checked": report['checked'], "reason": "missing_audit_anchor"}
        try:
            value = json.loads(anchor[0]); data = {"count": value['count'], "tail": value['tail']}
            mac = hmac.new(self.kek,b"QUADRA-AUDIT-ANCHOR-v1\x00" + canonical(data),
                           hashlib.sha256).hexdigest()
            if not hmac.compare_digest(value['mac'], mac):
                raise ValueError("bad mac")
        except (ValueError,KeyError,TypeError):
            return {"valid": False, "checked": report['checked'], "reason": "invalid_audit_anchor"}
        if data['count'] != report['checked'] or data['tail'] != report['tail']:
            return {"valid": False, "checked": report['checked'], "reason": "audit_head_mismatch"}
        if self.db.execute('SELECT count(*) FROM q_cells').fetchone()[0] and not report['checked']:
            return {"valid": False, "checked": 0, "reason": "missing_audit"}
        return {"valid": True, "checked": report['checked']}

    @synchronized
    def status(self,scope_id=None):
        if scope_id:
            cells=self.db.execute("SELECT count(*) FROM q_cells WHERE scope_id=?",(str(scope_id),)).fetchone()[0]
            pending=self.db.execute("SELECT count(*) FROM q_outbox o JOIN q_cells c ON c.cell_id=o.cell_id "
                                    "WHERE c.scope_id=? AND o.state IN ('PENDING','LEASED')",(str(scope_id),)).fetchone()[0]
            dead=self.db.execute("SELECT count(*) FROM q_outbox o JOIN q_cells c ON c.cell_id=o.cell_id "
                                  "WHERE c.scope_id=? AND o.state='DEAD'",(str(scope_id),)).fetchone()[0]
        else:
            cells=self.db.execute('SELECT count(*) FROM q_cells').fetchone()[0]
            pending=self.db.execute("SELECT count(*) FROM q_outbox WHERE state IN ('PENDING','LEASED')").fetchone()[0]
            dead=self.db.execute("SELECT count(*) FROM q_outbox WHERE state='DEAD'").fetchone()[0]
        return {"cells":cells,"pending_events":pending,"dead_events":dead,"schema":"7.4.0-reconstructed"}

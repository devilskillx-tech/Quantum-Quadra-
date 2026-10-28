"""Local demonstration of signed revocation events and independently stored checkpoints.

Trust boundary: the witness database AND its private key MUST be controlled by a
separate authority in production. Two files on one host are NOT independent.
No production / distributed transaction guarantees are claimed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

ZERO = "0" * 64


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def unb64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def private_key_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def public_key_pem(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def sign(key: Ed25519PrivateKey, payload: dict) -> str:
    return b64(key.sign(canonical(payload)))


def authentic(pub: Ed25519PublicKey, payload: dict, signature: str) -> bool:
    try:
        pub.verify(unb64(signature), canonical(payload))
        return True
    except (InvalidSignature, ValueError):
        return False


class IntegrityError(ValueError):
    pass


def _connect(path: str | Path) -> sqlite3.Connection:
    db = sqlite3.connect(str(path), timeout=5, isolation_level=None)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA busy_timeout=5000")
    return db


class ExternalWitness:
    """A demo authority with independently signed, complete event archive.

    In production use a remote trusted endpoint, separately held keys and durable
    archive. This local implementation is a fault-injection test double only.
    """

    def __init__(self, path: str | Path, key: Ed25519PrivateKey, issuer_public: Ed25519PublicKey):
        self.db = _connect(path)
        self.key = key
        self.issuer_public = issuer_public
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS archive(
             sequence INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE,
             record TEXT NOT NULL, record_hash TEXT NOT NULL UNIQUE);
          CREATE TABLE IF NOT EXISTS checkpoints(
             sequence INTEGER PRIMARY KEY, record_hash TEXT NOT NULL,
             signature TEXT NOT NULL);
        """)

    def close(self):
        self.db.close()

    def latest(self) -> dict | None:
        item = self.db.execute("SELECT sequence,record_hash,signature FROM checkpoints ORDER BY sequence DESC LIMIT 1").fetchone()
        if not item:
            return None
        return {"sequence": item[0], "head_hash": item[1], "signature": item[2]}

    def _receipt_body(self, seq: int, head: str) -> dict:
        return {"schema_version": 1, "ledger_id": "QUADRA-REVOCATIONS-DEMO", "sequence": seq, "head_hash": head}

    def verify_receipt(self, receipt: dict, trusted_witness: Ed25519PublicKey) -> bool:
        if not isinstance(receipt, dict) or set(receipt) != {"sequence", "head_hash", "signature"}:
            return False
        if type(receipt["sequence"]) is not int or receipt["sequence"] < 1 or not isinstance(receipt["head_hash"], str):
            return False
        return authentic(trusted_witness, self._receipt_body(receipt["sequence"], receipt["head_hash"]), receipt["signature"])

    def publish(self, record: dict) -> dict:
        """Idempotently commit signed event and checkpoint in one witness transaction."""
        if not verify_event(record, self.issuer_public):
            raise IntegrityError("UNAUTHENTIC_EVENT")
        body = record["event"]
        seq = body["sequence"]
        if seq < 1 or body["previous_hash"] not in ([ZERO] if seq == 1 else [self._previous(seq-1)]):
            raise IntegrityError("WITNESS_SEQUENCE_OR_PREV_MISMATCH")
        raw = canonical(record).decode()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.db.execute("SELECT record,record_hash FROM archive WHERE sequence=?", (seq,)).fetchone()
            if previous:
                if previous[0] != raw or previous[1] != record["event_hash"]:
                    raise IntegrityError("WITNESS_FORK")
                outcome = self.latest()
                self.db.execute("COMMIT")
                return outcome
            current = self.latest()
            if seq != (current["sequence"] + 1 if current else 1):
                raise IntegrityError("WITNESS_MISSING_EVENT")
            self.db.execute("INSERT INTO archive VALUES (?,?,?,?)", (seq, body["event_id"], raw, record["event_hash"]))
            self.db.execute("INSERT INTO checkpoints VALUES (?,?,?)", (seq, record["event_hash"], sign(self.key,self._receipt_body(seq,record["event_hash"]))))
            outcome = self.latest()
            self.db.execute("COMMIT")
            return outcome
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def _previous(self, seq: int) -> str:
        row = self.db.execute("SELECT record_hash FROM archive WHERE sequence=?", (seq,)).fetchone()
        return row[0] if row else ""

    def includes(self, record: dict, receipt: dict) -> bool:
        if not self.verify_receipt(receipt, self.key.public_key()):
            return False
        seq = record["event"]["sequence"]
        if seq > receipt["sequence"]:
            return False
        row = self.db.execute("SELECT record FROM archive WHERE sequence=?", (seq,)).fetchone()
        return bool(row and json.loads(row[0]) == record)

    def archived(self) -> list[dict]:
        return [json.loads(row[0]) for row in self.db.execute("SELECT record FROM archive ORDER BY sequence")]


def verify_event(record: dict, trusted_issuer: Ed25519PublicKey) -> bool:
    try:
        if set(record) != {"event", "event_hash", "issuer_signature"}:
            return False
        body = record["event"]
        if set(body) != {"schema_version", "sequence", "event_id", "certificate_id", "previous_hash", "type"}:
            return False
        if body["schema_version"] != 1 or body["type"] != "REVOKE" or type(body["sequence"]) is not int or body["sequence"] < 1:
            return False
        if not all(isinstance(body[k], str) and body[k] for k in ("event_id", "certificate_id", "previous_hash")):
            return False
        if digest(body) != record["event_hash"]:
            return False
        return authentic(trusted_issuer, body, record["issuer_signature"])
    except (ValueError, TypeError, KeyError):
        return False


class RevocationLedger:
    """SQLite outbox + revocation store; business ACK only after witness receipt.

    Local fail-closed check refuses use whenever the anchored chain cannot be
    authenticated. No two-phase commit or production witness is implied.
    """

    def __init__(self, path: str | Path, key: Ed25519PrivateKey, witness: ExternalWitness,
                 trusted_witness: Ed25519PublicKey):
        self.db = _connect(path)
        self.key = key
        self.pub = key.public_key()
        self.witness = witness
        self.trusted_witness = trusted_witness
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS events(
                sequence INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE,
                certificate_id TEXT NOT NULL, record TEXT NOT NULL, record_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS outbox(
                event_id TEXT PRIMARY KEY, status TEXT NOT NULL CHECK(status IN ('PENDING','CONFIRMED')));
        """)

    def close(self): self.db.close()

    def revoke(self, certificate_id: str, event_id: str) -> dict:
        if not certificate_id or not event_id or len(certificate_id)>200 or len(event_id)>200:
            raise ValueError("invalid ids")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            existing = self.db.execute("SELECT record FROM events WHERE event_id=?",(event_id,)).fetchone()
            if existing:
                rec = json.loads(existing[0])
                if rec["event"]["certificate_id"] != certificate_id:
                    raise IntegrityError("IDEMPOTENCY_KEY_COLLISION")
                self.db.execute("COMMIT")
                return rec
            row = self.db.execute("SELECT sequence,record_hash FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
            seq = row[0]+1 if row else 1
            head = row[1] if row else ZERO
            body = {"schema_version":1,"sequence":seq,"event_id":event_id,"certificate_id":certificate_id,"previous_hash":head,"type":"REVOKE"}
            rec = {"event":body,"event_hash":digest(body),"issuer_signature":sign(self.key,body)}
            self.db.execute("INSERT INTO events VALUES (?,?,?,?,?)",(seq,event_id,certificate_id,canonical(rec).decode(),rec["event_hash"]))
            self.db.execute("INSERT INTO outbox VALUES (?,?)",(event_id,"PENDING"))
            self.db.execute("COMMIT")
            return rec
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def send_pending(self) -> list[dict]:
        results = []
        for (eid, record,) in self.db.execute("SELECT o.event_id,e.record FROM outbox o JOIN events e ON o.event_id=e.event_id WHERE o.status='PENDING' ORDER BY e.sequence").fetchall():
            receipt = self.witness.publish(json.loads(record))
            if not self.witness.verify_receipt(receipt, self.trusted_witness):
                raise IntegrityError("UNTRUSTED_CHECKPOINT")
            event = json.loads(record)
            if not self.witness.includes(event, receipt):
                raise IntegrityError("CHECKPOINT_DOES_NOT_COVER_EVENT")
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute("UPDATE outbox SET status='CONFIRMED' WHERE event_id=?",(eid,))
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
            results.append(receipt)
        return results

    def verify_and_status(self) -> dict:
        latest = self.witness.latest()
        if not latest:
            # No trusted witness state: do not claim current validity.
            return {"status":"UNVERIFIABLE","reason":"NO_TRUSTED_CHECKPOINT"}
        if not self.witness.verify_receipt(latest,self.trusted_witness):
            return {"status":"REJECTED","reason":"CHECKPOINT_SIGNATURE_INVALID"}
        local = [json.loads(r[0]) for r in self.db.execute("SELECT record FROM events ORDER BY sequence")]
        archive = self.witness.archived()
        prev = ZERO
        for seq, event in enumerate(archive,1):
            if not verify_event(event,self.pub) or event["event"]["sequence"]!=seq or event["event"]["previous_hash"]!=prev:
                return {"status":"REJECTED","reason":"BROKEN_ARCHIVE_CHAIN"}
            prev = event["event_hash"]
        if len(archive) != latest["sequence"] or prev != latest["head_hash"]:
            return {"status":"REJECTED","reason":"ANCHOR_ARCHIVE_MISMATCH"}
        local_prev=ZERO
        for seq, e in enumerate(local,1):
            if (not verify_event(e,self.pub) or e["event"]["sequence"]!=seq
                    or e["event"]["previous_hash"]!=local_prev
                    or (seq <= len(archive) and e != archive[seq-1])):
                return {"status":"REJECTED","reason":"LOCAL_CHAIN_DIVERGED"}
            local_prev=e["event_hash"]
        if len(local)<len(archive):
            return {"status":"RECOVERY_REQUIRED","reason":"ROLLBACK_DETECTED","local_sequence":len(local),"checkpoint_sequence":len(archive)}
        # With local events ahead of the witness, they remain unanchored. Their
        # revocations must still block locally but are not globally certified.
        return {"status":"VERIFIED" if len(local)==len(archive) else "ANCHOR_PENDING",
                "local_sequence":len(local),"checkpoint_sequence":len(archive)}

    def reconcile(self) -> dict:
        status = self.verify_and_status()
        if status["status"] not in ("RECOVERY_REQUIRED","VERIFIED","ANCHOR_PENDING"):
            raise IntegrityError("CANNOT_RECONCILE:"+status["status"])
        for record in self.witness.archived():
            seq = record["event"]["sequence"]
            if self.db.execute("SELECT 1 FROM events WHERE sequence=?",(seq,)).fetchone():
                continue
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute("INSERT INTO events VALUES (?,?,?,?,?)",(seq,record["event"]["event_id"],record["event"]["certificate_id"],canonical(record).decode(),record["event_hash"]))
                self.db.execute("INSERT OR IGNORE INTO outbox VALUES (?,?)",(record["event"]["event_id"],"CONFIRMED"))
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
        return self.verify_and_status()

    def certificate_usable(self, certificate_id: str) -> bool:
        state = self.verify_and_status()
        if state["status"] != "VERIFIED":
            return False
        return self.db.execute("SELECT 1 FROM events WHERE certificate_id=? LIMIT 1",(certificate_id,)).fetchone() is None

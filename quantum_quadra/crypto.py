"""Explicit-key AES-GCM, authenticated metadata and canonical JSON."""
import base64
import hashlib
import json
import os
from typing import Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def master_key_from_env() -> bytes:
    value = os.getenv("QUADRA_KEK")
    if not value:
        raise RuntimeError("QUADRA_KEK manquant : fournir 32 octets aléatoires encodés en base64")
    try:
        key = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise RuntimeError("QUADRA_KEK : base64 invalide") from exc
    if len(key) != 32:
        raise RuntimeError("QUADRA_KEK doit contenir exactement 32 octets")
    return key


def aad_for(row: dict) -> bytes:
    return canonical({key: row[key] for key in (
        "cell_id", "scope_id", "memory_kind", "logical_key", "creator_type",
        "status", "key_version", "revision", "payload_sha256")})


def encrypt(key: bytes, payload: bytes, aad: bytes) -> bytes:
    return b"\x01" + (nonce := os.urandom(12)) + AESGCM(key).encrypt(nonce, payload, aad)


def decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < 30 or blob[0] != 1:
        raise ValueError("Enveloppe chiffrée invalide")
    return AESGCM(key).decrypt(blob[1:13], blob[13:], aad)


def wrap_dek(kek: bytes, scope_id: str, version: int, dek: bytes) -> bytes:
    return encrypt(kek, dek, canonical({"scope_id": scope_id, "version": version, "purpose": "DEK"}))


def unwrap_dek(kek: bytes, scope_id: str, version: int, wrapped: bytes) -> bytes:
    return decrypt(kek, wrapped, canonical({"scope_id": scope_id, "version": version, "purpose": "DEK"}))


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()

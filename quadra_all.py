#!/usr/bin/env python3
"""All-in-one launcher for QUANTUM QUADRA; deliberately no production GO."""
from __future__ import annotations
import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path


def demo_rollback() -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from quantum_quadra.revocation_anchor import RevocationLedger, ExternalWitness
    with tempfile.TemporaryDirectory() as directory:
        where=Path(directory)
        issuer=Ed25519PrivateKey.generate()
        witness_key=Ed25519PrivateKey.generate()
        witness=ExternalWitness(where/'independent_witness.sqlite',witness_key,issuer.public_key())
        db=where/'local.sqlite'
        ledger=RevocationLedger(db,issuer,witness,witness_key.public_key())
        # Snapshot BEFORE revocation; separate from the witness database.
        with sqlite3.connect(str(where/'old.sqlite')) as backup:
            ledger.db.backup(backup)
        ledger.revoke('example-certificate','example-revocation')
        assert ledger.certificate_usable('example-certificate') is False
        receipts=ledger.send_pending()
        assert receipts and ledger.verify_and_status()['status']=='VERIFIED'
        ledger.close()
        for ext in ('', '-wal','-shm'):
            f=Path(str(db)+ext)
            if f.exists(): f.unlink()
        shutil.copyfile(where/'old.sqlite',db)
        restored=RevocationLedger(db,issuer,witness,witness_key.public_key())
        before=restored.verify_and_status()
        assert before['status']=='RECOVERY_REQUIRED'
        assert not restored.certificate_usable('example-certificate')
        after=restored.reconcile()
        assert after['status']=='VERIFIED'
        assert not restored.certificate_usable('example-certificate')
        restored.close()
        witness.close()
    return {'status':'PASS','scope':'LOCAL_SQLITE_AND_LOCAL_EXTERNAL_WITNESS_SIMULATION',
            'rollback_status':before['status'],'restored_status':after['status'],
            'revoked_certificate_accepted':False,'production_go':False}


def doctor():
    from importlib.util import find_spec
    from scripts.formal_mutation_runner import evaluate
    result={'existing_core':'PRESENT', 'cryptography': bool(find_spec('cryptography')),
            'pytest':bool(find_spec('pytest')),
            'tlc_executed':False,
            'local_model_mutations':evaluate()['status'],
            'independent_witness_deployed':False,
            'effective_github_permissions_attested':False,
            'main_ruleset_verified_active':False,
            'production_go':False}
    return result


def main(argv=None):
    p=argparse.ArgumentParser(prog='quadra_all',description='QUANTUM QUADRA unified entrypoint; not production certified')
    sub=p.add_subparsers(dest='command',required=True)
    for c in ['doctor','demo-rollback','verify-formal','selftest','test','core']:
        sub.add_parser(c)
    args, rest = p.parse_known_args(argv)
    if args.command=='core':
        from quantum_quadra.cli import main as core_main
        return core_main(rest)
    if args.command=='doctor':
        result=doctor();print(json.dumps(result,indent=2));return 0
    if args.command=='demo-rollback':
        print(json.dumps(demo_rollback(),indent=2));return 0
    if args.command=='verify-formal':
        from scripts.formal_mutation_runner import main as check
        return check(rest)
    if args.command=='test':
        return subprocess.call([sys.executable,'-m','pytest','-q','tests']+rest)
    if args.command=='selftest':
        from quantum_quadra.cli import main as original
        return main_bridge(original,'selftest',rest)
    return 2


def main_bridge(fn,cmd,rest):
    return fn(rest+[cmd])


if __name__=='__main__': raise SystemExit(main())

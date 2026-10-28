"""Measured local RTO (after backup availability) and RPO (committed cells)."""
import secrets, sqlite3, uuid
from time import perf_counter
import pytest
from quantum_quadra.recovery import observe
from quantum_quadra.store import QuadraStore, QuadraError


def test_gate_rejects_data_loss():
    with pytest.raises(AssertionError,match='NO-GO'):
        observe('lost',perf_counter(),3,2,10).require_pass()


def test_gate_rejects_rto_regression():
    with pytest.raises(AssertionError,match='NO-GO'):
        observe('slow',perf_counter()-15,3,3,0.01).require_pass()


def test_backup_recovers_all_committed_cells_within_objective(tmp_path):
    scope=str(uuid.uuid4()); key=secrets.token_bytes(32)
    src=tmp_path/'source.db'; backup=tmp_path/'backup.db'
    with QuadraStore(str(src),key) as db:
        ids=[db.put(scope,str(i),{'i':i}) for i in range(20)]
        with sqlite3.connect(str(backup)) as dest:
            db.db.backup(dest)
    start=perf_counter()
    with QuadraStore(str(backup),key) as db:
        count=sum(db.read(scope,cid)['payload']['i']==i for i,cid in enumerate(ids))
        assert db.verify_all()['valid']
    observe('sqlite_restore',start,len(ids),count,10).require_pass()


def test_revocation_survives_restoration(tmp_path):
    scope=str(uuid.uuid4());key=secrets.token_bytes(32)
    with QuadraStore(str(tmp_path/'src.db'),key) as db:
        cid=db.put(scope,'revoked',{'status':'sensitive'})
        db.transition(scope,cid,'REVOKED')
        with sqlite3.connect(str(tmp_path/'backup.db')) as snap:
            db.db.backup(snap)
    start=perf_counter()
    with QuadraStore(str(tmp_path/'backup.db'),key) as restored:
        with pytest.raises(QuadraError):restored.read(scope,cid)
        assert restored.read(scope,cid,allow_inactive=True)['status']=='REVOKED'
        assert restored.verify_all()['valid']
    observe('sqlite_revocation',start,1,1,10).require_pass()

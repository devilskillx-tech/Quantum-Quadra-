import os
import secrets
import uuid
from fastapi.testclient import TestClient
from quantum_quadra.store import QuadraStore
from quantum_quadra.api import create_app

def test_api_requires_token_and_isolates_scope(monkeypatch,tmp_path):
    scope=str(uuid.uuid4());other=str(uuid.uuid4());token='secret-'+'x'*32
    monkeypatch.setenv('QUADRA_API_TOKEN',token)
    monkeypatch.setenv('QUADRA_API_SCOPE',scope)
    with QuadraStore(str(tmp_path/'api.db'),secrets.token_bytes(32)) as store:
        hidden=store.put(other,'private',{'secret':'never expose'})
        with TestClient(create_app(store)) as client:
            assert client.get('/status').status_code==401
            assert client.get('/status',headers={'Authorization':'Bearer wrong'}).status_code==403
            h={'Authorization':'Bearer '+token}
            r=client.post('/cell',headers=h,json={'logical_key':'item','payload':{'text':'hello world'}})
            assert r.status_code==201
            assert client.get('/cell/'+hidden,headers=h).status_code==404
            assert client.get('/search',params={'q':'secret'},headers=h).json()==[]
            assert client.get('/search',params={'q':'hello'},headers=h).json()[0]['logical_key']=='item'


def test_api_returns_409_for_tampered_ciphertext(monkeypatch,tmp_path):
    scope=str(uuid.uuid4());token='secret-'+'z'*32
    monkeypatch.setenv('QUADRA_API_TOKEN',token)
    monkeypatch.setenv('QUADRA_API_SCOPE',scope)
    with QuadraStore(str(tmp_path/'tampered.db'),secrets.token_bytes(32)) as store:
        cid=store.put(scope,'alpha',{'x':1})
        blob=store.db.execute('SELECT encrypted_payload FROM q_cells WHERE cell_id=?',(cid,)).fetchone()[0]
        store.db.execute('UPDATE q_cells SET encrypted_payload=? WHERE cell_id=?',
                         (blob[:-1]+bytes([blob[-1]^1]),cid))
        store.db.commit()
        with TestClient(create_app(store)) as client:
            r=client.get('/cell/'+cid,headers={'Authorization':'Bearer '+token})
            assert r.status_code==409

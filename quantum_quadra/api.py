"""Single-scope bearer-token API. No anonymous operations or wildcard CORS."""
import hmac
import os
import uuid
from fastapi import FastAPI, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field, ConfigDict
from .store import QuadraStore, QuadraError, IntegrityError
from .search import LocalSemanticModel

class CellInput(BaseModel):
    logical_key: str = Field(min_length=1,max_length=300)
    payload: dict
    memory_kind: str = 'EPISODIC'
    importance: float = Field(default=0.5,ge=0,le=1)

class AgentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")  # never accept caller-provided scope or tool overrides
    role: str = Field(min_length=1,max_length=50)
    query: str = Field(default="",max_length=1000)
    limit: int = Field(default=4,ge=1,le=8)
    use_local_ai: bool = False

class TransitionInput(BaseModel):
    status: str


def create_app(store=None):
    token=os.environ.get('QUADRA_API_TOKEN','')
    scope=os.environ.get('QUADRA_API_SCOPE','')
    if len(token)<24: raise RuntimeError('QUADRA_API_TOKEN doit avoir au moins 24 caractères')
    try: uuid.UUID(scope)
    except (ValueError,AttributeError) as exc:
        raise RuntimeError('QUADRA_API_SCOPE doit être un UUID valide') from exc
    if store is None:
        path=os.environ.get('QUADRA_EDGE_DB')
        if not path: raise RuntimeError('QUADRA_EDGE_DB manquant')
        store=QuadraStore(path)
    app=FastAPI(title='QUANTUM QUADRA reconstructed',version='7.7.1.dev0')

    def authorized(authorization: str | None = Header(default=None)):
        if not authorization or not authorization.startswith('Bearer '):
            raise HTTPException(status_code=401,detail='Bearer token requis')
        provided=authorization[len('Bearer '):]
        if not hmac.compare_digest(provided,token):
            raise HTTPException(status_code=403,detail='Accès refusé')
        return scope

    @app.get('/status')
    def status(s=Depends(authorized)):
        return store.status(s)

    @app.post('/cell',status_code=201)
    def put_cell(body:CellInput,s=Depends(authorized)):
        try:
            cid=store.put(s,body.logical_key,body.payload,body.memory_kind,importance=body.importance)
            return {'cell_id':cid}
        except ValueError as exc: raise HTTPException(status_code=422,detail=str(exc)) from exc

    @app.get('/cell/{cell_id}')
    def get_cell(cell_id:str,s=Depends(authorized)):
        try: return store.read(s,cell_id)
        except IntegrityError: raise HTTPException(status_code=409,detail='Intégrité invalide')
        except (KeyError,QuadraError): raise HTTPException(status_code=404,detail='Cellule indisponible')

    @app.post('/cell/{cell_id}/transition')
    def transition(cell_id:str,body:TransitionInput,s=Depends(authorized)):
        try: return {'revision':store.transition(s,cell_id,body.status)}
        except (KeyError,QuadraError): raise HTTPException(status_code=409,detail='Transition interdite')
        except ValueError as exc: raise HTTPException(status_code=422,detail=str(exc)) from exc

    @app.get('/search')
    def search(q:str=Query(min_length=1,max_length=1000),limit:int=Query(5,ge=1,le=100),
               mode:str='bm25',s=Depends(authorized)):
        try:
            model=LocalSemanticModel(os.environ['QUADRA_SEMANTIC_MODEL_PATH']) if mode=='hybrid' and 'QUADRA_SEMANTIC_MODEL_PATH' in os.environ else None
            return store.search(s,q,limit,mode,model)
        except (RuntimeError,ValueError) as exc: raise HTTPException(status_code=422,detail=str(exc)) from exc

    @app.get('/agents')
    def agent_catalog(s=Depends(authorized)):
        from .agents import SPECS
        return [{'name': spec.name, 'purpose': spec.purpose,
                 'capabilities': spec.capabilities, 'local_ai_supported': spec.model_allowed}
                for spec in SPECS.values()]

    @app.post('/agents/run')
    def agent_run(body: AgentInput, s=Depends(authorized)):
        from .agents import AgentPolicyError, build_local_agents
        try:
            # The authenticated scope is passed server-side; the request cannot supply one.
            model_name = os.environ.get('QUADRA_AGENT_LOCAL_MODEL') if body.use_local_ai else None
            agents = build_local_agents(store, model_name=model_name)
            return agents.run(s, body.role, query=body.query, limit=body.limit,
                              use_local_ai=body.use_local_ai)
        except AgentPolicyError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except IntegrityError as exc:
            raise HTTPException(status_code=409, detail='Intégrité invalide') from exc

    @app.get('/audit/verify')
    def verify(s=Depends(authorized)):
        return store.verify_all(s)
    return app

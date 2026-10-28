"""Reproducible retrieval evaluation with annotated relevance labels.

Never use its toy/example fixture to claim production search quality.
"""
import json
import math
from pathlib import Path
from .search import rank, LocalSemanticModel


def _ndcg(ids, relevant, k):
    rel = set(relevant)
    dcg = sum((1 / math.log2(pos + 2)) for pos, cid in enumerate(ids[:k]) if cid in rel)
    ideal = sum(1 / math.log2(pos + 2) for pos in range(min(k, len(rel))))
    return dcg / ideal if ideal else 0.0


def evaluate(dataset: dict, k=10, mode='bm25', semantic=None) -> dict:
    """Dataset: documents[{id,scope,text}], queries[{text,scope,relevant:[id]}]."""
    if not isinstance(k, int) or not 1 <= k <= 100:
        raise ValueError('k doit être compris entre 1 et 100')
    documents = dataset['documents']
    queries = dataset['queries']
    if not queries: raise ValueError('Requêtes annotées manquantes')
    if len({d['id'] for d in documents}) != len(documents):
        raise ValueError('IDs documents dupliqués')
    id_to_scope = {d['id']: d['scope'] for d in documents}
    totals={'ndcg_at_k':0.0,'recall_at_k':0.0,'mrr_at_k':0.0,'precision_at_k':0.0}
    details=[]
    for q in queries:
        relevant=set(q['relevant'])
        if not relevant or any(id_to_scope.get(cid) != q['scope'] for cid in relevant):
            raise ValueError('Labels de pertinence invalides ou inter-scopes')
        scoped=[d for d in documents if d['scope']==q['scope']]
        scores=rank(q['text'],[d['text'] for d in scoped],mode,semantic)
        ordered=sorted(zip(scoped,scores),key=lambda pair:(-pair[1],pair[0]['id']))
        ids=[d['id'] for d,score in ordered if score>0][:k]
        hits=sum(cid in relevant for cid in ids)
        reciprocal=next((1/(i+1) for i,cid in enumerate(ids) if cid in relevant),0.0)
        ndcg=_ndcg(ids,relevant,k)
        metrics={'ndcg_at_k':ndcg,'recall_at_k':hits/len(relevant),
                 'mrr_at_k':reciprocal,'precision_at_k':hits/k}
        for name,value in metrics.items():totals[name]+=value
        details.append({'query':q['text'],'scope':q['scope'],'retrieved_ids':ids,**metrics})
    return {'mode':mode,'k':k,'queries_evaluated':len(queries),
            'metrics':{key:round(val/len(queries),5) for key,val in totals.items()},
            'per_query':details}


def evaluate_file(path: str, k=10, mode='bm25', model_path=None):
    data=json.loads(Path(path).read_text(encoding='utf-8'))
    semantic=LocalSemanticModel(model_path) if mode=='hybrid' and model_path else None
    return evaluate(data,k,mode,semantic)

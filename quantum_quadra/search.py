"""BM25 on decrypted, scope-filtered documents; optional explicit local semantic model."""
import math
import re
from collections import Counter
from pathlib import Path


def terms(text: str) -> list[str]:
    return re.findall(r"[^\W_]+", text.casefold(), flags=re.UNICODE)


def flatten(value) -> str:
    if isinstance(value, dict):
        return " ".join(str(k) + " " + flatten(v) for k, v in value.items())
    if isinstance(value, (tuple, list)):
        return " ".join(flatten(v) for v in value)
    return str(value)


def bm25_scores(query: str, docs: list[str], k1=1.5, b=0.75) -> list[float]:
    token_lists = [terms(d) for d in docs]
    count = len(token_lists)
    if not count:
        return []
    avgdl = max(sum(len(t) for t in token_lists) / count, 1)
    dfs = Counter(t for tokens in token_lists for t in set(tokens))
    scores = []
    for tokens in token_lists:
        tf = Counter(tokens)
        score = 0.0
        for term in set(terms(query)):
            if not tf[term]:
                continue
            idf = math.log(1 + (count - dfs[term] + 0.5) / (dfs[term] + 0.5))
            denom = tf[term] + k1 * (1 - b + b * len(tokens) / avgdl)
            score += idf * (tf[term] * (k1 + 1)) / denom
        scores.append(score)
    return scores


class LocalSemanticModel:
    """No automatic downloads: model must exist on local disk."""
    def __init__(self, path: str):
        if not Path(path).exists():
            raise RuntimeError("Modèle sémantique absent du disque local")
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError("Installer l'extra [semantic]") from exc
        self.model = SentenceTransformer(path, local_files_only=True)

    def similarity(self, query: str, docs: list[str]) -> list[float]:
        vectors = self.model.encode([query, *docs], normalize_embeddings=True)
        return [float(vectors[0] @ vector) for vector in vectors[1:]]


def rank(query: str, docs: list[str], mode="bm25", semantic=None):
    lex = bm25_scores(query, docs)
    if mode == "bm25":
        return lex
    if mode != "hybrid":
        raise ValueError("Mode de recherche inconnu")
    if semantic is None:
        raise RuntimeError("Mode hybride indisponible : aucun modèle local validé")
    sem = semantic.similarity(query, docs)
    top = max(lex, default=0.0)
    return [0.5 * (a / top if top else 0.0) + 0.5 * max(0.0, b) for a, b in zip(lex, sem)]

"""Vector store for RAG workflows using sentence-transformers and numpy."""

from __future__ import annotations

import json
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import structlog

log = structlog.get_logger(__name__)

DEFAULT_EMBEDDING_MODEL = "all-MiniLM-L6-v2"
DEFAULT_PERSIST_DIR = os.environ.get("ADML_CHROMA_PERSIST_DIR", "./data/chroma")


@dataclass
class StoredDocument:
    id: str
    content: str
    source: str
    metadata: dict[str, Any] | None = None


@dataclass
class RetrievedChunk:
    content: str
    source: str
    score: float
    document_id: str
    is_poisoned: bool = False


def _cosine_similarity(query: np.ndarray, matrix: np.ndarray) -> np.ndarray:
    query_norm = np.linalg.norm(query)
    if query_norm == 0:
        return np.zeros(matrix.shape[0])
    matrix_norms = np.linalg.norm(matrix, axis=1)
    matrix_norms = np.where(matrix_norms == 0, 1.0, matrix_norms)
    return (matrix @ query) / (matrix_norms * query_norm)


class RagVectorStore:
    """Local vector store for RAG document management."""

    def __init__(
        self,
        collection_name: str = "default",
        persist_dir: str | None = DEFAULT_PERSIST_DIR,
        embedding_model: str = DEFAULT_EMBEDDING_MODEL,
    ) -> None:
        self.collection_name = collection_name
        base = Path(persist_dir or DEFAULT_PERSIST_DIR)
        self._dir = base / collection_name
        self._dir.mkdir(parents=True, exist_ok=True)
        self._embeddings_path = self._dir / "embeddings.npy"
        self._meta_path = self._dir / "metadata.json"

        try:
            from sentence_transformers import SentenceTransformer  # noqa: PLC0415

            self._model: Any = SentenceTransformer(embedding_model)
        except Exception:
            log.warning("rag.embedding_fallback", reason="sentence_transformers_unavailable")
            self._model = None

        self._ids: list[str] = []
        self._documents: list[str] = []
        self._metadatas: list[dict[str, Any]] = []
        self._embeddings: np.ndarray | None = None
        self._load()

    def _load(self) -> None:
        if self._meta_path.exists():
            data = json.loads(self._meta_path.read_text(encoding="utf-8"))
            self._ids = list(data.get("ids", []))
            self._documents = list(data.get("documents", []))
            self._metadatas = list(data.get("metadatas", []))
        if self._embeddings_path.exists():
            self._embeddings = np.load(self._embeddings_path)

    def _save(self) -> None:
        self._meta_path.write_text(
            json.dumps(
                {
                    "ids": self._ids,
                    "documents": self._documents,
                    "metadatas": self._metadatas,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        if self._embeddings is not None:
            np.save(self._embeddings_path, self._embeddings)

    def ingest(
        self,
        documents: list[str],
        sources: list[str] | None = None,
        metadatas: list[dict[str, str]] | None = None,
        ids: list[str] | None = None,
    ) -> list[str]:
        """Ingest documents into the vector store."""
        if self._model is None:
            raise RuntimeError("sentence-transformers is required for RAG ingestion")

        if ids is None:
            ids = [str(uuid.uuid4()) for _ in documents]
        if sources is None:
            sources = ["unknown"] * len(documents)
        if metadatas is None:
            metadatas = [{} for _ in documents]

        for i, src in enumerate(sources):
            if metadatas[i] is None:
                metadatas[i] = {}
            metadatas[i]["source"] = src

        new_embeddings = np.asarray(self._model.encode(documents, convert_to_numpy=True))
        if self._embeddings is None or len(self._embeddings) == 0:
            self._embeddings = new_embeddings
        else:
            self._embeddings = np.vstack([self._embeddings, new_embeddings])

        self._ids.extend(ids)
        self._documents.extend(documents)
        self._metadatas.extend(metadatas)
        self._save()

        log.info("rag.ingested", count=len(documents), collection=self.collection_name)
        return ids

    def search(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        """Search the vector store for documents relevant to the query."""
        if self._model is None or self._embeddings is None or not self._ids:
            return []

        query_embedding = np.asarray(self._model.encode([query], convert_to_numpy=True)[0])
        scores = _cosine_similarity(query_embedding, self._embeddings)
        top_indices = np.argsort(scores)[::-1][:k]

        chunks: list[RetrievedChunk] = []
        for idx in top_indices:
            meta = self._metadatas[idx]
            source = str(meta.get("source", "unknown"))
            chunks.append(
                RetrievedChunk(
                    content=self._documents[idx],
                    source=source,
                    score=round(float(scores[idx]), 4),
                    document_id=self._ids[idx],
                )
            )
        return chunks

    def count(self) -> int:
        return len(self._ids)

    def delete_collection(self) -> None:
        if self._dir.exists():
            shutil.rmtree(self._dir)
        self._ids = []
        self._documents = []
        self._metadatas = []
        self._embeddings = None
        log.info("rag.collection_deleted", name=self.collection_name)

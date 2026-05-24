"""Vector store abstraction backed by ChromaDB for RAG workflows."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import chromadb
import structlog

log = structlog.get_logger(__name__)

DEFAULT_EMBEDDING_MODEL = "all-MiniLM-L6-v2"


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


class RagVectorStore:
    """ChromaDB-backed vector store for RAG document management."""

    def __init__(
        self,
        collection_name: str = "default",
        persist_dir: str | None = None,
        embedding_model: str = DEFAULT_EMBEDDING_MODEL,
    ) -> None:
        self.collection_name = collection_name
        self._persist_dir = persist_dir

        if persist_dir:
            Path(persist_dir).mkdir(parents=True, exist_ok=True)
            self._client: chromadb.ClientAPI = chromadb.PersistentClient(path=persist_dir)
        else:
            self._client = chromadb.Client()

        try:
            from chromadb.utils import embedding_functions  # noqa: PLC0415
            self._ef: Any = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name=embedding_model,
            )
        except Exception:
            log.warning("rag.embedding_fallback", reason="sentence_transformers_unavailable")
            self._ef = None

        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            embedding_function=self._ef,
        )

    def ingest(
        self,
        documents: list[str],
        sources: list[str] | None = None,
        metadatas: list[dict[str, str]] | None = None,
        ids: list[str] | None = None,
    ) -> list[str]:
        """Ingest documents into the vector store.

        Returns the list of document IDs.
        """
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

        self._collection.add(
            ids=ids,
            documents=documents,
            metadatas=metadatas,  # type: ignore[arg-type]
        )

        log.info("rag.ingested", count=len(documents), collection=self.collection_name)
        return ids

    def search(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        """Search the vector store for documents relevant to the query."""
        results = self._collection.query(
            query_texts=[query],
            n_results=k,
            include=["documents", "metadatas", "distances"],
        )

        chunks: list[RetrievedChunk] = []
        if not results["ids"] or not results["ids"][0]:
            return chunks

        for i in range(len(results["ids"][0])):
            doc_id = results["ids"][0][i]
            content = results["documents"][0][i] if results["documents"] else ""
            distance = results["distances"][0][i] if results["distances"] else 1.0
            meta = results["metadatas"][0][i] if results["metadatas"] else {}
            source = str(meta.get("source", "unknown")) if isinstance(meta, dict) else "unknown"
            score = round(1.0 - min(1.0, distance), 4)

            chunks.append(RetrievedChunk(
                content=content,
                source=source,
                score=score,
                document_id=doc_id,
            ))

        return chunks

    def count(self) -> int:
        return self._collection.count()

    def delete_collection(self) -> None:
        self._client.delete_collection(self.collection_name)
        log.info("rag.collection_deleted", name=self.collection_name)

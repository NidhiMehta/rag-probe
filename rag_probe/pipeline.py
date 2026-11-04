"""
Pluggable RAG pipeline: embed → store → retrieve.

Default backend: ChromaDB + sentence-transformers (all local, no API).
Swap vector store by passing a custom store adapter.

Usage
-----
from rag_probe.pipeline import Pipeline

p = Pipeline()                          # ChromaDB default
p.index("my_collection", chunks)        # embed + store
results = p.query("my_collection", "What does this document say?", top_k=3)
"""

from __future__ import annotations
from typing import Callable
from sentence_transformers import SentenceTransformer

EMBED_MODEL = "all-MiniLM-L6-v2"


class Pipeline:
    """
    Embeds chunks and stores them in a vector store.
    Default: ChromaDB (persistent). Swap store_backend for other backends.

    Parameters
    ----------
    chroma_path   : directory for ChromaDB persistence
    embed_model   : sentence-transformers model name
    store_backend : callable(name, chunks, embeddings) -> store object
                    override to use FAISS, LlamaIndex, LangChain, etc.
    query_backend : callable(store, query_embedding, top_k) -> list[str]
    """

    def __init__(
        self,
        chroma_path: str = "./chromadb",
        embed_model: str = EMBED_MODEL,
        store_backend: Callable | None = None,
        query_backend: Callable | None = None,
    ):
        self.embedder = SentenceTransformer(embed_model)
        self._chroma_path = chroma_path
        self._store_backend  = store_backend
        self._query_backend  = query_backend
        self._chroma_client  = None

    def _get_chroma(self):
        if self._chroma_client is None:
            import chromadb
            self._chroma_client = chromadb.PersistentClient(path=self._chroma_path)
        return self._chroma_client

    def index(self, collection_name: str, chunks: list[str]) -> None:
        """Embed chunks and store them."""
        embeddings = self.embedder.encode(chunks).tolist()

        if self._store_backend:
            self._store_backend(collection_name, chunks, embeddings)
            return

        # Default: ChromaDB
        client = self._get_chroma()
        try:
            client.delete_collection(collection_name)
        except Exception:
            pass
        col = client.create_collection(collection_name)
        col.add(
            documents=chunks,
            embeddings=embeddings,
            ids=[f"chunk_{i}" for i in range(len(chunks))],
        )

    def query(self, collection_name: str, query: str, top_k: int = 3) -> list[str]:
        """Retrieve top_k chunks most relevant to query."""
        query_embedding = self.embedder.encode([query]).tolist()

        if self._query_backend:
            return self._query_backend(collection_name, query_embedding, top_k)

        # Default: ChromaDB
        client = self._get_chroma()
        col     = client.get_collection(collection_name)
        results = col.query(query_embeddings=query_embedding, n_results=min(top_k, col.count()))
        return results["documents"][0]



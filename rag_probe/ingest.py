"""
Pluggable ingestion layer.

Default backend: Lexoid (STATIC_PARSE).
Swap by passing a custom ingestor callable: ingestor(path) -> str

Usage
-----
# Default (Lexoid)
from rag_probe.ingest import ingest
text = ingest("report.pdf")

# Custom — LlamaIndex
from rag_probe.ingest import llamaindex_ingestor
text = ingest("report.pdf", ingestor=llamaindex_ingestor)

# Custom — LangChain
from rag_probe.ingest import langchain_ingestor
text = ingest("report.pdf", ingestor=langchain_ingestor)

# Bring your own
text = ingest("report.pdf", ingestor=lambda path: my_parser(path))
"""

from typing import Callable


def _lexoid_ingest(path: str) -> str:
    from lexoid.api import parse
    result = parse(path, parser_type="STATIC_PARSE", url=path)
    return result.get("raw", "")


def llamaindex_ingestor(path: str) -> str:
    """
    Example adapter for LlamaIndex.
    Requires: uv pip install -e ".[llamaindex]"
    """
    from llama_index.core import SimpleDirectoryReader
    import os
    docs = SimpleDirectoryReader(input_files=[path]).load_data()
    return "\n\n".join(doc.text for doc in docs)


def langchain_ingestor(path: str) -> str:
    """
    Example adapter for LangChain.
    Requires: uv pip install -e ".[langchain]"
    """
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pdf":
        from langchain_community.document_loaders import PyPDFLoader
        loader = PyPDFLoader(path)
    elif ext in (".html", ".htm"):
        from langchain_community.document_loaders import UnstructuredHTMLLoader
        loader = UnstructuredHTMLLoader(path)
    else:
        from langchain_community.document_loaders import TextLoader
        loader = TextLoader(path)
    docs = loader.load()
    return "\n\n".join(doc.page_content for doc in docs)


import os  # noqa: E402 — used by langchain_ingestor above


def ingest(path: str, ingestor: Callable[[str], str] | None = None) -> str:
    """Extract text from a document. Uses Lexoid by default."""
    fn = ingestor or _lexoid_ingest
    return fn(path)


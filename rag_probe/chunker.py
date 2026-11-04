"""
Chunking strategies.

Usage
-----
from rag_probe.chunker import chunk

chunks = chunk(text, size=256, overlap=0.25)
"""


def chunk(text: str, size: int = 256, overlap: float = 0.0) -> list[str]:
    """
    Split text into overlapping chunks.

    Parameters
    ----------
    text    : extracted document text
    size    : approximate chunk size in tokens (1 token ≈ 4 chars)
    overlap : fraction of chunk size to repeat between consecutive chunks (0.0–0.5)
    """
    chunk_chars   = size * 4
    overlap_chars = int(chunk_chars * overlap)
    step          = chunk_chars - overlap_chars
    chunks        = []
    start         = 0
    while start < len(text):
        chunks.append(text[start : start + chunk_chars])
        start += step
    return chunks

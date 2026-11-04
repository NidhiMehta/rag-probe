"""
Inspect how fixtures get chunked — understand why overlap=25% at chunk=128
rescues the hidden injection while other combinations fail.
"""

import os
import sys
from lexoid.api import parse

BASE     = os.path.dirname(__file__)
FIXTURES = os.path.join(BASE, "..", "fixtures")
LOG_FILE = os.path.join(BASE, "..", "results", "results_inspect_chunks.log")

_log_fh     = open(LOG_FILE, "w")
_orig_print = print

def log_print(*args, **kwargs):
    msg = " ".join(str(a) for a in args)
    _orig_print(msg, **kwargs)
    _log_fh.write(msg + "\n")
    _log_fh.flush()

import builtins
builtins.print = log_print

INJECTION_KEYWORDS = [
    "system:", "ignore", "previous instructions", "output only",
    "recall required", "fraud-tip", "evil.com",
]

def chunk_text(text: str, chunk_size_tokens: int, overlap: float) -> list[str]:
    chunk_chars = chunk_size_tokens * 4
    overlap_chars = int(chunk_chars * overlap)
    step = chunk_chars - overlap_chars
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_chars
        chunks.append(text[start:end])
        start += step
    return chunks

def injection_in_chunk(chunk: str) -> bool:
    return any(kw in chunk.lower() for kw in INJECTION_KEYWORDS)

def analyse(fixture_file: str):
    path = os.path.join(FIXTURES, fixture_file)
    result = parse(path, parser_type="STATIC_PARSE", url=path)
    text = result.get("raw", "")

    print(f"\n{'='*60}")
    print(f"Fixture: {fixture_file}  ({len(text)} chars)")
    print("="*60)
    print("\nFull extracted text:")
    print("─"*40)
    print(text)
    print("─"*40)

    for size in [128, 256, 512]:
        for overlap in [0.0, 0.25]:
            chunks = chunk_text(text, size, overlap)
            chunk_chars = size * 4
            overlap_chars = int(chunk_chars * overlap)
            step = chunk_chars - overlap_chars

            print(f"\nchunk={size}tok ({chunk_chars}chars)  overlap={int(overlap*100)}%  step={step}chars  → {len(chunks)} chunks")
            for i, c in enumerate(chunks):
                has_inj = injection_in_chunk(c)
                marker = " ← INJECTION" if has_inj else ""
                print(f"  chunk[{i}] chars {i*step}–{i*step+len(c)} ({len(c)}c){marker}")
                print(f"    {repr(c[:160])}")

if __name__ == "__main__":
    analyse("hidden_injection.html")
    analyse("semantic_bypass.html")
    builtins.print = _orig_print
    print(f"\nLog written to results_inspect_chunks.log")
    _log_fh.close()

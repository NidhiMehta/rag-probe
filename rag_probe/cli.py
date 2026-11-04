"""
CLI entrypoint: rag-probe scan <document>

Usage
-----
rag-probe scan report.pdf
rag-probe scan report.pdf --out results/report.json
rag-probe scan report.pdf --chunk-size 256 --overlap 0.25 --ner
"""

from __future__ import annotations
import argparse
import os
import sys

from rag_probe.ingest import ingest
from rag_probe.chunker import chunk
from rag_probe.pipeline import Pipeline
from rag_probe import checks
from rag_probe.checks import injection, pii, poison, file_safety
from rag_probe.report import print_report, write_json, write_html


def scan_document(
    path: str,
    chunk_size: int = 256,
    overlap: float = 0.0,
    use_ner: bool = False,
    out: str | None = None,
) -> bool:
    """Scan a document. Returns True if safe, False if any check failed."""
    if not os.path.exists(path):
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    # 1. Ingest
    text = ingest(path)

    # 2. Chunk + embed for semantic checks
    chunks = chunk(text, size=chunk_size, overlap=overlap)
    pipeline = Pipeline()
    embeddings = pipeline.embedder.encode(chunks).tolist() if len(chunks) >= 2 else []

    # 3. Run checks
    results = []
    results += file_safety.scan(path)
    results += injection.scan(text, chunks if embeddings else None, embeddings or None)
    results.append(pii.scan(text, use_ner=use_ner))
    results += poison.scan(text, chunks if embeddings else None, embeddings or None)

    # 4. Report
    print_report(results, path)

    if out:
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        write_json(results, path, out)
        html_out = os.path.splitext(out)[0] + ".html"
        write_html(results, path, html_out)
        print(f"\n  JSON report : {out}")
        print(f"  HTML report : {html_out}")

    return all(r.passed for r in results)


def main():
    parser = argparse.ArgumentParser(
        prog="rag-probe",
        description="Document safety scanner for RAG pipelines",
    )
    sub = parser.add_subparsers(dest="command")

    scan_cmd = sub.add_parser("scan", help="Scan a document")
    scan_cmd.add_argument("document", help="Path to document to scan")
    scan_cmd.add_argument("--chunk-size", type=int, default=256, help="Chunk size in tokens (default 256)")
    scan_cmd.add_argument("--overlap",    type=float, default=0.0, help="Chunk overlap fraction 0.0–0.5 (default 0.0)")
    scan_cmd.add_argument("--ner",        action="store_true",     help="Enable NER-based PII detection (requires spaCy)")
    scan_cmd.add_argument("--out",        type=str, default=None,  help="Write JSON report to this path")

    args = parser.parse_args()

    if args.command == "scan":
        safe = scan_document(
            args.document,
            chunk_size=args.chunk_size,
            overlap=args.overlap,
            use_ner=args.ner,
            out=args.out,
        )
        sys.exit(0 if safe else 1)
    else:
        parser.print_help()
        sys.exit(0)

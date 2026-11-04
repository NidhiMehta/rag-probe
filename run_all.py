"""
Run all rag-probe research experiments in sequence.

Experiments:
  1. prompt_injection_test   — static extraction only (no LLM)
  2. e2e_injection_test      — attacks A-D + sanitizer (Lexoid → qwen2.5:3b)
  3. full_injection_test     — attacks A-F + naive/block sanitizer + LLM_PARSE
  4. advanced_injection_test — attacks G-K
  5. rag_chunking_test       — RAG survival across chunk sizes / overlaps
  6. inspect_chunks          — chunk boundary analysis

All logs written to results/. Run from the rag-probe directory:
  uv pip install -e ".[ollama,chroma]"
  python run_all.py
"""

import os
import sys
import subprocess
import json
from datetime import datetime

BASE    = os.path.dirname(__file__)
TESTS   = os.path.join(BASE, "tests")
RESULTS = os.path.join(BASE, "results")
PYTHON  = sys.executable

EXPERIMENTS = [
    {
        "id":     "01",
        "name":   "Static extraction — injection survival",
        "script": "prompt_injection_test.py",
        "log":    None,   # prints to stdout only
    },
    {
        "id":     "02",
        "name":   "E2E injection A-D + sanitizer",
        "script": "e2e_injection_test.py",
        "log":    "results.log",
    },
    {
        "id":     "03",
        "name":   "Full injection suite A-F + LLM_PARSE",
        "script": "full_injection_test.py",
        "log":    "results_full.log",
    },
    {
        "id":     "04",
        "name":   "Advanced attacks G-K",
        "script": "advanced_injection_test.py",
        "log":    "results_advanced.log",
    },
    {
        "id":     "05",
        "name":   "RAG chunking survival",
        "script": "rag_chunking_test.py",
        "log":    "results_rag.log",
    },
    {
        "id":     "06",
        "name":   "Chunk boundary analysis",
        "script": "inspect_chunks.py",
        "log":    "results_inspect_chunks.log",
    },
]


def run_experiment(exp: dict) -> dict:
    script = os.path.join(TESTS, exp["script"])
    print(f"\n{'='*60}")
    print(f"  [{exp['id']}] {exp['name']}")
    print(f"  script: {exp['script']}")
    print(f"{'='*60}")

    start = datetime.now()
    result = subprocess.run(
        [PYTHON, script],
        capture_output=False,
        text=True,
    )
    elapsed = (datetime.now() - start).total_seconds()

    status = "ok" if result.returncode == 0 else "error"
    log_path = os.path.join(RESULTS, exp["log"]) if exp["log"] else None

    print(f"\n  [{exp['id']}] finished in {elapsed:.1f}s — {status.upper()}")
    if log_path and os.path.exists(log_path):
        print(f"  log: {log_path}")

    return {
        "id":       exp["id"],
        "name":     exp["name"],
        "script":   exp["script"],
        "status":   status,
        "elapsed_s": round(elapsed, 1),
        "log":      log_path,
    }


def write_summary(runs: list[dict]) -> str:
    summary = {
        "run_at":      datetime.now().isoformat(),
        "total":       len(runs),
        "ok":          sum(1 for r in runs if r["status"] == "ok"),
        "error":       sum(1 for r in runs if r["status"] == "error"),
        "experiments": runs,
    }
    path = os.path.join(RESULTS, "run_all_summary.json")
    with open(path, "w") as f:
        json.dump(summary, f, indent=2)
    return path


if __name__ == "__main__":
    print("=" * 60)
    print("  rag-probe — run all experiments")
    print(f"  started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    runs = []
    for exp in EXPERIMENTS:
        row = run_experiment(exp)
        runs.append(row)

    summary_path = write_summary(runs)

    print(f"\n{'='*60}")
    print("  SUMMARY")
    print("=" * 60)
    for r in runs:
        status_label = "OK   " if r["status"] == "ok" else "ERROR"
        print(f"  [{status_label}]  {r['id']}. {r['name']}  ({r['elapsed_s']}s)")

    ok    = sum(1 for r in runs if r["status"] == "ok")
    error = sum(1 for r in runs if r["status"] == "error")
    print(f"\n  {ok}/{len(runs)} experiments completed successfully")
    print(f"  Summary written to: {summary_path}")
    print("=" * 60)

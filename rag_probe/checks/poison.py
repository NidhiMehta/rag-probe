"""
Data poisoning detection.

Signals:
  1. semantic_discontinuity  — abrupt topic shift between chunks (reuses injection.py)
  2. authority_assertion     — document claims to override or amend prior content
  3. statistical_anomaly     — numeric claims that are implausibly extreme
"""

from __future__ import annotations
import re
from rag_probe.checks.injection import CheckResult, semantic_discontinuity


# ── Authority assertion ───────────────────────────────────────────────────────

AUTHORITY_PATTERNS = [
    r"\bper (the )?amendment\b",
    r"\bthis (document|content|section) (has been |is )?(superseded|updated|amended)\b",
    r"\bmandatory (disclosure|notice|update)\b",
    r"\beffective immediately\b",
    r"\boverrides? (all |any )?(previous|prior|earlier)\b",
    r"\bautomated (processing|summary|review) systems?\b",
    r"\bai[\-\s]assisted\b",
    r"\bsection \d+\.\d+ of the\b",
    r"\bthis (requirement|directive|policy) applies to\b",
]

def authority_assertion(text: str) -> CheckResult:
    """
    Flag language that asserts authority over automated systems —
    a hallmark of semantic bypass attacks.
    """
    hits = []
    for pat in AUTHORITY_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            start = max(0, m.start() - 50)
            end   = min(len(text), m.end() + 50)
            hits.append(f"pattern '{pat}': ...{text[start:end].strip()}...")
    passed = len(hits) == 0
    return CheckResult(
        name="authority_assertion",
        passed=passed,
        score=float(len(hits)),
        detail=f"{len(hits)} authority assertion(s) found",
        findings=hits,
    )


# ── Statistical anomaly ───────────────────────────────────────────────────────

def statistical_anomaly(text: str) -> CheckResult:
    """
    Flag implausibly extreme numeric claims: percentages > 100%,
    temperatures outside plausible ranges, round numbers presented as precise findings.
    Heuristic — high false positive rate, use as a weak signal only.
    """
    hits = []

    # Percentages > 100
    for m in re.finditer(r"(\d+(?:\.\d+)?)\s*%", text):
        val = float(m.group(1))
        if val > 100:
            hits.append(f"percentage > 100%: {m.group()} at pos {m.start()}")

    # Very round large numbers presented as measurements (e.g. "exactly 1000000 cases")
    for m in re.finditer(r"\b(exactly|precisely|confirmed)\s+(\d{6,})\b", text, re.IGNORECASE):
        hits.append(f"suspiciously precise large number: '{m.group()}' at pos {m.start()}")

    passed = len(hits) == 0
    return CheckResult(
        name="statistical_anomaly",
        passed=passed,
        score=float(len(hits)),
        detail=f"{len(hits)} statistical anomaly flag(s)",
        findings=hits,
    )


# ── Combined scan ─────────────────────────────────────────────────────────────

def scan(
    text: str,
    chunks: list[str] | None = None,
    embeddings: list[list[float]] | None = None,
) -> list[CheckResult]:
    results = [
        authority_assertion(text),
        statistical_anomaly(text),
    ]
    if chunks and embeddings and len(chunks) >= 2:
        results.append(semantic_discontinuity(chunks, embeddings))
    return results

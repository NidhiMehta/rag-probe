"""
Prompt injection detection.

Four signals, each returns a CheckResult.
Run all four with: scan(text, chunks, embeddings)
"""

from __future__ import annotations
import re
import math
from dataclasses import dataclass, field


@dataclass
class CheckResult:
    name: str
    passed: bool
    score: float
    detail: str
    findings: list[str] = field(default_factory=list)


# ── 1. Invisible character ratio ─────────────────────────────────────────────

ZERO_WIDTH = ["​", "‌", "‍", "﻿", "­"]

def invisible_char_ratio(text: str, threshold: float = 0.01) -> CheckResult:
    """Flag documents where >1% of characters are invisible zero-width chars."""
    if not text:
        return CheckResult("invisible_char_ratio", True, 0.0, "empty document")
    count = sum(text.count(ch) for ch in ZERO_WIDTH)
    ratio = count / len(text)
    passed = ratio <= threshold
    return CheckResult(
        name="invisible_char_ratio",
        passed=passed,
        score=round(ratio, 4),
        detail=f"{count} zero-width chars out of {len(text)} total ({ratio*100:.2f}%)",
        findings=[f"zero-width char ratio {ratio*100:.2f}% exceeds threshold {threshold*100:.0f}%"] if not passed else [],
    )


# ── 2. Length inflation ───────────────────────────────────────────────────────

def length_inflation(text: str, threshold: float = 1.4) -> CheckResult:
    """
    Compare extracted length against expected length from visible word count.
    Visible words × 5 chars/word = expected. Ratio > threshold is suspicious.
    Strips zero-width chars to estimate visible content.
    """
    clean = text
    for ch in ZERO_WIDTH:
        clean = clean.replace(ch, "")
    visible_words = len(clean.split())
    expected_chars = visible_words * 5
    if expected_chars == 0:
        return CheckResult("length_inflation", True, 1.0, "no visible words")
    ratio = len(text) / expected_chars
    passed = ratio <= threshold
    return CheckResult(
        name="length_inflation",
        passed=passed,
        score=round(ratio, 3),
        detail=f"{len(text)} extracted chars, {expected_chars} expected from {visible_words} visible words (ratio {ratio:.2f}x)",
        findings=[f"extracted length is {ratio:.2f}x expected — possible hidden content"] if not passed else [],
    )


# ── 3. Semantic discontinuity ─────────────────────────────────────────────────

def semantic_discontinuity(
    chunks: list[str],
    embeddings: list[list[float]],
    threshold_sigma: float = 2.0,
) -> CheckResult:
    """
    Compute cosine distance between consecutive chunk embeddings.
    A spike > mean + threshold_sigma * std flags a semantic break — likely injection.
    """
    if len(chunks) < 2:
        return CheckResult("semantic_discontinuity", True, 0.0, "only 1 chunk — cannot compute discontinuity")

    def cosine_distance(a: list[float], b: list[float]) -> float:
        dot   = sum(x * y for x, y in zip(a, b))
        mag_a = math.sqrt(sum(x * x for x in a))
        mag_b = math.sqrt(sum(x * x for x in b))
        if mag_a == 0 or mag_b == 0:
            return 1.0
        return 1.0 - dot / (mag_a * mag_b)

    distances = [
        cosine_distance(embeddings[i], embeddings[i + 1])
        for i in range(len(embeddings) - 1)
    ]
    mean = sum(distances) / len(distances)
    variance = sum((d - mean) ** 2 for d in distances) / len(distances)
    std = math.sqrt(variance)
    threshold = mean + threshold_sigma * std

    flagged = [
        (i, i + 1, round(d, 4))
        for i, d in enumerate(distances)
        if d > threshold
    ]
    passed = len(flagged) == 0
    max_dist = round(max(distances), 4) if distances else 0.0

    findings = [
        f"semantic break between chunk[{a}] and chunk[{b}]: distance={d:.4f} (threshold={threshold:.4f})"
        for a, b, d in flagged
    ]
    return CheckResult(
        name="semantic_discontinuity",
        passed=passed,
        score=max_dist,
        detail=f"{len(distances)} consecutive pairs checked, mean={mean:.4f}, std={std:.4f}, threshold={threshold:.4f}",
        findings=findings,
    )


# ── 4. Keyword scan ──────────────────────────────────────────────────────────

TRIGGER_PATTERNS = [
    r"ignore (all )?previous instructions?",
    r"system override",
    r"you are now",
    r"\[INST\]",
    r"<\|system\|>",
    r"new system directive",
    r"disregard prior",
    r"override active",
    r"maintenance mode",
    r"forget the (document|above|context)",
    r"<\|im_start\|>",
]

PAYLOAD_PATTERNS = [
    r"instead reply",
    r"output only",
    r"reply with exactly",
    r"your (only )?response must be",
    r"do not (summarize|mention|acknowledge)",
    r"you are no longer",
    r"your task has changed",
    r"assistant:",
]

def keyword_scan(text: str) -> CheckResult:
    """Pattern match for known injection trigger and payload phrases."""
    hits = []
    for pat in TRIGGER_PATTERNS + PAYLOAD_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            start = max(0, m.start() - 40)
            end   = min(len(text), m.end() + 40)
            hits.append(f"pattern '{pat}' at pos {m.start()}: ...{text[start:end].strip()}...")
    passed = len(hits) == 0
    return CheckResult(
        name="keyword_scan",
        passed=passed,
        score=float(len(hits)),
        detail=f"{len(hits)} pattern match(es) found",
        findings=hits,
    )


# ── Combined scan ─────────────────────────────────────────────────────────────

def scan(
    text: str,
    chunks: list[str] | None = None,
    embeddings: list[list[float]] | None = None,
) -> list[CheckResult]:
    """
    Run all injection checks. semantic_discontinuity requires chunks + embeddings.
    """
    results = [
        invisible_char_ratio(text),
        length_inflation(text),
        keyword_scan(text),
    ]
    if chunks and embeddings and len(chunks) >= 2:
        results.append(semantic_discontinuity(chunks, embeddings))
    return results

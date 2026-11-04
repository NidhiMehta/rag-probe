"""
PII detection.

Regex-based by default (no model needed).
Optional NER via spaCy for names and org names: uv pip install -e ".[ner]"
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from rag_probe.checks.injection import CheckResult


PII_PATTERNS: dict[str, str] = {
    "email":       r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "phone_us":    r"\b(\+1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b",
    "ssn":         r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d[ \-]?){13,16}\b",
    "ip_address":  r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "passport":    r"\b[A-Z]{1,2}\d{6,9}\b",
    "iban":        r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b",
    "date_of_birth": r"\b(0?[1-9]|1[0-2])[\/\-](0?[1-9]|[12]\d|3[01])[\/\-](19|20)\d{2}\b",
}

@dataclass
class PIIFinding:
    pii_type: str
    value: str
    position: int
    context: str


def regex_scan(text: str) -> list[PIIFinding]:
    findings = []
    for pii_type, pattern in PII_PATTERNS.items():
        for m in re.finditer(pattern, text):
            start = max(0, m.start() - 30)
            end   = min(len(text), m.end() + 30)
            findings.append(PIIFinding(
                pii_type=pii_type,
                value=m.group(),
                position=m.start(),
                context=f"...{text[start:end].strip()}...",
            ))
    return findings


def ner_scan(text: str) -> list[PIIFinding]:
    """
    NER-based scan for names, orgs, locations.
    Requires: uv pip install -e ".[ner]" && python -m spacy download en_core_web_sm
    """
    try:
        import spacy
        nlp = spacy.load("en_core_web_sm")
    except (ImportError, OSError):
        return []

    doc = nlp(text)
    findings = []
    for ent in doc.ents:
        if ent.label_ in ("PERSON", "ORG", "GPE", "LOC"):
            start = max(0, ent.start_char - 30)
            end   = min(len(text), ent.end_char + 30)
            findings.append(PIIFinding(
                pii_type=ent.label_.lower(),
                value=ent.text,
                position=ent.start_char,
                context=f"...{text[start:end].strip()}...",
            ))
    return findings


def scan(text: str, use_ner: bool = False) -> CheckResult:
    """Run PII scan. Set use_ner=True to also detect names/orgs via spaCy."""
    findings = regex_scan(text)
    if use_ner:
        findings += ner_scan(text)

    passed = len(findings) == 0
    finding_strs = [
        f"[{f.pii_type}] '{f.value}' at pos {f.position}: {f.context}"
        for f in findings
    ]
    type_counts: dict[str, int] = {}
    for f in findings:
        type_counts[f.pii_type] = type_counts.get(f.pii_type, 0) + 1

    detail = ", ".join(f"{v} {k}" for k, v in type_counts.items()) if type_counts else "no PII found"
    return CheckResult(
        name="pii",
        passed=passed,
        score=float(len(findings)),
        detail=detail,
        findings=finding_strs,
    )

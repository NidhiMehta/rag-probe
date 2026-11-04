"""
File safety checks.

  1. pdf_javascript   — embedded JavaScript in PDF files
  2. docx_macros      — VBA macros in DOCX/XLSM/PPTM files
  3. zip_bomb         — decompression bomb in DOCX/ODT (ZIP-based formats)
  4. svg_script       — <script> tags in SVG files
"""

from __future__ import annotations
import os
import re
import zipfile
from dataclasses import dataclass, field
from rag_probe.checks.injection import CheckResult

ZIP_BOMB_RATIO     = 100    # flag if uncompressed > 100x compressed
ZIP_BOMB_MAX_MB    = 500    # flag if uncompressed > 500 MB


def pdf_javascript(path: str) -> CheckResult:
    """Detect embedded JavaScript actions in a PDF."""
    findings = []
    try:
        import pypdf
        reader = pypdf.PdfReader(path)
        # Check /JS and /JavaScript in page actions and document-level actions
        raw = open(path, "rb").read()
        hits = re.findall(rb"/JavaScript|/JS\s*\(|/JS\s*<<", raw)
        if hits:
            findings.append(f"found {len(hits)} JavaScript reference(s) in PDF structure")
        # Check named actions
        if b"/Launch" in raw:
            findings.append("found /Launch action in PDF — can execute external programs")
        if b"/SubmitForm" in raw:
            findings.append("found /SubmitForm action — can exfiltrate data")
    except ImportError:
        return CheckResult("pdf_javascript", True, 0.0, "pypdf not installed — skipped")
    except Exception as e:
        return CheckResult("pdf_javascript", False, 1.0, f"error reading PDF: {e}", [str(e)])

    passed = len(findings) == 0
    return CheckResult(
        name="pdf_javascript",
        passed=passed,
        score=float(len(findings)),
        detail=f"{len(findings)} JavaScript/action finding(s) in PDF",
        findings=findings,
    )


def docx_macros(path: str) -> CheckResult:
    """Detect VBA macros in Office Open XML files (docx, xlsx, pptx, etc.)."""
    findings = []
    ext = os.path.splitext(path)[1].lower()
    if ext not in (".docx", ".docm", ".xlsm", ".pptm", ".xlsx", ".pptx"):
        return CheckResult("docx_macros", True, 0.0, f"not an Office file ({ext}) — skipped")

    try:
        with zipfile.ZipFile(path, "r") as z:
            names = z.namelist()
            if any("vbaProject" in n for n in names):
                findings.append("vbaProject.bin found — file contains VBA macros")
            if any(n.endswith(".bin") and "macro" in n.lower() for n in names):
                findings.append("macro binary found in Office ZIP structure")
    except zipfile.BadZipFile:
        findings.append("file is not a valid ZIP/Office file — possible disguised format")
    except Exception as e:
        return CheckResult("docx_macros", False, 1.0, f"error reading file: {e}", [str(e)])

    passed = len(findings) == 0
    return CheckResult(
        name="docx_macros",
        passed=passed,
        score=float(len(findings)),
        detail=f"{len(findings)} macro finding(s)",
        findings=findings,
    )


def zip_bomb(path: str) -> CheckResult:
    """
    Detect decompression bombs in ZIP-based formats (docx, odt, etc.).
    Flags if: uncompressed / compressed > ZIP_BOMB_RATIO, or uncompressed > ZIP_BOMB_MAX_MB.
    """
    ext = os.path.splitext(path)[1].lower()
    if ext not in (".docx", ".docm", ".odt", ".xlsx", ".pptx", ".zip"):
        return CheckResult("zip_bomb", True, 0.0, f"not a ZIP-based file ({ext}) — skipped")

    findings = []
    try:
        compressed_size = os.path.getsize(path)
        with zipfile.ZipFile(path, "r") as z:
            uncompressed_size = sum(i.file_size for i in z.infolist())

        ratio = uncompressed_size / max(compressed_size, 1)
        uncompressed_mb = uncompressed_size / (1024 * 1024)

        if ratio > ZIP_BOMB_RATIO:
            findings.append(
                f"compression ratio {ratio:.0f}x exceeds threshold {ZIP_BOMB_RATIO}x "
                f"({compressed_size/1024:.1f} KB compressed → {uncompressed_mb:.1f} MB uncompressed)"
            )
        if uncompressed_mb > ZIP_BOMB_MAX_MB:
            findings.append(
                f"uncompressed size {uncompressed_mb:.1f} MB exceeds threshold {ZIP_BOMB_MAX_MB} MB"
            )
    except zipfile.BadZipFile:
        findings.append("file is not a valid ZIP — possible format spoofing")
    except Exception as e:
        return CheckResult("zip_bomb", False, 1.0, f"error reading file: {e}", [str(e)])

    passed = len(findings) == 0
    return CheckResult(
        name="zip_bomb",
        passed=passed,
        score=float(len(findings)),
        detail=f"{len(findings)} zip bomb indicator(s)",
        findings=findings,
    )


def svg_script(path: str) -> CheckResult:
    """Detect <script> tags in SVG files."""
    ext = os.path.splitext(path)[1].lower()
    if ext != ".svg":
        return CheckResult("svg_script", True, 0.0, f"not an SVG ({ext}) — skipped")

    findings = []
    try:
        content = open(path, "r", encoding="utf-8", errors="replace").read()
        matches = re.findall(r"<script[\s>]", content, re.IGNORECASE)
        if matches:
            findings.append(f"found {len(matches)} <script> tag(s) in SVG")
        if re.search(r"javascript\s*:", content, re.IGNORECASE):
            findings.append("found javascript: URI in SVG — can execute on render")
    except Exception as e:
        return CheckResult("svg_script", False, 1.0, f"error reading SVG: {e}", [str(e)])

    passed = len(findings) == 0
    return CheckResult(
        name="svg_script",
        passed=passed,
        score=float(len(findings)),
        detail=f"{len(findings)} script finding(s) in SVG",
        findings=findings,
    )


def scan(path: str) -> list[CheckResult]:
    """Run all file safety checks appropriate for the given file type."""
    ext = os.path.splitext(path)[1].lower()
    results = []
    if ext == ".pdf":
        results.append(pdf_javascript(path))
    if ext in (".docx", ".docm", ".xlsm", ".pptm", ".xlsx", ".pptx"):
        results.append(docx_macros(path))
        results.append(zip_bomb(path))
    if ext in (".odt", ".zip"):
        results.append(zip_bomb(path))
    if ext == ".svg":
        results.append(svg_script(path))
    if not results:
        results.append(CheckResult("file_safety", True, 0.0, f"no file safety checks for {ext}"))
    return results

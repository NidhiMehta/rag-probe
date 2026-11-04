"""
Unified scan report — terminal output + JSON file.
"""

from __future__ import annotations
import json
import os
from datetime import datetime
from rag_probe.checks.injection import CheckResult


def _symbol(passed: bool) -> str:
    return "PASS" if passed else "FAIL"


def print_report(results: list[CheckResult], document: str) -> None:
    width = 60
    print("=" * width)
    print(f"  rag-probe scan report")
    print(f"  document : {os.path.basename(document)}")
    print(f"  time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * width)

    for r in results:
        status = _symbol(r.passed)
        print(f"  [{status}]  {r.name:<30}  score={r.score}")
        print(f"         {r.detail}")
        for f in r.findings:
            print(f"         ! {f}")
    print("-" * width)

    failed = [r for r in results if not r.passed]
    if failed:
        print(f"  UNSAFE — {len(failed)}/{len(results)} check(s) failed")
        for r in failed:
            print(f"    • {r.name}")
    else:
        print(f"  SAFE — all {len(results)} check(s) passed")
    print("=" * width)


def write_json(results: list[CheckResult], document: str, output_path: str) -> None:
    data = {
        "document": document,
        "scanned_at": datetime.now().isoformat(),
        "overall": "SAFE" if all(r.passed for r in results) else "UNSAFE",
        "checks": [
            {
                "name":     r.name,
                "passed":   r.passed,
                "score":    r.score,
                "detail":   r.detail,
                "findings": r.findings,
            }
            for r in results
        ],
    }
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)


def write_html(results: list[CheckResult], document: str, output_path: str) -> None:
    """Generate a styled HTML scan report."""
    now       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    overall   = "SAFE" if all(r.passed for r in results) else "UNSAFE"
    failed    = [r for r in results if not r.passed]
    passed    = [r for r in results if r.passed]

    def check_row(r: CheckResult) -> str:
        status    = "pass" if r.passed else "fail"
        label     = "PASS" if r.passed else "FAIL"
        has_finds = bool(r.findings)
        toggle    = '<span class="check-toggle">▼</span>' if has_finds else ""
        findings_html = ""
        if has_finds:
            items = "\n".join(
                f'          <div class="finding">{_esc(f)}</div>' for f in r.findings
            )
            findings_html = f'        <div class="findings open">\n{items}\n        </div>'
        return f"""
      <div class="check">
        <div class="check-row" onclick="toggle(this)">
          <span class="check-icon {status}">{label}</span>
          <span class="check-name">{_esc(r.name)}</span>
          <span class="check-detail">{_esc(r.detail)}</span>
          <span class="check-score">{r.score}</span>
          {toggle}
        </div>
{findings_html}
      </div>"""

    checks_html = "\n".join(check_row(r) for r in results)

    overall_class = overall.lower()
    html = f"""<!doctype html>
<title>rag-probe · {_esc(os.path.basename(document))}</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap">
<style>
  :root {{
    --bg:#0d0f12;--bg2:#141720;--bg3:#1c2030;--border:#252a3a;
    --text:#c8cdd8;--muted:#5a6278;--accent:#4f8ef7;
    --pass:#2ea06a;--pass-bg:#0d2318;--pass-dim:#1a3d28;
    --fail:#e0504a;--fail-bg:#250d0c;--fail-dim:#3d1515;
    --warn:#e0a030;
    --mono:'IBM Plex Mono',monospace;--sans:'IBM Plex Sans',system-ui,sans-serif;
  }}
  @media(prefers-color-scheme:light){{:root:not([data-theme="dark"]){{
    --bg:#f5f6f8;--bg2:#fff;--bg3:#eef0f4;--border:#dde0e8;
    --text:#1a1e2c;--muted:#7a8299;--accent:#2563eb;
    --pass:#16803c;--pass-bg:#f0faf4;--pass-dim:#d1f5e0;
    --fail:#c0392b;--fail-bg:#fdf2f2;--fail-dim:#fcd8d6;--warn:#b45309;
  }}}}
  :root[data-theme="light"]{{
    --bg:#f5f6f8;--bg2:#fff;--bg3:#eef0f4;--border:#dde0e8;
    --text:#1a1e2c;--muted:#7a8299;--accent:#2563eb;
    --pass:#16803c;--pass-bg:#f0faf4;--pass-dim:#d1f5e0;
    --fail:#c0392b;--fail-bg:#fdf2f2;--fail-dim:#fcd8d6;--warn:#b45309;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;
    line-height:1.6;padding:0 16px;
    padding-block:env(safe-area-inset-top,0px) env(safe-area-inset-bottom,0px)}}
  .page{{max-width:920px;margin:0 auto;padding-block:48px 80px}}
  .header{{margin-bottom:36px;border-bottom:1px solid var(--border);padding-bottom:24px}}
  .header-top{{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap}}
  .tool-name{{font-family:var(--mono);font-size:11px;font-weight:600;letter-spacing:.12em;
    text-transform:uppercase;color:var(--accent);margin-bottom:8px}}
  h1{{font-size:24px;font-weight:600;letter-spacing:-.02em}}
  .header-meta{{font-size:12px;color:var(--muted);font-family:var(--mono);margin-top:6px}}
  .theme-btn{{background:var(--bg3);border:1px solid var(--border);color:var(--muted);
    font-family:var(--mono);font-size:11px;padding:6px 12px;border-radius:4px;cursor:pointer}}
  .theme-btn:hover{{color:var(--text)}}
  .summary-bar{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:32px}}
  .summary-card{{flex:1;min-width:130px;background:var(--bg2);border:1px solid var(--border);
    border-radius:6px;padding:14px 18px}}
  .summary-card .label{{font-family:var(--mono);font-size:10px;letter-spacing:.1em;
    text-transform:uppercase;color:var(--muted);margin-bottom:4px}}
  .summary-card .value{{font-size:22px;font-weight:600;font-family:var(--mono)}}
  .summary-card .sub{{font-size:11px;color:var(--muted);margin-top:2px}}
  .scan{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;
    margin-bottom:24px;overflow:hidden}}
  .scan-header{{display:flex;align-items:center;gap:14px;padding:16px 24px;
    border-bottom:1px solid var(--border);flex-wrap:wrap}}
  .scan-badge{{font-family:var(--mono);font-size:11px;font-weight:600;letter-spacing:.08em;
    padding:4px 10px;border-radius:3px;text-transform:uppercase;flex-shrink:0}}
  .scan-badge.unsafe{{background:var(--fail-dim);color:var(--fail)}}
  .scan-badge.safe{{background:var(--pass-dim);color:var(--pass)}}
  .scan-doc{{font-family:var(--mono);font-size:13px;word-break:break-all}}
  .scan-time{{font-size:11px;color:var(--muted);margin-left:auto;white-space:nowrap;font-family:var(--mono)}}
  .check{{border-bottom:1px solid var(--border)}}
  .check:last-child{{border-bottom:none}}
  .check-row{{display:flex;align-items:center;gap:12px;padding:10px 24px;cursor:pointer}}
  .check-row:hover{{background:var(--bg3)}}
  .check-icon{{font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.06em;
    padding:3px 8px;border-radius:3px;flex-shrink:0;min-width:44px;text-align:center}}
  .check-icon.pass{{background:var(--pass-bg);color:var(--pass)}}
  .check-icon.fail{{background:var(--fail-bg);color:var(--fail)}}
  .check-name{{font-family:var(--mono);font-size:12px;min-width:200px}}
  .check-detail{{font-size:12px;color:var(--muted);flex:1}}
  .check-score{{font-family:var(--mono);font-size:11px;color:var(--muted);white-space:nowrap}}
  .check-toggle{{font-family:var(--mono);font-size:10px;color:var(--muted);margin-left:8px}}
  .findings{{display:none;background:var(--bg3);border-top:1px solid var(--border);
    padding:12px 24px 12px 80px}}
  .findings.open{{display:block}}
  .finding{{font-family:var(--mono);font-size:11px;color:var(--warn);line-height:1.7;
    padding:3px 0;word-break:break-word}}
  .finding::before{{content:"! ";color:var(--fail)}}
</style>
<div class="page">
  <header class="header">
    <div class="header-top">
      <div>
        <div class="tool-name">rag-probe · document safety scanner</div>
        <h1>{_esc(os.path.basename(document))}</h1>
        <div class="header-meta">scanned {now}</div>
      </div>
      <button class="theme-btn" onclick="toggleTheme()">toggle theme</button>
    </div>
  </header>
  <div class="summary-bar">
    <div class="summary-card">
      <div class="label">overall</div>
      <div class="value" style="color:var(--{'pass' if overall=='SAFE' else 'fail'})">{overall}</div>
    </div>
    <div class="summary-card">
      <div class="label">checks failed</div>
      <div class="value" style="color:var(--fail)">{len(failed)}</div>
      <div class="sub">of {len(results)} total</div>
    </div>
    <div class="summary-card">
      <div class="label">checks passed</div>
      <div class="value" style="color:var(--pass)">{len(passed)}</div>
      <div class="sub">of {len(results)} total</div>
    </div>
  </div>
  <div class="scan">
    <div class="scan-header">
      <span class="scan-badge {overall_class}">{overall}</span>
      <span class="scan-doc">{_esc(document)}</span>
      <span class="scan-time">{now}</span>
    </div>
    <div class="checks">
{checks_html}
    </div>
  </div>
</div>
<script>
  function toggle(row) {{
    const f = row.nextElementSibling;
    const a = row.querySelector('.check-toggle');
    if (!f || !f.classList.contains('findings')) return;
    const open = f.classList.toggle('open');
    if (a) a.textContent = open ? '▼' : '▶';
  }}
  function toggleTheme() {{
    const r = document.documentElement;
    const c = r.getAttribute('data-theme');
    if (c === 'dark') r.setAttribute('data-theme','light');
    else if (c === 'light') r.removeAttribute('data-theme');
    else r.setAttribute('data-theme','dark');
  }}
</script>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

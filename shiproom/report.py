from __future__ import annotations

import html
import json
from pathlib import Path

from .public import public_release_view
from .registry import discover


def esc(value) -> str:
    return html.escape(str(value))


def render(release: dict, output: Path) -> Path:
    release = public_release_view(release, discover())
    release_id = esc(release.get("release_id", "missing"))
    verdict = esc(release.get("verdict", {}).get("status", "DRAFT"))
    promise = esc(release.get("product", {}).get("promise", ""))
    selection = release.get("manager_selection", {})
    selected = ", ".join(selection.get("selected_modules", [])) or "Pending Hermes manager selection"
    findings = "".join(
        f"<article><h3>{esc(f.get('title',''))}</h3><p>{esc(f.get('criterion_id',''))} · {esc(f.get('state',''))}</p><pre>{esc(json.dumps(f.get('evidence', []), indent=2))}</pre></article>"
        for f in release.get("findings", [])
    ) or "<p>No findings.</p>"
    decisions = "".join(
        f"<article><h3>{esc(d.get('title','Owner decision'))}</h3><p>{esc(d.get('choice') or 'Pending')} · {esc(d.get('resolution'))}</p></article>"
        for d in release.get("owner_decisions", [])
    ) or "<p>No owner decisions.</p>"
    checks = "".join(
        f"<article><h3>{esc(c.get('criterion_id','Check'))}</h3><p>HTTP {esc(c.get('status'))} · passed={esc(c.get('passed'))}</p><p>{esc(c.get('target',''))}</p></article>"
        for c in release.get("checks", [])
    ) or "<p>No checks.</p>"
    trace = esc(json.dumps({"release_id": release.get("release_id"), "public_artifacts": release.get("public_artifacts"), "native_ids": release.get("native_ids")}, indent=2))
    page = f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>
<title>Shiproom · {verdict}</title><style>
:root{{--ink:#13231d;--paper:#f5f2e9;--green:#175c44;--line:#cfcbbe}}*{{box-sizing:border-box}}
body{{margin:0;background:var(--paper);color:var(--ink);font:16px/1.5 system-ui,sans-serif}}main{{max-width:980px;margin:auto;padding:48px 24px}}
.eyebrow{{letter-spacing:.1em;text-transform:uppercase;font-weight:700;color:var(--green)}}h1{{font:700 clamp(46px,9vw,96px)/.95 Georgia,serif;margin:.2em 0}}
.verdict{{display:inline-block;padding:10px 16px;border:2px solid currentColor;border-radius:99px;font-weight:800}}section{{border-top:1px solid var(--line);padding:28px 0}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:18px}}article{{background:#fff;padding:20px;border:1px solid var(--line);border-radius:14px}}
details{{margin-top:32px}}pre{{overflow:auto;background:#10221b;color:#eaf4ef;padding:18px;border-radius:12px}}
</style></head><body><main data-release-id='{release_id}'><div class='eyebrow'>Shiproom release assurance · {release_id}</div><h1>{verdict}</h1><div class='verdict'>{verdict}</div>
<section><h2>Product promise</h2><p>{promise}</p></section><section><h2>Selected panel</h2><p>{esc(selected)}</p></section>
<section><h2>Evidence-backed findings</h2><div class='grid'>{findings}</div></section><section><h2>Owner decisions</h2><div class='grid'>{decisions}</div></section>
<section><h2>Before / after checks</h2><div class='grid'>{checks}</div></section><section><h2>Traceability</h2><pre>{trace}</pre></section>
</main></body></html>"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(page, encoding="utf-8")
    return output

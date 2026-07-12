from __future__ import annotations

import html
import json
from pathlib import Path


def render(release: dict, output: Path) -> Path:
    verdict = html.escape(str(release.get("verdict", {}).get("status", "DRAFT")))
    promise = html.escape(str(release.get("product", {}).get("promise", "")))
    selected = ", ".join(release.get("panel", {}).get("selected_modules", []))
    findings = "".join(
        f"<article><h3>{html.escape(f.get('title',''))}</h3><p>{html.escape(f.get('criterion_id',''))} · {html.escape(f.get('state',''))}</p></article>"
        for f in release.get("findings", [])
    ) or "<p>No findings.</p>"
    decisions = "".join(
        f"<article><h3>{html.escape(d.get('title','Owner decision'))}</h3><p>{html.escape(str(d.get('choice') or 'Pending'))}</p></article>"
        for d in release.get("owner_decisions", [])
    ) or "<p>No owner decisions.</p>"
    payload = html.escape(json.dumps(release, indent=2))
    page = f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>
<title>Shiproom · {verdict}</title><style>
:root{{--ink:#13231d;--paper:#f5f2e9;--green:#175c44;--red:#a63d2f;--line:#cfcbbe}}*{{box-sizing:border-box}}
body{{margin:0;background:var(--paper);color:var(--ink);font:16px/1.5 system-ui,sans-serif}}main{{max-width:980px;margin:auto;padding:48px 24px}}
.eyebrow{{letter-spacing:.14em;text-transform:uppercase;font-weight:700;color:var(--green)}}h1{{font:700 clamp(46px,9vw,96px)/.95 Georgia,serif;margin:.2em 0}}
.verdict{{display:inline-block;padding:10px 16px;border:2px solid currentColor;border-radius:99px;font-weight:800}}section{{border-top:1px solid var(--line);padding:28px 0}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:18px}}article{{background:#fff;padding:20px;border:1px solid var(--line);border-radius:14px}}
details{{margin-top:32px}}pre{{overflow:auto;background:#10221b;color:#eaf4ef;padding:18px;border-radius:12px}}
</style></head><body><main><div class='eyebrow'>Shiproom release assurance</div><h1>{verdict}</h1><div class='verdict'>{verdict}</div>
<section><h2>Product promise</h2><p>{promise}</p></section><section><h2>Selected panel</h2><p>{html.escape(selected)}</p></section>
<section><h2>Evidence-backed findings</h2><div class='grid'>{findings}</div></section><section><h2>Owner decisions</h2><div class='grid'>{decisions}</div></section>
<details><summary>Canonical release object</summary><pre>{payload}</pre></details></main></body></html>"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(page, encoding="utf-8")
    return output


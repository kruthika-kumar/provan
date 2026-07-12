from __future__ import annotations

import html
from pathlib import Path

from .view import release_run_view


def esc(value) -> str: return html.escape(str(value if value is not None else ""))


def render(release: dict, output: Path, *, events: list[dict] | None = None, audience: str = "all") -> Path:
    if audience not in {"all", "ceo", "product", "engineering"}: raise ValueError("unsupported report audience")
    view = release_run_view(release, events)
    selected_summary = ", ".join(view["manager_selection"]["selected_modules"]) or "None yet"
    cards = f"<p class='module-summary'>Selected modules: {esc(selected_summary)}</p>" + "".join(f"<article class='module {esc(m['status'])}'><p class='status'>{esc(m['status']).upper()}</p><h3>{esc(m['name'])}</h3><p>{esc(m['reason'])}</p></article>" for m in view["module_cards"])
    counts = "".join(f"<article><strong>{value}</strong><span>{esc(label.replace('_',' '))}</span></article>" for label, value in view["evidence_counts"].items())
    findings = "".join(_finding(f) for f in view["findings"]) or "<p>No material findings recorded.</p>"
    checks = "".join(_check(c) for c in view["checks"]) or "<p>No deterministic checks recorded.</p>"
    decisions = "".join(f"<article><h3>{esc(d.get('title','Owner decision'))}</h3><p>{esc(d.get('choice') or 'Pending')} — {esc(d.get('resolution') or 'unresolved')}</p></article>" for d in view["owner_decisions"]) or "<p>No owner decision required.</p>"
    timeline = "".join(_event(e) for e in view["run"]["events"]) or "<p>No event timeline is available for this legacy controlled run.</p>"
    role_sections = []
    if audience in {"all", "ceo"}: role_sections.append(_ceo(view, findings, decisions))
    if audience in {"all", "product"}: role_sections.append(_product(view))
    if audience in {"all", "engineering"}: role_sections.append(_engineering(view, checks))
    selected = set(view["manager_selection"]["selected_modules"])
    if audience == "all" and "design" in selected: role_sections.append("<section><h2>Design lead</h2><p>Design and accessibility review was selected. See its evidence and timeline entries below.</p></section>")
    if audience == "all" and "data" in selected: role_sections.append("<section><h2>Data / AI lead</h2><p>Data and AI review was selected. Model-reviewed evidence remains visually distinct from deterministic proof.</p></section>")
    before_after = _before_after(view)
    page = f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'><title>Shiproom · {esc(view['verdict'].get('status','DRAFT'))}</title><style>
:root{{--ink:#14231d;--paper:#f3f0e6;--card:#fff;--green:#175c44;--red:#922f2f;--amber:#936515;--muted:#64706a;--line:#cbc8bc}}*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:16px/1.5 system-ui,sans-serif}}main{{max-width:1120px;margin:auto;padding:42px 24px}}h1{{font:700 clamp(42px,8vw,86px)/.95 Georgia,serif;margin:.15em 0}}h2{{font:700 30px Georgia,serif}}h3,p,code{{overflow-wrap:anywhere}}section{{border-top:1px solid var(--line);padding:28px 0}}.eyebrow,.status{{letter-spacing:.1em;text-transform:uppercase;font-weight:800;color:var(--green)}}.verdict{{display:inline-block;border:2px solid;padding:8px 14px;border-radius:999px;font-weight:800}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;align-items:stretch}}.grid article{{min-width:0;height:100%}}.module-summary{{grid-column:1/-1;margin:0 0 4px}}article{{background:var(--card);padding:18px;border:1px solid var(--line);border-radius:12px}}.counts strong{{display:block;font:700 34px Georgia}}.counts span{{text-transform:capitalize}}.module{{border-top:7px solid var(--green)}}.module.skipped{{border-top-color:var(--muted)}}.module.failed{{border-top-color:var(--red)}}.module.revised{{border-top-color:var(--amber)}}.flow text{{font:600 13px system-ui}}.flow .node{{fill:#fff;stroke:#175c44;stroke-width:2}}.lane{{display:grid;grid-template-columns:130px minmax(0,1fr);gap:14px;margin:8px 0}}.lane time{{color:var(--muted)}}.evidence-model_reviewed{{border-left:7px solid var(--amber)}}.evidence-deterministically_verified{{border-left:7px solid var(--green)}}.evidence-missing_evidence{{border-left:7px solid var(--red)}}.disclaimer{{padding:14px;border:1px solid var(--amber);background:#fff8df}}code{{word-break:break-word}}</style></head><body><main data-release-id='{esc(view['release_id'])}'><header><p class='eyebrow'>Shiproom · {esc(view['mode'])}</p><h1>{esc(view['product'].get('name'))}</h1><p>{esc(view['product'].get('promise'))}</p><p class='verdict'>{esc(view['verdict'].get('status','DRAFT'))}</p><p>Release <code>{esc(view['release_id'])}</code> · Duration {esc(view['run']['duration_seconds'])}s · Human intervention {esc(view['run']['human_intervention'])} · Cost {esc(view['run']['estimated_cost'])}</p>{f"<p class='disclaimer'>{esc(view['disclaimer'])}</p>" if view['disclaimer'] else ''}</header><section><h2>Evidence accounting</h2><div class='grid counts'>{counts}</div></section><section><h2>Agency flow</h2>{_flow(view)}<div class='grid'>{cards}</div></section>{''.join(role_sections)}{before_after}<section><h2>Swimlane timeline</h2>{timeline}</section><section><h2>Traceability</h2><p>Repository: <code>{esc(view['repository'].get('url'))}</code></p><p>Commit: <code>{esc(view['repository'].get('commit_sha') or 'unavailable')}</code></p><p>Deployment: <code>{esc(view['deployment'].get('url'))}</code></p><p>GitHub: {esc(view['public_native_ids'])}</p></section></main></body></html>"""
    output.parent.mkdir(parents=True, exist_ok=True); output.write_text(page, encoding="utf-8"); return output


def _flow(view):
    labels = ["Release contract", "Release manager", "Reviewers", "Evidence gate", view["verdict"].get("status", "Verdict")]
    nodes = "".join(f"<rect class='node' x='{10+i*190}' y='20' width='155' height='55' rx='10'/><text x='{87+i*190}' y='53' text-anchor='middle'>{esc(label)}</text>" for i,label in enumerate(labels))
    edges = "".join(f"<path d='M {165+i*190} 47 L {200+i*190} 47' stroke='#175c44' stroke-width='3'/><text x='{182+i*190}' y='38' text-anchor='middle'>→</text>" for i in range(4))
    return f"<svg class='flow' role='img' aria-label='Release contract to manager to reviewers to evidence gate to verdict' viewBox='0 0 930 95' width='100%'>{nodes}{edges}</svg>"


def _finding(f):
    evidence = f.get("evidence", []); status = evidence[-1].get("status", "agent_reported") if evidence else "missing_evidence"
    return f"<article class='evidence-{esc(status)}'><p class='status'>{esc(status).replace('_',' ')}</p><h3>{esc(f.get('title'))}</h3><p>{esc(f.get('criterion_id'))} · {esc(f.get('state'))}</p></article>"


def _check(c): return f"<article class='evidence-{esc(c.get('evidence_status','missing_evidence'))}'><p class='status'>{esc(c.get('evidence_status','missing evidence')).replace('_',' ')}</p><h3>{esc(c.get('criterion_id','Check'))}</h3><p>Status {esc(c.get('status', c.get('exit_code','unavailable')))} · passed={esc(c.get('passed'))}</p><code>{esc(c.get('target',''))}</code></article>"
def _event(e):
    parent = f" (parent {esc(e.get('parent_event_id'))})" if e.get("parent_event_id") else ""
    lane = (e.get("module_id") or e.get("agent_id") or "Evidence Gate").title()
    return f"<div class='lane'><strong>{esc(lane)}</strong><div><time>{esc(e.get('timestamp'))}</time><br>{esc(e.get('event_type')).replace('_',' ')} — {esc(e.get('status'))}{parent}</div></div>"
def _ceo(v, findings, decisions): return f"<section><h2>CEO view</h2><p>Verdict: <strong>{esc(v['verdict'].get('status'))}</strong>. Verified blockers: {v['evidence_counts']['verified_blockers']}. Missing required evidence: {v['evidence_counts']['missing_required_evidence']}.</p><div class='grid'>{findings}{decisions}</div></section>"
def _product(v): return f"<section><h2>Product lead</h2><h3>Promise</h3><p>{esc(v['product'].get('promise'))}</p><h3>Target user</h3><p>{esc(v['product'].get('target_user'))}</p><h3>Critical journey</h3><ol>{''.join(f'<li>{esc(x)}</li>' for x in v['product'].get('critical_journey',[]))}</ol><h3>Non-goals</h3><p>{esc(', '.join(v['product'].get('non_goals',[])))}</p></section>"
def _engineering(v, checks): return f"<section><h2>Engineering lead</h2><p>Repository {esc(v['repository'].get('url'))} · branch {esc(v['repository'].get('base_branch') or 'unavailable')} · commit {esc(v['repository'].get('commit_sha') or 'unavailable')}</p><div class='grid'>{checks}</div></section>"
def _before_after(v):
    if v["mode"] == "external" or not v["remediation"]: return ""
    statuses = [c.get("status") for c in v["checks"]]
    if 404 not in statuses or 200 not in statuses: return ""
    closed = any(f.get("state") == "CLOSED" for f in v["findings"]); accepted = any(d.get("resolution") == "accepted_condition" for d in v["owner_decisions"])
    return f"<section><h2>Controlled-demo before / after</h2><div class='grid'><article><h3>Before</h3><p>HTTP 404</p></article><article><h3>After</h3><p>HTTP 200</p></article><article><h3>Closure</h3><p>Finding closed: {closed}</p><p>Owner condition accepted: {accepted}</p></article></div></section>"

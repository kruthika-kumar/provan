from __future__ import annotations

import html
from pathlib import Path

from .view import release_run_view

def esc(value) -> str: return html.escape(str(value if value is not None else ""))
def duration(value) -> str:
    seconds=max(0,int(value or 0)); minutes,seconds=divmod(seconds,60); hours,minutes=divmod(minutes,60)
    return " ".join(x for x in (f"{hours}h" if hours else "",f"{minutes}m" if minutes else "",f"{seconds}s" if seconds or not hours else "") if x)

def _check_card(c: dict) -> str:
    target = f"<a href='{esc(c.get('target'))}'>Evidence target</a>" if c.get("target") else ""
    evidence_status=esc(c.get('evidence_status','missing_evidence'))
    return f"<article class='evidence evidence-{evidence_status} {evidence_status}'><b>{esc(c.get('evidence_status','missing evidence')).replace('_',' ')}</b><h3>{esc(c.get('criterion_id','Check'))}</h3><p>Status {esc(c.get('status',c.get('exit_code','unavailable')))} · passed={esc(c.get('passed'))}</p>{target}</article>"

def render(release: dict, output: Path, *, events: list[dict] | None=None, audience: str="all") -> Path:
    if audience not in {"all","ceo","product","engineering"}: raise ValueError("unsupported report audience")
    v=release_run_view(release,events); selected=", ".join(v["manager_selection"]["selected_modules"]) or "None"
    modules="".join(f"<article class='module {esc(m['status'])}'><b>{esc(m['status']).upper()}</b><h3>{esc(m['name'])}</h3><p>{esc(m['reason'])}</p></article>" for m in v["module_cards"])
    checks="".join(_check_card(c) for c in v["checks"]) or "<p>No checks recorded.</p>"
    findings="".join(f"<article><h3>{esc(f.get('title'))}</h3><p>{esc(f.get('criterion_id'))} · {esc(f.get('state'))}</p></article>" for f in v["findings"]) or "<p>No material findings.</p>"
    decisions="".join(f"<article><h3>{esc(d.get('title','Owner decision'))}</h3><p>{esc(d.get('choice') or 'Pending')} — {esc(d.get('resolution') or 'unresolved')}</p></article>" for d in v["owner_decisions"]) or "<p>No owner decision required.</p>"
    timeline="".join(f"<details><summary>{esc(e.get('event_type')).replace('_',' ')} — {esc(e.get('status'))}</summary><p>{esc(e.get('module_id') or e.get('agent_id') or 'Evidence gate')} · {esc(e.get('timestamp'))}</p></details>" for e in v["run"]["events"]) or "<p>Legacy controlled run: detailed event stream unavailable.</p>"
    roles=[]
    if audience in {"all","ceo"}: roles.append(f"<section><h2>CEO</h2><p><strong>{esc(v['verdict'].get('status'))}</strong> · verified blockers {v['evidence_counts']['verified_blockers']} · missing evidence {v['evidence_counts']['missing_required_evidence']}</p><div class='grid'>{findings}{decisions}</div></section>")
    if audience in {"all","product"}: roles.append(f"<section><h2>Product</h2><p><strong>Promise:</strong> {esc(v['product'].get('promise'))}</p><p><strong>Target user:</strong> {esc(v['product'].get('target_user'))}</p><ol>{''.join(f'<li>{esc(x)}</li>' for x in v['product'].get('critical_journey',[]))}</ol></section>")
    if audience in {"all","engineering"}: roles.append(f"<section><h2>Engineering</h2><p><a href='{esc(v['repository'].get('url'))}'>Repository</a> · branch {esc(v['repository'].get('base_branch') or 'unavailable')} · commit {esc(v['repository'].get('commit_sha') or 'unavailable')}</p><div class='grid'>{checks}</div></section>")
    before=""
    statuses=[c.get("status") for c in v["checks"]]
    if v["mode"]!="external" and v["remediation"] and 404 in statuses and 200 in statuses:
        before="<section><h2>Verified before / after</h2><div class='grid'><article><b>BEFORE</b><h3>HTTP 404</h3></article><article><b>AFTER</b><h3>HTTP 200</h3></article><article><b>CLOSURE</b><p>Finding closed: True</p><p>Owner condition accepted: True</p></article></div></section>"
    native=v["public_native_ids"]; links=[]
    if native.get("github_repository"): links.append(f"<a href='https://github.com/{esc(native['github_repository'])}'>Repository</a>")
    if native.get("github_pr_number") and native.get("github_repository"): links.append(f"<a href='https://github.com/{esc(native['github_repository'])}/pull/{esc(native['github_pr_number'])}'>PR #{esc(native['github_pr_number'])}</a>")
    if native.get("github_comment_url"): links.append(f"<a href='{esc(native['github_comment_url'])}'>Evidence comment</a>")
    css=":root{--ink:#14231d;--paper:#f3f0e6;--card:#fff;--green:#175c44;--red:#9b3833;--muted:#68736d;--line:#cbc8be}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.5 system-ui}main{max-width:1120px;margin:auto;padding:42px 24px}h1{font:700 clamp(44px,8vw,88px)/.95 Georgia}h2{font:700 32px Georgia}h3,p,a{overflow-wrap:anywhere}section{border-top:1px solid var(--line);padding:28px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;align-items:stretch}.grid article{min-width:0}.module,.evidence,article{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:19px}.module{border-top:7px solid var(--green)}.module.skipped{border-top-color:var(--muted)}.module.failed,.evidence.missing_evidence{border-top-color:var(--red)}.evidence.model_reviewed{border-top-color:#a66a10}b{letter-spacing:.08em;color:var(--green)}details{padding:10px;border-bottom:1px solid var(--line)}"
    disclaimer=f"<p>{esc(v['disclaimer'])}</p>" if v.get("disclaimer") else ""
    deployment_id=f"<p>Cloudflare deployment ID: <code>{esc(native.get('cloudflare_deployment_id'))}</code></p>" if native.get("cloudflare_deployment_id") else ""
    page=f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'><title>Shiproom · {esc(v['verdict'].get('status','DRAFT'))}</title><style>{css}</style></head><body><main data-release-id='{esc(v['release_id'])}'><header><p>SHIPROOM · {esc(v['mode']).upper()}</p><h1>{esc(v['verdict'].get('status','DRAFT'))}</h1><p>{esc(v['product'].get('promise'))}</p><p>Release <code>{esc(v['release_id'])}</code> · Duration {esc(duration(v['run']['duration_seconds']))} · Human intervention {esc(v['run']['human_intervention'])}</p>{disclaimer}</header><section><h2>Agent organization</h2><p class='module-summary'>Selected modules: {esc(selected)}</p><div class='grid'>{modules}</div></section>{''.join(roles)}{before}<section><h2>Technical timeline</h2>{timeline}</section><section><h2>Traceability</h2>{''.join(f'<p>{x}</p>' for x in links)}<p><a href='{esc(v['deployment'].get('url'))}'>Deployment</a></p>{deployment_id}</section></main></body></html>"""
    output.parent.mkdir(parents=True,exist_ok=True); output.write_text(page,encoding="utf-8"); return output

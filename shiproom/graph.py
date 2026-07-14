from __future__ import annotations

import hashlib, json, os, posixpath, re, uuid
from pathlib import Path
from typing import Any

from .authority import LocalExecutionContext
from .intent import load_graph_input
from .project import canonical_json, content_hash

GRAPH_SCHEMA="requirement-evidence-graph.v1"; SUMMARY_SCHEMA="criterion-evidence-summary.v1"; GAPS_SCHEMA="evidence-gaps.v1"
PACKET_SCHEMA="evidence-mapping-source-packet.v1"; PROPOSAL_SCHEMA="evidence-mapping-proposal.v1"; MANIFEST_SCHEMA="requirement-evidence-graph-manifest.v1"; POINTER_SCHEMA="requirement-evidence-graph-current-generation.v1"
COMPILER_VERSION="requirement-evidence-graph.v2"; LIMIT=256*1024
ARTIFACTS=("requirement-evidence-graph.json","criterion-evidence-summary.json","evidence-gaps.json")
NODE_TYPES={"source","requirement","acceptance_criterion","critical_journey","implementation_reference","test_reference","instrumentation_reference","runtime_evidence","finding","owner_decision","remediation_plan","closure_evidence"}
CLASSIFICATIONS={"deterministically_established","source_backed","model_mapped_candidate","owner_confirmed","missing","not_inspected"}
SLOT_TYPES={"implementation":"implementation_reference","test":"test_reference","instrumentation":"instrumentation_reference","runtime":"runtime_evidence"}
RELATIONSHIPS={
 "supports_requirement":({"source"},{"requirement"},{"source_backed"}),"supports_acceptance_criterion":({"source"},{"acceptance_criterion"},{"source_backed"}),"decomposes_into":({"requirement"},{"acceptance_criterion"},{"deterministically_established"}),"affects_critical_journey":({"requirement"},{"critical_journey"},{"deterministically_established","source_backed"}),"may_be_implemented_by":({"acceptance_criterion"},{"implementation_reference"},{"model_mapped_candidate","not_inspected","missing","deterministically_established"}),"may_be_verified_by":({"acceptance_criterion"},{"test_reference"},{"model_mapped_candidate","not_inspected","missing","deterministically_established"}),"may_be_observed_by":({"acceptance_criterion"},{"instrumentation_reference"},{"model_mapped_candidate","not_inspected","missing","deterministically_established"}),"has_runtime_evidence":({"acceptance_criterion"},{"runtime_evidence"},{"model_mapped_candidate","not_inspected","missing","deterministically_established"}),"concerns_criterion":({"finding"},{"acceptance_criterion"},{"model_mapped_candidate","not_inspected","deterministically_established"}),"supported_by_evidence":({"finding"},{"source","runtime_evidence","test_reference","instrumentation_reference"},{"source_backed","deterministically_established"}),"requires_owner_decision":({"finding"},{"owner_decision"},{"not_inspected","deterministically_established"}),"resolved_or_conditioned_by":({"owner_decision"},{"finding"},{"owner_confirmed","deterministically_established"}),"addressed_by":({"finding"},{"remediation_plan"},{"not_inspected","deterministically_established"}),"requires_closure_evidence":({"finding","remediation_plan"},{"closure_evidence"},{"not_inspected","missing","deterministically_established"}),"closes":({"closure_evidence"},{"finding"},{"deterministically_established"}),"fails_to_close":({"closure_evidence"},{"finding"},{"deterministically_established"}),"maps_to_critical_journey":({"acceptance_criterion"},{"critical_journey"},{"model_mapped_candidate"})}
ROUTES={"http":"runtime","browser":"runtime","deployment":"runtime","test":"test","instrumentation":"instrumentation","event_verification":"instrumentation"}

def _id(prefix:str,value:Any)->str:return prefix+"_"+hashlib.sha256(canonical_json(value).encode()).hexdigest()[:16]
def _hash(data:bytes)->str:return "sha256:"+hashlib.sha256(data).hexdigest()
def _normal(v:str)->str:return re.sub(r"\s+"," ",v.removeprefix("\ufeff").replace("\r\n","\n").replace("\r","\n").strip())
def _sort(v:list[Any])->list[Any]:return [json.loads(x) for x in sorted({canonical_json(x) for x in v})]
def _root(ctx):return ctx.repository_root/".shiproom"/"local"/"releases"/ctx.release["release_id"]/"requirement-evidence-graph"
def _authority(ctx):return {k:ctx.authority_binding[k] for k in ("project_id","contract_hash","contract_source","authority_policy_version")}
def _atomic(path:Path,obj:dict):
 path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_name(path.name+"."+uuid.uuid4().hex+".tmp"); tmp.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+"\n",encoding="utf-8"); os.replace(tmp,path)
def _node(kind:str, identity:Any, **fields:Any)->dict:
 if kind not in NODE_TYPES:raise ValueError("invalid node type")
 nid=identity if kind in {"requirement","acceptance_criterion"} else _id(kind,identity)
 return {"node_id":nid,"node_type":kind,"provenance":fields.pop("provenance"),**fields}
def _edge(nodes,src,tgt,name,classification,rationale,origin,refs=None):
 allowed=RELATIONSHIPS.get(name)
 if not allowed or src not in nodes or tgt not in nodes or nodes[src]["node_type"] not in allowed[0] or nodes[tgt]["node_type"] not in allowed[1] or classification not in allowed[2]:raise ValueError("invalid graph relationship")
 body={"source_node_id":src,"target_node_id":tgt,"relationship":name,"establishment_classification":classification,"rationale":rationale,"origin":origin,"references":_sort(refs or [])}
 return {"edge_id":_id("edge",body),**body}

def _safe_check(c,index,seed):
 cid=c.get("check_id") or _id("check",{"projection":seed,"index":index,"criterion":c.get("criterion_id"),"type":c.get("type"),"target":c.get("target"),"status":c.get("status")})
 keys=("criterion_id","type","target","status","passed","evidence_status","runtime_outcome","error_type","granted_path","deployment_grant_hash","rerun_of","result","command_id","evidence_kind")
 return {k:c[k] for k in keys if k in c}|{"check_id":cid,"original_index":index}
def _projection(ctx):
 r=ctx.release; dep=r.get("deployment",{}); safe_dep={"origin":ctx.deployment_grant.get("origin"),"allowed_paths":ctx.deployment_grant.get("allowed_paths"),"grant_hash":ctx.authority_binding.get("deployment_grant_hash")}
 raw={"release_id":r["release_id"],"repository_commit":ctx.authority_binding["repository_commit"],"project_authority":_authority(ctx),"deployment":safe_dep,"product":{k:r.get("product",{}).get(k) for k in ("critical_journey","promise","target_user")},"owner_constraints":r.get("owner_constraints",[]),"checks":r.get("checks",[]),"findings":r.get("findings",[]),"owner_decisions":[{k:v for k,v in d.items() if k not in {"recorded_at","created_at","updated_at"}} for d in r.get("owner_decisions",[])],"remediation_tasks":r.get("remediation_tasks",[]),"runtime_artifacts":r.get("runtime_artifacts",[]),"state":r.get("state"),"verdict":r.get("verdict",{})}
 digest=content_hash(raw); checks=[_safe_check(c,i,digest) for i,c in enumerate(r.get("checks",[]))]
 return {"release_id":r["release_id"],"release_projection_hash":digest,"deployment":safe_dep,"checks":checks,"findings":r.get("findings",[]),"owner_decisions":raw["owner_decisions"],"remediation_tasks":r.get("remediation_tasks",[]),"runtime_artifacts":r.get("runtime_artifacts",[],),"state":r.get("state"),"verdict":r.get("verdict",{})},digest
def _binding(ctx):
 im,ia,ip=load_graph_input(ctx); projection,digest=_projection(ctx); return im,ia,ip,projection,digest

def _locators(text):return [{"start_line":i,"end_line":i,"quote_hash":_hash(line.encode())} for i,line in enumerate(text.split("\n"),1)]
def _packet_expected(ctx,paths):
 im,ia,ip,p,ph=_binding(ctx); selected=[]; seen=set()
 for value in paths:
  if not isinstance(value,str):raise ValueError("invalid mapping path")
  path=posixpath.normpath(value.replace("\\","/"))
  if not path or path.startswith("/") or ".." in Path(path).parts or path.casefold() in seen:raise ValueError("invalid or duplicate mapping path")
  seen.add(path.casefold()); blob=ctx.read_release_blob(path,byte_limit=LIMIT)
  if blob["classification"]!="text" or blob["text"] is None:raise ValueError("mapping source must be UTF-8 text")
  if any(x["returned_git_path"].casefold()==blob["path"].casefold() for x in selected):raise ValueError("mapping paths resolve to same committed path")
  text=blob["text"].removeprefix("\ufeff").replace("\r\n","\n").replace("\r","\n"); selected.append({"path":blob["path"],"returned_git_path":blob["path"],"git_blob_hash":blob["blob_hash"],"normalized_text_hash":_hash(text.encode()),"text":text,"locators":_locators(text)})
 journeys=[{"journey_id":_id("journey",{"intent":im["semantic_bundle_hash"],"text":_normal(x)}),"journey_text":_normal(x)} for x in ia["product-intent.json"].get("release_scope",[])]
 checks=p["checks"]; runtime=[{"runtime_evidence_id":_id("runtime",c),"check_id":c["check_id"],"type":c.get("type"),"target":c.get("target"),"granted_path":c.get("granted_path"),"status":c.get("status"),"evidence_status":c.get("evidence_status"),"original_index":c["original_index"]} for c in checks if c.get("type") in {"http","browser","deployment"}]
 out={"schema_version":PACKET_SCHEMA,"release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],"project_authority":_authority(ctx),"product_intent_semantic_bundle_hash":im["semantic_bundle_hash"],"product_intent_source_packet_hash":im["source_packet_hash"],"release_projection_hash":ph,"requirement_ids":sorted(x["requirement_id"] for x in ia["requirements.json"]["requirements"]),"criterion_ids":sorted(x["criterion_id"] for x in ia["acceptance-criteria.json"]["criteria"]),"critical_journeys":sorted(journeys,key=canonical_json),"canonical_checks":checks,"canonical_runtime_evidence":runtime,"canonical_findings":sorted(p["findings"],key=canonical_json),"selected_sources":sorted(selected,key=lambda x:x["path"]),"coverage_boundary":"Only explicitly selected commit-pinned files; no discovery.","packet_hash":""}; out["packet_hash"]=content_hash({k:v for k,v in out.items() if k!="packet_hash"}); return out
def mapping_prepare(ctx,paths):ctx.require("file.read"); packet=_packet_expected(ctx,paths); _atomic(_root(ctx)/"mapping-source-packet.json",packet); (_root(ctx)/"inbox").mkdir(parents=True,exist_ok=True); return packet
def _load_mapping_packet(ctx):
 path=_root(ctx)/"mapping-source-packet.json"
 if not path.exists():return None,None
 if path.is_symlink() or not path.is_file():raise ValueError("mapping packet is invalid")
 raw=path.read_bytes(); packet=json.loads(raw.decode()); required={"schema_version","release_id","release_commit","project_authority","product_intent_semantic_bundle_hash","product_intent_source_packet_hash","release_projection_hash","requirement_ids","criterion_ids","critical_journeys","canonical_checks","canonical_runtime_evidence","canonical_findings","selected_sources","coverage_boundary","packet_hash"}
 if set(packet)!=required or packet.get("schema_version")!=PACKET_SCHEMA or packet.get("packet_hash")!=content_hash({k:v for k,v in packet.items() if k!="packet_hash"}) or packet!=_packet_expected(ctx,[x["path"] for x in packet["selected_sources"]]):raise ValueError("mapping packet is stale or invalid")
 return packet,raw
def _proposal_path(ctx,value):
 inbox=(_root(ctx)/"inbox").resolve(); raw=Path(value).absolute()
 if raw.is_symlink():raise ValueError("mapping proposal must be regular inbox JSON")
 path=raw.resolve()
 if inbox not in path.parents or path.suffix!=".json" or path.is_symlink() or not path.is_file() or path.stat().st_size>LIMIT:raise ValueError("mapping proposal must be bounded inbox JSON")
 return path
def _quote(ref,sources):
 allowed={"path","returned_git_path","git_blob_hash","start_line","end_line","quote","quote_hash","label"}
 if set(ref)-allowed or not {"path","returned_git_path","git_blob_hash"}<=set(ref):raise ValueError("invalid repository reference")
 src=sources.get(ref["path"])
 if not src or any(ref[k]!=src[k] for k in ("returned_git_path","git_blob_hash")):raise ValueError("stale repository reference")
 q={"start_line","end_line","quote","quote_hash"}
 if q&set(ref):
  if not q<=set(ref) or not all(isinstance(ref[k],int) for k in ("start_line","end_line")):raise ValueError("invalid mapping quote")
  lines=src["text"].split("\n"); actual="\n".join(lines[ref["start_line"]-1:ref["end_line"]]) if 1<=ref["start_line"]<=ref["end_line"]<=len(lines) else ""
  if actual.count(ref["quote"])!=1 or ref["quote_hash"]!=_hash(ref["quote"].encode()):raise ValueError("invalid mapping quote")
def _validate_proposal(p,packet):
 required={"schema_version","release_id","release_commit","product_intent_semantic_bundle_hash","release_projection_hash","mapping_packet_hash","mappings"}; bind={"release_id":"release_id","release_commit":"release_commit","product_intent_semantic_bundle_hash":"product_intent_semantic_bundle_hash","release_projection_hash":"release_projection_hash","mapping_packet_hash":"packet_hash"}
 if set(p)!=required or p.get("schema_version")!=PROPOSAL_SCHEMA or not isinstance(p.get("mappings"),list) or any(p[k]!=packet[v] for k,v in bind.items()):raise ValueError("mapping proposal binding is invalid")
 sources={x["path"]:x for x in packet["selected_sources"]}; criteria=set(packet["criterion_ids"]); runtime={x["runtime_evidence_id"] for x in packet["canonical_runtime_evidence"]}|{x["check_id"] for x in packet["canonical_checks"]}; findings={x.get("id") for x in packet["canonical_findings"]}; journeys={x["journey_id"] for x in packet["critical_journeys"]}; ids=set(); semantic=set()
 for x in p["mappings"]:
  base={"mapping_id","criterion_id","target_type","rationale"}
  if not isinstance(x,dict) or not base<=set(x) or not isinstance(x["mapping_id"],str) or not x["mapping_id"].strip() or len(x["mapping_id"])>100 or x["mapping_id"] in ids or not isinstance(x["rationale"],str) or not x["rationale"].strip() or len(x["rationale"])>1000 or x["criterion_id"] not in criteria:raise ValueError("invalid mapping")
  ids.add(x["mapping_id"]); typ=x["target_type"]
  if typ in {"implementation_reference","test_reference","instrumentation_reference"}:
   if set(x)-({*base,"reference","quality_assessment"}) or not isinstance(x.get("reference"),dict) or x.get("quality_assessment") not in {None,"plausible","partial","inadequate","unknown"}:raise ValueError("invalid repository mapping")
   _quote(x["reference"],sources); ident=(x["criterion_id"],typ,canonical_json({k:v for k,v in x["reference"].items() if k!="label"}))
  elif typ in {"runtime_evidence","finding"}:
   if set(x)!={*base,"canonical_id"} or not isinstance(x.get("canonical_id"),str) or x["canonical_id"] not in (runtime if typ=="runtime_evidence" else findings):raise ValueError("invalid canonical mapping")
   ident=(x["criterion_id"],typ,x["canonical_id"])
  elif typ=="critical_journey":
   if set(x)!={*base,"journey_id"} or x.get("journey_id") not in journeys:raise ValueError("invalid journey mapping")
   ident=(x["criterion_id"],typ,x["journey_id"])
  else:raise ValueError("invalid mapping target")
  if ident in semantic:raise ValueError("duplicate semantic mapping")
  semantic.add(ident)
def _normalize_proposal(p,packet):
 out=json.loads(canonical_json(p))
 for x in out["mappings"]:x.pop("mapping_id"); x["establishment_classification"]="model_mapped_candidate"
 out["mappings"]=sorted(out["mappings"],key=canonical_json); return out

def _route(check):
 kind=ROUTES.get(check.get("type")); return kind
def _successful(check,slot):
 if not check.get("passed") or check.get("evidence_status")!="deterministically_verified":return False
 if slot=="runtime" and check.get("type")=="http":return isinstance(check.get("status"),int) and 200<=check["status"]<400
 return True
def _compatible(original,rerun,slot):
 if original.get("type")!=rerun.get("type") or original.get("criterion_id")!=rerun.get("criterion_id"):return False
 if slot=="runtime":return _normal(str(original.get("target") or original.get("granted_path") or ""))==_normal(str(rerun.get("target") or rerun.get("granted_path") or ""))
 return original.get("command_id")==rerun.get("command_id") or original.get("target")==rerun.get("target")
def _record(nodes,edges,src,tgt,relationship,classification,rationale,origin,refs=None):
 edge=_edge(nodes,src,tgt,relationship,classification,rationale,origin,refs); edges.append(edge); return edge
def _relationship_for_slot(slot):return {"implementation":"may_be_implemented_by","test":"may_be_verified_by","instrumentation":"may_be_observed_by","runtime":"has_runtime_evidence"}[slot]
def _gap(cid,kind,state,basis_nodes,basis_edges,needed,**extra):
 return {"gap_id":_id("gap",{"criterion":cid,"type":kind,"state":state,"nodes":sorted(basis_nodes),"edges":sorted(basis_edges),**extra}),"criterion_id":cid,"gap_type":kind,"state":state,"basis_node_ids":sorted(basis_nodes),"basis_edge_ids":sorted(basis_edges),"evidence_needed":needed,"linked_canonical_finding_ids":sorted(extra.pop("finding_ids",[])),"product_intent_ambiguity_ids":sorted(extra.pop("ambiguity_ids",[])),**extra}
def _compile(ctx,packet,normalized):
 im,ia,ip,projection,ph=_binding(ctx); requirements=ia["requirements.json"]["requirements"]; criteria=ia["acceptance-criteria.json"]["criteria"]; ambiguities=ia["ambiguities.json"]["ambiguities"]
 nodes={}; edges=[]; limitations=[]
 def add(x):
  if x["node_id"] in nodes and nodes[x["node_id"]]!=x:raise ValueError("graph node ID collision")
  nodes[x["node_id"]]=x; return x["node_id"]
 sources={}
 for s in ip["sources"]:
  sources[s["source_id"]]=add(_node("source",{"packet":ip["packet_hash"],"source":s["source_id"]},provenance="product_intent_packet",source_id=s["source_id"],authority_tier=s["authority_tier"],path=s["path"],normalized_text_hash=s["normalized_text_hash"]))
 journeys={}
 for text in ia["product-intent.json"].get("release_scope",[]):
  value=_normal(text); journeys[value]=add(_node("critical_journey",{"intent":im["semantic_bundle_hash"],"text":value},provenance="product_intent",journey_text=value))
 req_nodes={}; crit_nodes={}; req_by_id={r["requirement_id"]:r for r in requirements}
 for r in requirements:
  rid=add(_node("requirement",r["requirement_id"],provenance="product_intent",requirement_id=r["requirement_id"],statement=r["statement"],classification=r["classification"],status=r["status"])); req_nodes[r["requirement_id"]]=rid
  for ref in r["source_refs"]:
   if ref.get("source_id") in sources:_record(nodes,edges,sources[ref["source_id"]],rid,"supports_requirement","source_backed","Product Intent citation.","product_intent",[ref])
  for text in r.get("related_journey_ids",[]):
   if _normal(text) in journeys:_record(nodes,edges,rid,journeys[_normal(text)],"affects_critical_journey","deterministically_established","Exact Product Intent journey reference.","product_intent")
 for c in criteria:
  cid=add(_node("acceptance_criterion",c["criterion_id"],provenance="product_intent",criterion_id=c["criterion_id"],requirement_id=c["requirement_id"],classification=c["classification"],confirmation_state=c["confirmation_state"],action=c.get("action"),expected_outcomes=c.get("expected_outcomes",[]))); crit_nodes[c["criterion_id"]]=cid; _record(nodes,edges,req_nodes[c["requirement_id"]],cid,"decomposes_into","deterministically_established","Product Intent ownership.","product_intent")
  for ref in c.get("source_refs",[]):
   if ref.get("source_id") in sources:_record(nodes,edges,sources[ref["source_id"]],cid,"supports_acceptance_criterion","source_backed","Product Intent citation.","product_intent",[ref])
 canonical={}; check_slot={}
 for check in projection["checks"]:
  slot=_route(check)
  if not slot:
   limitations.append({"kind":"unsupported_check","check_id":check["check_id"],"check_type":check.get("type"),"criterion_id":check.get("criterion_id")}); continue
  if check.get("evidence_status")=="missing_evidence":
   nid=add(_node(SLOT_TYPES[slot],{"missing":check["check_id"],"slot":slot},provenance="canonical_release_state",slot_status="deterministic_missing",evidence_slot=slot,check_id=check["check_id"],reason=check.get("error_type") or "canonical missing evidence"))
  else:
   kind=SLOT_TYPES[slot]; nid=add(_node(kind,{"canonical":check["check_id"],"slot":slot},provenance="canonical_release_state",slot_status="actual",evidence_slot=slot,check_id=check["check_id"],check_type=check.get("type"),target=check.get("target"),granted_path=check.get("granted_path"),status=check.get("status"),passed=check.get("passed"),evidence_status=check.get("evidence_status")))
  canonical[check["check_id"]]=nid; check_slot[check["check_id"]]=slot
 findings={}; decisions={}; tasks={}
 for f in projection["findings"]:
  fid=f.get("id") or _id("finding",f); findings[fid]=add(_node("finding",{"projection":ph,"id":fid},provenance="canonical_release_state",canonical_finding_id=fid,criterion_id=f.get("criterion_id"),title=f.get("title"),severity=f.get("severity"),blocking=bool(f.get("blocking")),state=f.get("state"),evidence=_sort(f.get("evidence",[]))))
 for d in projection["owner_decisions"]:
  did=d.get("id") or _id("decision",d); decisions[did]=add(_node("owner_decision",{"projection":ph,"id":did},provenance="canonical_release_state",canonical_decision_id=did,title=d.get("title"),choice=d.get("choice"),resolution=d.get("resolution"),evidence=_sort(d.get("evidence",[]))))
 for t in projection["remediation_tasks"]:
  tid=t.get("id") or _id("remediation",t); tasks[tid]=add(_node("remediation_plan",{"projection":ph,"id":tid},provenance="canonical_release_state",canonical_task_id=tid,remediation_class=t.get("class"),base_branch=t.get("base_branch"),branch=t.get("branch"),status=t.get("status"),auto_merge=t.get("auto_merge"),commit_sha=t.get("commit_sha")))
 # exact canonical criterion relationships and uniquely resolved finding evidence.
 for f in projection["findings"]:
  fid=f.get("id") or _id("finding",f)
  if f.get("criterion_id") in crit_nodes:_record(nodes,edges,findings[fid],crit_nodes[f["criterion_id"]],"concerns_criterion","deterministically_established","Exact canonical criterion ID.","release_projection")
  for ev in f.get("evidence",[]):
   ref=ev.get("reference") if isinstance(ev,dict) else None; matches=[nid for c,nid in canonical.items() if ref and ref in {next(x for x in projection["checks"] if x["check_id"]==c).get("target"),next(x for x in projection["checks"] if x["check_id"]==c).get("granted_path"),c}]
   if len(matches)==1:_record(nodes,edges,findings[fid],matches[0],"supported_by_evidence","deterministically_established","Unique canonical evidence reference.","release_projection",[ev])
   elif len(matches)>1:limitations.append({"kind":"ambiguous_evidence_reference","finding_id":fid,"reference":ref})
 for d in projection["owner_decisions"]:
  did=d.get("id") or _id("decision",d)
  for ev in d.get("evidence",[]):
   ref=ev.get("reference") if isinstance(ev,dict) else None
   if ref in findings:
    _record(nodes,edges,findings[ref],decisions[did],"requires_owner_decision","deterministically_established","Exact decision evidence reference.","release_projection");
    if d.get("choice") and d.get("resolution"):_record(nodes,edges,decisions[did],findings[ref],"resolved_or_conditioned_by","owner_confirmed","Recorded decision.","release_projection")
 mappings=(normalized or {"mappings":[]})["mappings"]; bycrit={c:[] for c in crit_nodes}
 for m in mappings:bycrit[m["criterion_id"]].append(m)
 slot_edges={c:{s:[] for s in SLOT_TYPES} for c in crit_nodes}; direct_journeys={c:[] for c in crit_nodes}
 # deterministic canonical check links require the final criterion ID.
 for check_id,nid in canonical.items():
  check=next(x for x in projection["checks"] if x["check_id"]==check_id); cid=check.get("criterion_id"); slot=check_slot[check_id]
  if cid in crit_nodes:slot_edges[cid][slot].append(_record(nodes,edges,crit_nodes[cid],nid,_relationship_for_slot(slot),"deterministically_established","Exact canonical criterion ID.","release_projection"))
 for cid in crit_nodes:
  for m in bycrit[cid]:
   typ=m["target_type"]
   if typ in {"implementation_reference","test_reference","instrumentation_reference"}:
    slot=next(s for s,k in SLOT_TYPES.items() if k==typ); ref=m["reference"]; nid=add(_node(typ,{"packet":packet["packet_hash"],"mapping":m},provenance="mapping_proposal",slot_status="candidate_present",evidence_slot=slot,path=ref["path"],returned_git_path=ref["returned_git_path"],git_blob_hash=ref["git_blob_hash"],label=ref.get("label"),quality_assessment=m.get("quality_assessment"),rationale=m["rationale"])); slot_edges[cid][slot].append(_record(nodes,edges,crit_nodes[cid],nid,_relationship_for_slot(slot),"model_mapped_candidate",m["rationale"],"mapping_proposal",[ref]))
   elif typ=="runtime_evidence":
    nid=canonical.get(m["canonical_id"])
    if nid:slot_edges[cid]["runtime"].append(_record(nodes,edges,crit_nodes[cid],nid,"has_runtime_evidence","model_mapped_candidate",m["rationale"],"mapping_proposal"))
   elif typ=="finding" and m["canonical_id"] in findings:_record(nodes,edges,findings[m["canonical_id"]],crit_nodes[cid],"concerns_criterion","model_mapped_candidate",m["rationale"],"mapping_proposal")
   elif typ=="critical_journey":
    target=next((n for n in journeys.values() if n==m["journey_id"]),None)
    if target:direct_journeys[cid].append(_record(nodes,edges,crit_nodes[cid],target,"maps_to_critical_journey","model_mapped_candidate",m["rationale"],"mapping_proposal"))
  for slot,kind in SLOT_TYPES.items():
   if not slot_edges[cid][slot]:
    nid=add(_node(kind,{"criterion":cid,"slot":slot,"projection":ph},provenance="graph_compiler",slot_status="not_inspected",evidence_slot=slot,reason="No qualified canonical evidence or mapping.")); slot_edges[cid][slot].append(_record(nodes,edges,crit_nodes[cid],nid,_relationship_for_slot(slot),"not_inspected","No qualified evidence.","graph_compiler"))
 # closure only follows compatible indexed reruns and exact closed finding.
 for rerun in projection["checks"]:
  index=rerun.get("rerun_of")
  if not isinstance(index,int) or not 0<=index<len(projection["checks"]) or rerun["check_id"] not in canonical:continue
  original=projection["checks"][index]; slot=check_slot.get(rerun["check_id"])
  if slot is None or slot!=check_slot.get(original["check_id"]) or not _compatible(original,rerun,slot):continue
  related=[f for f in projection["findings"] if f.get("criterion_id")==rerun.get("criterion_id")]
  for f in related:
   fid=f.get("id") or _id("finding",f); closed=f.get("state")=="CLOSED"; success=_successful(rerun,slot); failure=rerun.get("evidence_status")=="deterministically_verified" and rerun.get("passed") is False
   if not (success and closed) and not failure:continue
   closure=add(_node("closure_evidence",{"rerun":rerun["check_id"],"finding":fid},provenance="canonical_release_state",slot_status="actual",original_check_id=original["check_id"],rerun_check_id=rerun["check_id"],closure_state="closed" if success and closed else "failed"))
   _record(nodes,edges,closure,findings[fid],"closes" if success and closed else "fails_to_close","deterministically_established","Compatible canonical rerun lineage.","release_projection")
 gaps=[]; summaries=[]
 for c in criteria:
  cid=c["criterion_id"]; req=req_by_id[c["requirement_id"]]; cnode=crit_nodes[cid]; gapids=[]
  for slot in SLOT_TYPES:
   records=slot_edges[cid][slot]; ns=[nodes[e["target_node_id"]] for e in records]; deterministic=[(e,n) for e,n in zip(records,ns) if e["establishment_classification"]=="deterministically_established"]
   candidate=[(e,n) for e,n in zip(records,ns) if e["establishment_classification"]=="model_mapped_candidate"]
   if deterministic:
    failed=[(e,n) for e,n in deterministic if n.get("slot_status")=="deterministic_missing" or (n.get("passed") is False and n.get("evidence_status")=="deterministically_verified")]
    state="open" if failed else "closed" if any(n.get("passed") is True and n.get("evidence_status")=="deterministically_verified" for _,n in deterministic) else "unknown"
   else:state="unknown"
   kind={"implementation":"implementation_gap","test":"test_evidence_gap","instrumentation":"instrumentation_gap","runtime":"runtime_evidence_gap"}[slot]; g=_gap(cid,kind,state,[cnode]+[n["node_id"] for _,n in deterministic+candidate],[e["edge_id"] for e,_ in deterministic+candidate],"Qualifying deterministic %s evidence."%slot,candidate_linked_failure=bool(candidate and any(n.get("passed") is False for _,n in candidate))); gaps.append(g); gapids.append(g["gap_id"])
   for e,n in candidate:
    if n.get("quality_assessment") in {"partial","inadequate","unknown"}:
     q=_gap(cid,"quality_judgment","unknown",[cnode,n["node_id"]],[e["edge_id"]],"Qualified assessment or deterministic evidence.",assessment=n["quality_assessment"]); gaps.append(q); gapids.append(q["gap_id"])
  if c["classification"]=="inferred_requires_owner" or c["confirmation_state"]!="confirmed":gaps.append(_gap(cid,"specification_gap","open",[cnode],[],"Owner-confirmed Product Intent.")); gapids.append(gaps[-1]["gap_id"])
  amb=[a["ambiguity_id"] for a in ambiguities if cid in a.get("affected_criterion_ids",[]) or c["requirement_id"] in a.get("affected_requirement_ids",[])]
  if amb:gaps.append(_gap(cid,"source_conflict","open",[cnode],[],"Resolved Product Intent ambiguity.",ambiguity_ids=amb)); gapids.append(gaps[-1]["gap_id"])
  linked_find=[e for e in edges if e["relationship"]=="concerns_criterion" and e["target_node_id"]==cnode]; linked_dec=[e for e in edges if e["relationship"]=="requires_owner_decision" and e["source_node_id"] in {x["source_node_id"] for x in linked_find}]
  if any(nodes[e["target_node_id"]].get("choice") is None for e in linked_dec):gaps.append(_gap(cid,"owner_decision_required","open",[cnode]+[e["target_node_id"] for e in linked_dec],[e["edge_id"] for e in linked_dec],"Recorded owner decision.")); gapids.append(gaps[-1]["gap_id"])
  def items(es):return [{"node_id":e["target_node_id"],"relationship_edge_id":e["edge_id"],"relationship_classification":e["establishment_classification"],"node_provenance":nodes[e["target_node_id"]]["provenance"],"node":nodes[e["target_node_id"]],**{k:v for k,v in nodes[e["target_node_id"]].items() if k not in {"node_id","node_type","provenance"}}} for e in es]
  closure=[e for e in edges if e["relationship"] in {"closes","fails_to_close"} and any(x["source_node_id"]==e["target_node_id"] for x in linked_find)]
  summaries.append({"criterion_id":cid,"criterion_node_id":cnode,"owning_requirement":{"node_id":req_nodes[c["requirement_id"]],"statement":req["statement"]},"requirement_id":c["requirement_id"],"requirement_statement":req["statement"],"source_support":items([e for e in edges if e["relationship"]=="supports_acceptance_criterion" and e["target_node_id"]==cnode]),"inherited_journeys":_sort(req.get("related_journey_ids",[])),"critical_journey_context":_sort(req.get("related_journey_ids",[])),"direct_journeys":items(direct_journeys[cid]),"implementation":items(slot_edges[cid]["implementation"]),"tests":items(slot_edges[cid]["test"]),"instrumentation":items(slot_edges[cid]["instrumentation"]),"runtime":items(slot_edges[cid]["runtime"]),"missing_slots":sorted(s for s in SLOT_TYPES if any(x["node"].get("slot_status")=="deterministic_missing" for x in items(slot_edges[cid][s]))),"not_inspected_slots":sorted(s for s in SLOT_TYPES if any(x["node"].get("slot_status")=="not_inspected" for x in items(slot_edges[cid][s]))),"model_judgments":[g["gap_id"] for g in gaps if g["criterion_id"]==cid and g["gap_type"]=="quality_judgment"],"findings":items(linked_find),"blockers":items([e for e in linked_find if nodes[e["source_node_id"]].get("blocking")]),"owner_decisions":items(linked_dec),"remediation":[],"closure":items(closure),"closure_evidence_required":"not_inspected" if not closure else "actual","gaps":sorted(gapids),"evidence_needed_to_close":_sort([g["evidence_needed"] for g in gaps if g["criterion_id"]==cid])})
 common={"release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],"project_authority":_authority(ctx),"product_intent_semantic_bundle_hash":im["semantic_bundle_hash"],"product_intent_source_packet_hash":im["source_packet_hash"],"release_projection_hash":ph,"compiler_version":COMPILER_VERSION}
 graph={"schema_version":GRAPH_SCHEMA,**common,"mapping_packet_state":"present" if packet else "absent","mapping_packet_hash":packet["packet_hash"] if packet else None,"coverage_boundary":"Validated Product Intent, canonical release projection, and optional explicit mapping packet only.","import_limitations":sorted(limitations,key=canonical_json),"nodes":sorted(nodes.values(),key=lambda x:x["node_id"]),"edges":sorted({e["edge_id"]:e for e in edges}.values(),key=lambda x:x["edge_id"])}
 return graph,{"schema_version":SUMMARY_SCHEMA,**common,"criteria":sorted(summaries,key=lambda x:x["criterion_id"])},{"schema_version":GAPS_SCHEMA,**common,"gaps":sorted(gaps,key=lambda x:x["gap_id"])}

def _validate_artifacts(artifacts, criterion_ids=None):
 if set(artifacts)!=set(ARTIFACTS):raise ValueError("graph artifact set is invalid")
 g,s,ga=(artifacts[x] for x in ARTIFACTS); common={"release_id","release_commit","project_authority","product_intent_semantic_bundle_hash","product_intent_source_packet_hash","release_projection_hash","compiler_version"}
 if set(g)!={"schema_version",*common,"mapping_packet_state","mapping_packet_hash","coverage_boundary","import_limitations","nodes","edges"} or g["schema_version"]!=GRAPH_SCHEMA:raise ValueError("graph schema is invalid")
 nodes={x.get("node_id"):x for x in g["nodes"]}
 if len(nodes)!=len(g["nodes"]) or any(set(n)<{"node_id","node_type","provenance"} or n["node_type"] not in NODE_TYPES or not isinstance(n["provenance"],str) for n in nodes.values()):raise ValueError("graph node schema is invalid")
 seen=set()
 for e in g["edges"]:
  required={"edge_id","source_node_id","target_node_id","relationship","establishment_classification","rationale","origin","references"}
  if set(e)!=required or e["edge_id"] in seen:raise ValueError("graph edge schema is invalid")
  if _edge(nodes,e["source_node_id"],e["target_node_id"],e["relationship"],e["establishment_classification"],e["rationale"],e["origin"],e["references"])!=e:raise ValueError("graph edge is invalid")
  seen.add(e["edge_id"])
 if set(s)!={"schema_version",*common,"criteria"} or s["schema_version"]!=SUMMARY_SCHEMA or set(ga)!={"schema_version",*common,"gaps"} or ga["schema_version"]!=GAPS_SCHEMA:raise ValueError("summary or gap schema invalid")
 summary_ids=[x.get("criterion_id") for x in s["criteria"]]
 if len(summary_ids)!=len(set(summary_ids)) or (criterion_ids is not None and set(summary_ids)!=set(criterion_ids)):raise ValueError("criterion summary set invalid")
 for gap in ga["gaps"]:
  required={"gap_id","criterion_id","gap_type","state","basis_node_ids","basis_edge_ids","evidence_needed","linked_canonical_finding_ids","product_intent_ambiguity_ids"}
  if not required<=set(gap) or gap["state"] not in {"open","unknown","closed"} or any(x not in nodes for x in gap["basis_node_ids"]) or any(x not in seen for x in gap["basis_edge_ids"]):raise ValueError("gap schema invalid")
def _persist(ctx,packet,packet_bytes,submitted,submitted_bytes,normalized,artifacts):
 root=_root(ctx); directory=root/"generations"/("gen_"+uuid.uuid4().hex); directory.mkdir(parents=True); hashes={}
 for name,obj in artifacts.items():_atomic(directory/name,obj); hashes[name]=_hash((directory/name).read_bytes())
 if packet_bytes:(directory/"mapping-source-packet.json").write_bytes(packet_bytes)
 if submitted_bytes:(directory/"submitted-mapping-proposal.json").write_bytes(submitted_bytes); _atomic(directory/"normalized-mapping-proposal.json",normalized)
 im,_,_,_,ph=_binding(ctx); nb=(directory/"normalized-mapping-proposal.json").read_bytes() if normalized else None
 manifest={"schema_version":MANIFEST_SCHEMA,"release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],"project_authority":_authority(ctx),"product_intent_semantic_bundle_hash":im["semantic_bundle_hash"],"product_intent_source_packet_hash":im["source_packet_hash"],"release_projection_hash":ph,"mapping_packet_state":"present" if packet else "absent","mapping_packet_hash":packet["packet_hash"] if packet else None,"mapping_packet_snapshot_hash":_hash(packet_bytes) if packet_bytes else None,"submitted_proposal_hash":content_hash(submitted) if submitted else None,"submitted_proposal_snapshot_hash":_hash(submitted_bytes) if submitted_bytes else None,"normalized_proposal_hash":content_hash(normalized) if normalized else None,"normalized_proposal_snapshot_hash":_hash(nb) if nb else None,"compiler_version":COMPILER_VERSION,"artifact_filenames":list(ARTIFACTS),"artifact_hashes":hashes}
 manifest["semantic_bundle_hash"]=content_hash({"intent":manifest["product_intent_semantic_bundle_hash"],"packet":manifest["mapping_packet_hash"],"projection":ph,"compiler":COMPILER_VERSION,"artifacts":{k:hashes[k] for k in sorted(hashes)}}); manifest["bundle_hash"]=content_hash(manifest); _atomic(directory/"manifest.json",manifest); _atomic(root/"current-generation.json",{"schema_version":POINTER_SCHEMA,"generation":directory.name,"manifest_hash":_hash((directory/"manifest.json").read_bytes())}); return manifest
def compile_bundle(ctx,proposal_file=None):
 ctx.require("file.read"); packet,pb=_load_mapping_packet(ctx); submitted=normalized=None; sb=None
 if proposal_file:
  if not packet:raise ValueError("mapping proposal requires active mapping packet")
  sb=_proposal_path(ctx,proposal_file).read_bytes(); submitted=json.loads(sb.decode()); _validate_proposal(submitted,packet); normalized=_normalize_proposal(submitted,packet)
 artifacts=dict(zip(ARTIFACTS,_compile(ctx,packet,normalized))); _validate_artifacts(artifacts,[x["criterion_id"] for x in load_graph_input(ctx)[1]["acceptance-criteria.json"]["criteria"]]); return _persist(ctx,packet,pb,submitted,sb,normalized,artifacts)
def load_bundle(ctx):
 root=_root(ctx); pointer=root/"current-generation.json"
 if pointer.is_symlink() or not pointer.is_file():raise ValueError("complete graph generation unavailable")
 p=json.loads(pointer.read_text()); gen=p.get("generation")
 if set(p)!={"schema_version","generation","manifest_hash"} or p.get("schema_version")!=POINTER_SCHEMA or not isinstance(gen,str) or not re.fullmatch(r"gen_[0-9a-f]{32}",gen):raise ValueError("graph pointer invalid")
 base=(root/"generations").resolve(); directory=(base/gen).resolve()
 if directory.parent!=base or directory.is_symlink() or not directory.is_dir():raise ValueError("graph generation invalid")
 manifest_path=directory/"manifest.json"
 if manifest_path.is_symlink() or not manifest_path.is_file() or _hash(manifest_path.read_bytes())!=p["manifest_hash"]:raise ValueError("graph generation invalid")
 manifest=json.loads(manifest_path.read_text()); required={"schema_version","release_id","release_commit","project_authority","product_intent_semantic_bundle_hash","product_intent_source_packet_hash","release_projection_hash","mapping_packet_state","mapping_packet_hash","mapping_packet_snapshot_hash","submitted_proposal_hash","submitted_proposal_snapshot_hash","normalized_proposal_hash","normalized_proposal_snapshot_hash","compiler_version","artifact_filenames","artifact_hashes","semantic_bundle_hash","bundle_hash"}
 if set(manifest)!=required or manifest.get("schema_version")!=MANIFEST_SCHEMA or manifest.get("compiler_version")!=COMPILER_VERSION or manifest.get("artifact_filenames")!=list(ARTIFACTS) or set(manifest.get("artifact_hashes",{}))!=set(ARTIFACTS) or manifest.get("bundle_hash")!=content_hash({k:v for k,v in manifest.items() if k!="bundle_hash"}):raise ValueError("graph manifest invalid or stale")
 packet,pb=_load_mapping_packet(ctx); submitted=normalized=None
 if bool(packet)!=(manifest["mapping_packet_state"]=="present") or (packet and (manifest["mapping_packet_hash"]!=packet["packet_hash"] or (directory/"mapping-source-packet.json").is_symlink() or (directory/"mapping-source-packet.json").read_bytes()!=pb)):raise ValueError("graph mapping packet stale")
 if manifest["submitted_proposal_hash"]:
  sp,np=directory/"submitted-mapping-proposal.json",directory/"normalized-mapping-proposal.json"
  if not packet or any(x.is_symlink() or not x.is_file() for x in (sp,np)):raise ValueError("proposal snapshots invalid")
  sb,nb=sp.read_bytes(),np.read_bytes(); submitted=json.loads(sb.decode()); _validate_proposal(submitted,packet); normalized=_normalize_proposal(submitted,packet)
  if _hash(sb)!=manifest["submitted_proposal_snapshot_hash"] or content_hash(submitted)!=manifest["submitted_proposal_hash"] or _hash(nb)!=manifest["normalized_proposal_snapshot_hash"] or content_hash(normalized)!=manifest["normalized_proposal_hash"] or normalized!=json.loads(nb.decode()):raise ValueError("proposal snapshots stale")
 artifacts={}
 for name in ARTIFACTS:
  path=directory/name
  if path.is_symlink() or not path.is_file() or _hash(path.read_bytes())!=manifest["artifact_hashes"][name]:raise ValueError("graph artifact invalid")
  artifacts[name]=json.loads(path.read_text())
 expected=dict(zip(ARTIFACTS,_compile(ctx,packet,normalized)))
 if artifacts!=expected:raise ValueError("graph artifacts stale")
 _validate_artifacts(artifacts,[x["criterion_id"] for x in load_graph_input(ctx)[1]["acceptance-criteria.json"]["criteria"]]); return manifest,artifacts
def show(ctx,criterion_id=None):
 _,artifacts=load_bundle(ctx); summaries=artifacts[ARTIFACTS[1]]["criteria"]; summaries=[x for x in summaries if not criterion_id or x["criterion_id"]==criterion_id]
 if criterion_id and not summaries:raise ValueError("criterion unavailable")
 gaps={x["gap_id"]:x for x in artifacts[ARTIFACTS[2]]["gaps"]}; lines=[]
 for s in summaries:
  lines += [f"Requirement: {s['owning_requirement']['statement']}",f"Criterion: {s['criterion_id']}","Journey context: "+(", ".join(s["inherited_journeys"]) or "not inspected")]
  for label,key in (("Implementation","implementation"),("Test evidence","tests"),("Instrumentation","instrumentation"),("Runtime","runtime")):
   lines.append(label+": "+", ".join(f"{x['node'].get('slot_status')} [{x['relationship_classification']}] {x['node'].get('path') or x['node'].get('target') or ''}" for x in s[key]))
  lines.append("Findings: "+", ".join(x["node"].get("canonical_finding_id","") for x in s["findings"]) or "Findings: none"); lines.append("Closure: "+", ".join(x["node"].get("closure_state","") for x in s["closure"]) or "Closure: not_inspected"); lines.append("Gaps: "+", ".join(f"{gaps[x]['gap_type']}={gaps[x]['state']} ({gaps[x]['evidence_needed']})" for x in s["gaps"]))
 return "\n".join(lines)

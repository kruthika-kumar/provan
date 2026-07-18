from __future__ import annotations

import argparse
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .models import Release
from .external import compile_release, eligible_modules, require_capability, review_packet, validate_contract as validate_external_contract
from .hermes import apply_manager_decision, validate_receipt
from .public import public_release_view, write_public_view
from .review import ReviewerCorrection
from .registry import discover, select
from .report import render
from .runs import LocalRunStore, materialize
from .evidence import http_check
from .telemetry import span
from .policy import guard_external_operation
from .context import compile_project_context, context_event_metadata
from .remediation import assert_clean_worktree, current_branch, git, repository_root
from .runner import run_module
from .verdict import calculate
from .onboarding import discover as discover_project, human_report, human_project_view, initialize as initialize_project, paths as project_paths, project_authority_view
from .project import activate as activate_project, activation_status, validate_contract as validate_project_contract
from .authority import LocalExecutionContext, bind_release_authority
from .intent import compile_bundle as compile_intent, prepare as prepare_intent, show as show_intent
from .graph import compile_bundle as compile_graph, mapping_prepare, show as show_graph
from .assessment import compile_assessment, prepare as prepare_assessment, show_assessment
from .measurement_ai.preparation import prepare as prepare_measurement_ai
from .measurement_ai.persistence import compile_generation as compile_measurement_ai
from .measurement_ai.rendering import show as show_measurement_ai
from .measurement_ai.qualification import prepare_qualification, compile_qualification
from .measurement_ai.verifier import prepare_verifier
from .remediation_roadmaps import prepare as prepare_remediation, compile as compile_remediation, load_generation as load_remediation, closure_verify as verify_remediation_closure
from .review_organisation import prepare as prepare_review_plan, load as load_review_plan, adapt as adapt_review_plan
from .contestability import append_action as append_contestation, load as load_contestation
from .management_artifacts import compile as compile_management, load as load_management


def load(path: Path) -> dict:
    return Release.from_dict(json.loads(path.read_text(encoding="utf-8"))).to_dict()


def save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shiproom")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init"); init.add_argument("--repo", default="."); init.add_argument("--local-only", action="store_true"); init.add_argument("--non-interactive", action="store_true"); init.add_argument("--project-name"); init.add_argument("--product-purpose"); init.add_argument("--primary-user", action="append"); init.add_argument("--profile", choices=["inspect", "verify", "remediate"], default="inspect"); init.add_argument("--activate", action="store_true")
    project = sub.add_parser("project"); project.add_argument("action", choices=["show", "activate"]); project.add_argument("--repo", default="."); project.add_argument("--contract"); project.add_argument("--json", action="store_true")
    doctor = sub.add_parser("doctor"); doctor.add_argument("--repo", default="."); doctor.add_argument("--json", action="store_true"); doctor.add_argument("--probe", action="store_true")
    modules = sub.add_parser("modules"); modules.add_argument("action", choices=["list"])
    release = sub.add_parser("release"); release.add_argument("action", choices=["init"]); release.add_argument("--repo", required=True); release.add_argument("--live-url", required=True); release.add_argument("--promise", required=True); release.add_argument("--target-user", default="builders"); release.add_argument("--output", default="release-state/release.json")
    review = sub.add_parser("review"); group = review.add_mutually_exclusive_group(required=True); group.add_argument("--module"); group.add_argument("--all", action="store_true"); review.add_argument("--release", required=True)
    report = sub.add_parser("report"); report.add_argument("action", choices=["render"]); report.add_argument("--release", required=True); report.add_argument("--output", default="dist/release-report.html")
    decision = sub.add_parser("decision"); decision.add_argument("action", choices=["add", "record"]); decision.add_argument("--release", required=True); decision.add_argument("--id", default="decision_publish_promise"); decision.add_argument("--title", default="Beta publication promise"); decision.add_argument("--choice"); decision.add_argument("--resolution", choices=["resolved", "accepted_condition"])
    trace = sub.add_parser("trace"); trace.add_argument("action", choices=["record"]); trace.add_argument("--release", required=True); trace.add_argument("--live-url"); trace.add_argument("--hermes-session-id"); trace.add_argument("--github-repository"); trace.add_argument("--github-pr-number", type=int); trace.add_argument("--github-pr-id"); trace.add_argument("--github-comment-id"); trace.add_argument("--github-comment-url"); trace.add_argument("--cloudflare-deployment-id"); trace.add_argument("--report-url")
    hermes = sub.add_parser("hermes"); hermes.add_argument("action", choices=["packet", "selection", "receipt", "verify-join"]); hermes.add_argument("--release", required=True); hermes.add_argument("--input"); hermes.add_argument("--receipt"); hermes.add_argument("--output")
    external = sub.add_parser("external"); external.add_argument("action", choices=["init", "packet", "repository", "selection", "result", "check-http", "finish"]); external.add_argument("--contract"); external.add_argument("--release"); external.add_argument("--input"); external.add_argument("--output"); external.add_argument("--module"); external.add_argument("--delegation-id"); external.add_argument("--criterion-id"); external.add_argument("--branch"); external.add_argument("--commit-sha"); external.add_argument("--clean", action="store_true"); external.add_argument("--run-root", default="run-history")
    runs = sub.add_parser("runs"); runs.add_argument("action", choices=["list", "show", "render"]); runs.add_argument("--release"); runs.add_argument("--release-state"); runs.add_argument("--output"); runs.add_argument("--audience", choices=["all", "ceo", "product", "engineering"], default="all"); runs.add_argument("--run-root", default="run-history")
    intent = sub.add_parser("intent"); intent.add_argument("action", choices=["prepare", "compile", "show"]); intent.add_argument("--release", required=True); intent.add_argument("--source", action="append", default=[]); intent.add_argument("--supporting-source", action="append", default=[]); intent.add_argument("--proposal")
    graph = sub.add_parser("graph"); graph.add_argument("action", choices=["compile", "show", "mapping"]); graph.add_argument("--release", required=True); graph.add_argument("--proposal"); graph.add_argument("--criterion"); graph.add_argument("--path", action="append", default=[]); graph.add_argument("--effective", action="store_true"); graph.add_argument("mapping_action", nargs="?", choices=["prepare"])
    assessment = sub.add_parser("assessment"); assessment.add_argument("action", choices=["prepare", "compile", "show"]); assessment.add_argument("--release", required=True); assessment.add_argument("--capabilities"); assessment.add_argument("--base-commit"); assessment.add_argument("--path", action="append", default=[]); assessment.add_argument("--preparation"); assessment.add_argument("--criterion")
    measurement_ai = sub.add_parser("measurement-ai"); measurement_ai.add_argument("action", choices=["prepare", "compile", "show", "qualification", "verifier"]); measurement_ai.add_argument("qualification_action", nargs="?", choices=["prepare","compile"]); measurement_ai.add_argument("--release", required=True); measurement_ai.add_argument("--review-mode", choices=["contract_only","guided_review","expert_escalated_review"], default="contract_only"); measurement_ai.add_argument("--capabilities"); measurement_ai.add_argument("--applicability"); measurement_ai.add_argument("--review-capabilities"); measurement_ai.add_argument("--permission"); measurement_ai.add_argument("--path", action="append", default=[]); measurement_ai.add_argument("--preparation"); measurement_ai.add_argument("--verifier-preparation", action="append", default=[]); measurement_ai.add_argument("--role", choices=["measurement","ai_evaluation"]); measurement_ai.add_argument("--journey"); measurement_ai.add_argument("--result")
    remediation = sub.add_parser("remediation-roadmap"); remediation.add_argument("action", choices=["prepare", "compile", "show", "closure-verify"]); remediation.add_argument("--release", required=True); remediation.add_argument("--preparation"); remediation.add_argument("--closure-contract"); remediation.add_argument("--evidence")
    review_plan = sub.add_parser("review-plan"); review_plan.add_argument("action", choices=["prepare", "show", "adapt"]); review_plan.add_argument("--release", required=True); review_plan.add_argument("--trigger"); review_plan.add_argument("--specialist"); review_plan.add_argument("--criterion"); review_plan.add_argument("--evidence-id")
    contest = sub.add_parser("contestation"); contest.add_argument("action", choices=["add", "show"]); contest.add_argument("--release", required=True); contest.add_argument("--input")
    management = sub.add_parser("management-artifacts"); management.add_argument("action", choices=["compile", "show"]); management.add_argument("--release", required=True)
    args = parser.parse_args(argv)
    registry = discover()
    if args.command == "measurement-ai":
        data=load(Path(args.release)); context=LocalExecutionContext.from_release(data)
        if args.action == "qualification":
            if args.qualification_action=="prepare": print(json.dumps(prepare_qualification(context.repository_root),indent=2))
            elif args.qualification_action=="compile" and args.result: print(json.dumps(compile_qualification(context.repository_root,Path(args.result)),indent=2))
            else: raise SystemExit("measurement-ai qualification requires prepare, or compile --result")
        elif args.action == "verifier":
            if args.qualification_action!="prepare" or not args.preparation or not args.role: raise SystemExit("measurement-ai verifier prepare requires --preparation and --role")
            def optional_json(path): return json.loads(Path(path).read_text(encoding="utf-8")) if path else None
            print(json.dumps(prepare_verifier(context,args.preparation,args.role,optional_json(args.review_capabilities),optional_json(args.permission)),indent=2))
        elif args.action == "prepare":
            def optional_json(path): return json.loads(Path(path).read_text(encoding="utf-8")) if path else None
            result=prepare_measurement_ai(context,review_mode=args.review_mode,capabilities_path=args.capabilities,applicability_path=args.applicability,review_capabilities=optional_json(args.review_capabilities),permission=optional_json(args.permission),owner_paths=args.path)
            print(json.dumps(result,indent=2))
        elif args.action == "compile":
            if args.capabilities or args.applicability or args.review_capabilities or args.permission or args.path or args.journey or args.role: raise SystemExit("measurement-ai compile accepts only --release, optional --preparation, and verifier preparations")
            print(json.dumps(compile_measurement_ai(context,args.preparation,args.verifier_preparation),indent=2))
        else:
            if args.capabilities or args.applicability or args.review_capabilities or args.permission or args.path or args.preparation or args.verifier_preparation or args.role: raise SystemExit("measurement-ai show accepts only --release and optional --journey")
            print(show_measurement_ai(context,args.journey))
    elif args.command == "remediation-roadmap":
        data=load(Path(args.release)); context=LocalExecutionContext.from_release(data)
        if args.action == "prepare":
            if args.preparation or args.closure_contract or args.evidence: raise SystemExit("remediation-roadmap prepare accepts only --release")
            print(json.dumps(prepare_remediation(context), indent=2))
        elif args.action == "compile":
            if args.closure_contract or args.evidence: raise SystemExit("remediation-roadmap compile accepts --release and optional --preparation")
            print(json.dumps(compile_remediation(context,args.preparation), indent=2))
        elif args.action == "show":
            if args.preparation or args.closure_contract or args.evidence: raise SystemExit("remediation-roadmap show accepts only --release")
            manifest,artifacts=load_remediation(context); print(json.dumps({"generation":manifest["generation"],"index":artifacts["remediation-index.json"]},indent=2))
        else:
            if args.preparation or not args.closure_contract or not args.evidence: raise SystemExit("remediation-roadmap closure-verify requires --release --closure-contract --evidence")
            print(json.dumps(verify_remediation_closure(context,args.closure_contract,json.loads(Path(args.evidence).read_text(encoding="utf-8"))),indent=2))
    elif args.command == "review-plan":
        data=load(Path(args.release)); context=LocalExecutionContext.from_release(data)
        if args.action == "prepare":
            if args.trigger or args.specialist or args.criterion or args.evidence_id: raise SystemExit("review-plan prepare accepts only --release")
            print(json.dumps(prepare_review_plan(context),indent=2))
        elif args.action == "show":
            if args.trigger or args.specialist or args.criterion or args.evidence_id: raise SystemExit("review-plan show accepts only --release")
            manifest,artifacts=load_review_plan(context); print(json.dumps({"generation":manifest["generation"],"plan":artifacts["review-plan.json"]},indent=2))
        else:
            if not all((args.trigger,args.specialist,args.criterion,args.evidence_id)): raise SystemExit("review-plan adapt requires --release --trigger --specialist --criterion --evidence-id")
            print(json.dumps(adapt_review_plan(context,args.trigger,args.specialist,args.criterion,args.evidence_id),indent=2))
    elif args.command == "contestation":
        data=load(Path(args.release)); context=LocalExecutionContext.from_release(data)
        if args.action=="add":
            if not args.input: raise SystemExit("contestation add requires --release --input")
            print(json.dumps(append_contestation(context,json.loads(Path(args.input).read_text(encoding="utf-8"))),indent=2))
        else:
            if args.input: raise SystemExit("contestation show accepts only --release")
            manifest,artifacts=load_contestation(context); print(json.dumps({"generation":manifest["generation"],"ledger":artifacts["contestation-ledger.json"]},indent=2))
    elif args.command == "management-artifacts":
        data=load(Path(args.release)); context=LocalExecutionContext.from_release(data)
        if args.action=="compile": print(json.dumps(compile_management(context),indent=2))
        else:
            manifest,artifacts=load_management(context); print(json.dumps({"generation":manifest["generation"],"index":artifacts["release-packet-index"]},indent=2))
    elif args.command == "assessment":
        data = load(Path(args.release)); context = LocalExecutionContext.from_release(data)
        if args.action == "prepare":
            if args.preparation or args.criterion: raise SystemExit("assessment prepare does not accept --preparation or --criterion")
            result = prepare_assessment(context, capabilities_path=args.capabilities, base_commit=args.base_commit, owner_paths=args.path); print(json.dumps(result, indent=2))
        elif args.action == "compile":
            if args.capabilities or args.base_commit or args.path or args.criterion: raise SystemExit("assessment compile accepts only --release and optional --preparation")
            print(json.dumps(compile_assessment(context, args.preparation), indent=2))
        else:
            if args.capabilities or args.base_commit or args.path or args.preparation: raise SystemExit("assessment show accepts only --release and optional --criterion")
            print(show_assessment(context, args.criterion))
    elif args.command == "intent":
        data = load(Path(args.release)); context = LocalExecutionContext.from_release(data)
        if args.action == "prepare":
            result = prepare_intent(context, args.source, args.supporting_source); print(json.dumps({"release_id": result["release_id"], "packet_hash": result["packet_hash"], "source_coverage": result["source_coverage"]}, indent=2))
        elif args.action == "compile":
            if args.source or args.supporting_source: raise SystemExit("intent compile does not accept source selection; run intent prepare first")
            result = compile_intent(context, args.proposal); print(json.dumps(result, indent=2))
        else:
            if args.source or args.supporting_source or args.proposal: raise SystemExit("intent show accepts only --release")
            print(show_intent(context))
    elif args.command == "graph":
        data = load(Path(args.release)); context = LocalExecutionContext.from_release(data)
        if args.action == "mapping":
            if args.mapping_action != "prepare" or not args.path or args.proposal or args.criterion or args.effective: raise SystemExit("graph mapping prepare requires --release and one or more --path values")
            result = mapping_prepare(context, args.path); print(json.dumps({"release_id": result["release_id"], "packet_hash": result["packet_hash"], "selected_sources": [x["path"] for x in result["selected_sources"]]}, indent=2))
        elif args.action == "compile":
            if args.path or args.criterion or args.mapping_action or args.effective: raise SystemExit("graph compile accepts only --release and optional --proposal")
            print(json.dumps(compile_graph(context, args.proposal), indent=2))
        else:
            if args.path or args.proposal or args.mapping_action: raise SystemExit("graph show accepts only --release, optional --criterion, and optional --effective")
            print(show_assessment(context, args.criterion) if args.effective else show_graph(context, args.criterion))
    elif args.command == "init":
        repo = repository_root(Path(args.repo)); shared, _ = project_paths(repo, args.local_only)
        existing = shared.is_file()
        if not existing:
            if args.non_interactive and not all((args.project_name, args.product_purpose, args.primary_user, args.activate)): raise SystemExit("non-interactive init requires --project-name --product-purpose --primary-user and --activate")
            name = args.project_name or input("Project name: ").strip(); purpose = args.product_purpose or input("One-sentence product purpose: ").strip(); users = args.primary_user or [input("Primary users: ").strip()]
        else:
            data = json.loads(shared.read_text(encoding="utf-8")); name=data["project_name"]; purpose=data["product_purpose"]; users=data["primary_users"]
        confirmed = args.activate
        if existing and not confirmed:
            status = activation_status(repo, shared, project_paths(repo)[1])
            confirmed = status["reusable"] and not status["invalid_command_grants"]
        if not args.non_interactive and not confirmed:
            preview = initialize_project(repo, project_name=name, product_purpose=purpose, primary_users=users, profile=args.profile, local_only=args.local_only, confirmed=False); print(json.dumps(preview, indent=2)); confirmed = input("Activate this project contract? [y/N]: ").strip().lower() == "y"
        result = initialize_project(repo, project_name=name, product_purpose=purpose, primary_users=users, profile=args.profile, local_only=args.local_only, confirmed=confirmed); print(json.dumps(result, indent=2, default=str)); return 0 if result["status"] == "ACTIVE" else 1
    elif args.command == "project":
        repo = repository_root(Path(args.repo)); contract_path = Path(args.contract).resolve() if args.contract else next((p for p in project_paths(repo)[:1] + project_paths(repo, True)[:1] if p.is_file()), project_paths(repo)[0]); receipt = project_paths(repo)[1]
        if not contract_path.is_file(): raise SystemExit("project contract not found")
        if args.action == "activate": result = activate_project(repo, contract_path, receipt); print(json.dumps(result,indent=2)); return 0
        result=project_authority_view(repo,contract_path,receipt); print(json.dumps(result,indent=2,default=str) if args.json else human_project_view(result)); return 0
    elif args.command == "doctor":
        repo = repository_root(Path(args.repo)); result = discover_project(repo, probe=args.probe); print(json.dumps(result, indent=2, default=str) if args.json else human_report(result)); return 0
    elif args.command == "modules":
        for module_id, module in registry.items(): print(f"{module_id}\t{module.config.get('name','')}")
    elif args.command == "release":
        repo = repository_root(Path(args.repo)); assert_clean_worktree(repo); base_branch = current_branch(repo)
        binding, deployment_grant = bind_release_authority(repo, args.live_url, "/result/demo")
        data = Release(release_id=f"rel_{uuid.uuid4().hex[:12]}", repository={"url": args.repo, "path": str(repo), "base_branch": base_branch, "commit_sha": binding["repository_commit"]}, deployment={"url": deployment_grant["origin"], "generated_path": "/result/demo", "read_grant": deployment_grant}, product={"name": "Launch Card", "target_user": args.target_user, "promise": args.promise, "critical_journey": ["Enter project", "Generate", "Open public URL"], "non_goals": []}, project_authority=binding).to_dict()
        data["project_context"] = compile_project_context(project_id=repo.name.lower().replace(" ", "-"), repository_url=args.repo, commit_sha=git(repo, "rev-parse", "HEAD").stdout.strip(), release_input=data["product"], repository_root=repo)
        selected, skipped = select(data, registry); data["panel"] = {"selected_modules": selected, "skipped_modules": skipped}; save(Path(args.output), data); print(args.output)
    elif args.command == "review":
        path = Path(args.release); data = load(path); context = LocalExecutionContext.from_release(data); targets = data["panel"]["selected_modules"] if args.all else [args.module]
        for module_id in targets:
            if module_id not in registry: raise SystemExit(f"unknown module: {module_id}")
            result = run_module(module_id, data, context)
            criterion_ids = {check.get("criterion_id") for check in result["checks"]}
            finding_ids = {finding.get("id") for finding in result["findings"]}
            data["checks"] = [check for check in data["checks"] if check.get("criterion_id") not in criterion_ids]
            data["findings"] = [finding for finding in data["findings"] if finding.get("id") not in finding_ids]
            data["checks"].extend(result["checks"]); data["findings"].extend(result["findings"])
        data["verdict"] = calculate(data); data["state"] = data["verdict"]["status"]; save(path, data); print(json.dumps({"release_id": data["release_id"], "verdict": data["verdict"], "checks": len(data["checks"]), "findings": len(data["findings"])}, indent=2))
    elif args.command == "decision":
        path = Path(args.release); data = load(path)
        existing = next((d for d in data["owner_decisions"] if d.get("id") == args.id), None)
        if args.action == "add":
            if existing: raise SystemExit(f"decision already exists: {args.id}")
            data["owner_decisions"].append({"id": args.id, "title": args.title, "choice": None, "resolution": None, "evidence": []})
        else:
            if not existing: raise SystemExit(f"decision not found: {args.id}")
            if not args.choice or not args.resolution: raise SystemExit("record requires --choice and --resolution")
            existing.update({"choice": args.choice, "resolution": args.resolution, "recorded_at": datetime.now(UTC).isoformat(), "evidence": [{"status": "owner_confirmed", "kind": "owner_choice", "value": args.choice}]})
        data["verdict"] = calculate(data); data["state"] = data["verdict"]["status"]; save(path, data); print(json.dumps({"release_id": data["release_id"], "decision_id": args.id, "verdict": data["verdict"]}, indent=2))
    elif args.command == "external":
        store = LocalRunStore(Path(args.run_root))
        if args.action == "init":
            if not args.contract: raise SystemExit("external init requires --contract")
            with span("shiproom.contract.compile"):
                contract = validate_external_contract(json.loads(Path(args.contract).read_text(encoding="utf-8")))
                data = compile_release(contract)
            output = Path(args.output or f"release-state/{data['release_id']}.json"); save(output, data)
            store.append(data["release_id"], "contract_accepted", operation="external.init", evidence_references=[data["repository"]["url"], data["deployment"]["url"]], metadata={"contract_schema": contract["schema_version"], "capabilities": data["capabilities"]})
            print(json.dumps({"release_id": data["release_id"], "release": str(output)}, indent=2))
        else:
            if not args.release: raise SystemExit(f"external {args.action} requires --release")
            path = Path(args.release); data = load(path)
            if data.get("mode") != "external": raise SystemExit("external command requires mode=external")
            if args.action == "repository":
                guard_external_operation(data, store, "public.inspect")
                if not args.branch or not args.commit_sha or not args.clean: raise SystemExit("external repository requires --branch --commit-sha --clean")
                data["repository"].update({"base_branch": args.branch, "commit_sha": args.commit_sha, "clean_before": True}); save(path, data)
                store.append(data["release_id"], "deterministic_check", operation="git.metadata", status="passed", evidence_references=[data["repository"]["url"]], metadata={"branch": args.branch, "commit_sha": args.commit_sha, "clean": True}); print(json.dumps(data["repository"], indent=2))
            elif args.action == "packet":
                with span("shiproom.panel.select", {"release_id": data["release_id"]}): packet = review_packet(data, registry)
                data["panel"]["eligible_modules"] = [m["module_id"] for m in packet["eligible_modules"]]; save(path, data)
                context_meta=context_event_metadata(data["project_context"])
                store.append(data["release_id"], "manager_planning", agent_id="manager", operation="external.packet", metadata={"eligible_modules": data["panel"]["eligible_modules"], "ineligible_modules": packet["ineligible_modules"], **context_meta})
                output = Path(args.output or f"review-packets/{data['release_id']}.json"); save(output, packet); print(output)
            elif args.action == "selection":
                if not args.input: raise SystemExit("external selection requires --input")
                decision_data = json.loads(Path(args.input).read_text(encoding="utf-8")); eligible, _ = eligible_modules(data, registry); all_ids = set(registry); ineligible = all_ids - set(eligible)
                apply_manager_decision(data, decision_data, all_ids, ineligible); data["panel"]["eligible_modules"] = eligible; save(path, data)
                planning = next((e for e in reversed(store.events(data["release_id"])) if e["event_type"] == "manager_planning"), None)
                parent = planning["event_id"] if planning else None
                context_meta=context_event_metadata(data["project_context"])
                for module_id in decision_data["selected_modules"]: store.append(data["release_id"], "module_selected", parent_event_id=parent, agent_id="manager", module_id=module_id, status="selected", metadata={"reason": decision_data["selection_reasons"][module_id], "module_version": registry[module_id].config.get("version"), **context_meta})
                for module_id in decision_data["skipped_modules"]: store.append(data["release_id"], "module_skipped", parent_event_id=parent, agent_id="manager", module_id=module_id, status="skipped", metadata={"reason": decision_data["selection_reasons"][module_id], **context_meta})
                print(json.dumps(data["panel"], indent=2))
            elif args.action == "result":
                if not all((args.input, args.module, args.delegation_id)): raise SystemExit("external result requires --input --module --delegation-id")
                result_data = json.loads(Path(args.input).read_text(encoding="utf-8")); correction = ReviewerCorrection(store, data["release_id"]); context_meta=context_event_metadata(data["project_context"])
                started=store.append(data["release_id"],"delegate_started",agent_id="specialist",module_id=args.module,delegation_id=args.delegation_id,status="running",metadata=context_meta)
                prior = [e for e in store.events(data["release_id"]) if e.get("module_id") == args.module and e["event_type"] == "result_rejected"]
                correction.attempts[args.module] = len(prior)
                with span("shiproom.module.validate", {"release_id": data["release_id"], "module_id": args.module, "delegation_id": args.delegation_id}): response = correction.submit(result_data, expected_module=args.module, delegation_id=args.delegation_id)
                if response["status"] == "revision_required":
                    with span("shiproom.module.revise", {"release_id": data["release_id"], "module_id": args.module}): pass
                if response["status"] == "accepted":
                    result = response["result"]; criteria = {c.get("criterion_id") for c in result["checks"]}; data["checks"] = [c for c in data["checks"] if c.get("criterion_id") not in criteria] + result["checks"]
                    ids = {f.get("id") for f in result["findings"]}; data["findings"] = [f for f in data["findings"] if f.get("id") not in ids] + result["findings"]; save(path, data)
                    store.append(data["release_id"],"delegate_completed",parent_event_id=started["event_id"],agent_id="specialist",module_id=args.module,delegation_id=args.delegation_id,metadata=context_meta)
                print(json.dumps(response, indent=2));
                if response["status"] == "failed": return 1
            elif args.action == "check-http":
                guard_external_operation(data, store, "public.inspect"); criterion = args.criterion_id or "EXTERNAL_DEPLOYMENT_REACHABLE"
                with span("shiproom.check.evaluate", {"release_id": data["release_id"], "criterion_id": criterion}): check = http_check(data["deployment"]["url"])
                check.update({"criterion_id": criterion, "required": True})
                data["checks"] = [c for c in data["checks"] if c.get("criterion_id") != criterion] + [check]; save(path, data)
                store.append(data["release_id"], "deterministic_check", agent_id="verifier", criterion_id=criterion, operation="http.get", status="passed" if check["passed"] else "failed", evidence_references=[check["target"]], metadata={"http_status": check.get("status"), "evidence_status": check["evidence_status"], **context_event_metadata(data["project_context"])}); print(json.dumps(check, indent=2))
            else:
                with span("shiproom.release.run", {"release_id": data["release_id"]}): data["verdict"] = calculate(data)
                data["state"] = data["verdict"]["status"]; save(path, data)
                verdict_event = store.append(data["release_id"], "verdict_calculated", operation="canonical.calculate", status=data["state"], metadata={"reason_codes": data["verdict"]["reason_codes"]})
                store.append(data["release_id"], "run_completed", parent_event_id=verdict_event["event_id"], status="completed" if data["state"] in {"READY", "SHIP_WITH_CONDITIONS"} else "failed", metadata={"verdict": data["state"]}); print(json.dumps(data["verdict"], indent=2))
    elif args.command == "runs":
        store = LocalRunStore(Path(args.run_root))
        if args.action == "list": print("\n".join(store.releases()))
        else:
            if not args.release or not args.release_state: raise SystemExit("runs show/render require --release and --release-state")
            data = load(Path(args.release_state)); events = store.events(args.release); record = materialize(data, events)
            if args.action == "show": print(json.dumps(record, indent=2))
            else:
                output = Path(args.output or f"private-reports/{args.release}-{args.audience}.html")
                with span("shiproom.release.publish", {"release_id": args.release, "audience": args.audience}): render(data, output, events=events, audience=args.audience)
                store.append(args.release, "report_rendered", operation=f"runs.render.{args.audience}", status="completed", metadata={"audience": args.audience, "private": not data.get("capabilities", {}).get("publish_report", False)}); print(output)
    elif args.command == "hermes":
        path = Path(args.release); data = load(path)
        if args.action == "packet":
            output = Path(args.output or "public-artifacts/public-release-view.json")
            write_public_view(data, output, registry); print(output)
        elif args.action == "selection":
            if not args.input: raise SystemExit("selection requires --input")
            decision_data = json.loads(Path(args.input).read_text(encoding="utf-8"))
            apply_manager_decision(data, decision_data, set(registry)); save(path, data); print(json.dumps(data["panel"], indent=2))
        elif args.action == "receipt":
            if not args.receipt: raise SystemExit("receipt requires --receipt")
            receipt_data = validate_receipt(json.loads(Path(args.receipt).read_text(encoding="utf-8")), data["release_id"])
            output = Path(args.output or "hermes-receipts/receipt.json"); save(output, receipt_data)
            data.setdefault("telemetry", {})["hermes_session_id"] = receipt_data["session_id"]; save(path, data); print(output)
        else:
            if not args.receipt: raise SystemExit("verify-join requires --receipt")
            receipt_data = validate_receipt(json.loads(Path(args.receipt).read_text(encoding="utf-8")), data["release_id"])
            view = public_release_view(data, registry); release_id = data["release_id"]
            if receipt_data["release_id"] != release_id: raise SystemExit("receipt release_id mismatch")
            print(json.dumps({"status": "JOINED", "release_id": release_id, "session_id": receipt_data["session_id"], "report_url": view["public_artifacts"]["report_url"], "github_comment_url": view["public_artifacts"]["github_comment_url"]}, indent=2))
    elif args.command == "trace":
        path = Path(args.release); data = load(path)
        if args.live_url: data["deployment"]["url"] = args.live_url
        if args.hermes_session_id: data.setdefault("telemetry", {})["hermes_session_id"] = args.hermes_session_id
        github = data.setdefault("integrations", {}).setdefault("github", {})
        cloudflare = data.setdefault("integrations", {}).setdefault("cloudflare", {})
        for key in ("github_repository", "github_pr_number", "github_pr_id", "github_comment_id", "github_comment_url"):
            value = getattr(args, key)
            if value is not None: github[key.removeprefix("github_")] = value
        if args.cloudflare_deployment_id: cloudflare["deployment_id"] = args.cloudflare_deployment_id
        if args.report_url:
            cloudflare["report_url"] = args.report_url
            data["deployment"]["report_url"] = args.report_url
        save(path, data); print(json.dumps({"release_id": data["release_id"], "telemetry": data["telemetry"], "integrations": data["integrations"]}, indent=2))
    else:
        release_path=Path(args.release); data = load(release_path); output = render(data, Path(args.output)); repo=repository_root(Path(data["repository"]["path"])); relative=Path(output).resolve().relative_to(repo)
        data.setdefault("runtime_artifacts",[]).append({"release_id":data["release_id"],"path":relative.as_posix(),"kind":"report"}); save(release_path,data); print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

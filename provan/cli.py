from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .doctor import run_doctor
from .errors import ProvanError
from .repository import inspect_repository
from .change_brief import explain, promote, render_brief
from .acceptance import (attest, create_contract, decide, disposition_items,
                         freeze_contract, reinspect, render_record)
from .foundry import foundry, pattern_library
from .foundry_semantic import cleanup_source_bundle
from .safe_input import read_bounded_file
from .canonical import canonical_bytes
from .session10_validators import validate_error_serialized
from . import telemetry


def _configure_safe_console() -> None:
    """Keep typed output usable on legacy Windows consoles without data loss errors."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try: reconfigure(errors="backslashreplace")
            except (OSError, ValueError): pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="provan", description="Read-only repository assurance")
    sub = parser.add_subparsers(dest="command")
    doctor = sub.add_parser("doctor"); doctor.add_argument("--format", choices=["json"], default="json")
    repo = sub.add_parser("repository"); repo_sub = repo.add_subparsers(dest="repository_command")
    inspect = repo_sub.add_parser("inspect")
    inspect.add_argument("--repo", required=True); inspect.add_argument("--base", required=True); inspect.add_argument("--head", required=True)
    inspect.add_argument("--mode", choices=["source-only"], default="source-only"); inspect.add_argument("--output", type=Path); inspect.add_argument("--allow-exec", action="store_true")
    telem = sub.add_parser("telemetry"); telem_sub = telem.add_subparsers(dest="telemetry_command")
    for name in ("status", "schema", "preview", "enable", "disable", "clear-pending", "reset-id"): telem_sub.add_parser(name)
    change = sub.add_parser("explain", help="Create a bounded Change Brief")
    change.add_argument("--repo", required=True)
    candidate = change.add_mutually_exclusive_group(required=True)
    candidate.add_argument("--working-tree", action="store_true")
    candidate.add_argument("--base")
    change.add_argument("--head")
    change.add_argument("--pr")
    brief = change.add_mutually_exclusive_group(); brief.add_argument("--brief"); brief.add_argument("--brief-file", type=Path)
    agent = change.add_mutually_exclusive_group(); agent.add_argument("--agent-claim"); agent.add_argument("--agent-claim-file", type=Path)
    change.add_argument("--context", type=Path, action="append", default=[]); change.add_argument("--alias", action="append", default=[])
    change.add_argument("--user-journey", action="append", default=[]); change.add_argument("--user-journey-file", type=Path, action="append", default=[])
    previous = change.add_mutually_exclusive_group(); previous.add_argument("--previous-brief"); previous.add_argument("--previous-brief-manifest", type=Path)
    model = change.add_mutually_exclusive_group(); model.add_argument("--model-provider"); model.add_argument("--no-model", action="store_true")
    change.add_argument("--format", choices=["terminal","json","markdown","html"], default="terminal")
    acceptance = sub.add_parser("acceptance"); acceptance_sub=acceptance.add_subparsers(dest="acceptance_command")
    promote_parser=acceptance_sub.add_parser("promote"); promote_parser.add_argument("--brief",required=True)
    contract=acceptance_sub.add_parser("contract"); contract.add_argument("--preparation",required=True); contract.add_argument("--foundry-projection"); mode=contract.add_mutually_exclusive_group(required=True); mode.add_argument("--show-items",action="store_true"); mode.add_argument("--dispositions-file",type=Path); contract.add_argument("--actor-label"); contract.add_argument("--supersedes")
    foundry_parser=acceptance_sub.add_parser("foundry"); foundry_parser.add_argument("--brief",required=True); foundry_parser.add_argument("--source-manifest",type=Path,required=True); foundry_parser.add_argument("--interpretation",choices=["faithful","clarifying","enhanced"],default="faithful"); foundry_parser.add_argument("--depth",choices=["fast","standard","deep"],default="standard"); foundry_parser.add_argument("--information-boundary",choices=["blind","implementation-informed"],default="blind"); foundry_parser.add_argument("--view",choices=["full","owner-review"],default="full"); foundry_model=foundry_parser.add_mutually_exclusive_group(); foundry_model.add_argument("--model-provider"); foundry_model.add_argument("--no-model",action="store_true"); foundry_parser.add_argument("--format",choices=["terminal","json","markdown","html"],default="terminal")
    patterns=acceptance_sub.add_parser("patterns"); patterns.add_argument("--show"); patterns.add_argument("--format",choices=["json"],default="json")
    foundry_cleanup=acceptance_sub.add_parser("foundry-cleanup"); foundry_cleanup.add_argument("--run",required=True)
    freeze=acceptance_sub.add_parser("freeze"); freeze.add_argument("--contract",required=True); freeze.add_argument("--repo",required=True)
    attest_parser=acceptance_sub.add_parser("attest"); attest_parser.add_argument("--freeze",required=True); attest_parser.add_argument("--evidence",type=Path,action="append",default=[])
    decision=acceptance_sub.add_parser("decide"); decision.add_argument("--attestation",required=True); decision.add_argument("--decision-file",type=Path,required=True); decision.add_argument("--actor-label",required=True)
    record=acceptance_sub.add_parser("record"); record.add_argument("--attestation",required=True); record.add_argument("--decision"); record.add_argument("--format",choices=["terminal","json","markdown","html"],default="terminal")
    reinspection=sub.add_parser("reinspect"); reinspection.add_argument("--record",required=True); reinspection.add_argument("--repo",required=True); reinspection.add_argument("--head",required=True); reinspection.add_argument("--external-change-receipt-file",type=Path)
    return parser


def _json_file(path: Path, limit: int) -> dict:
    text,_=read_bounded_file(path,limit=limit)
    try:value=json.loads(text)
    except json.JSONDecodeError as exc:raise ProvanError("INPUT_FILE_STRUCTURED_INVALID","input must be canonical JSON") from exc
    if not isinstance(value,dict):raise ProvanError("INPUT_FILE_STRUCTURED_INVALID","input JSON must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    _configure_safe_console()
    args = _parser().parse_args(argv)
    try:
        if args.command == "doctor": value = run_doctor()
        elif args.command == "repository" and args.repository_command == "inspect": value = inspect_repository(args.repo, args.base, args.head, args.output, allow_exec=args.allow_exec)
        elif args.command == "explain":
            if args.base and not args.head: raise ProvanError("PINNED_COMMIT_REQUIRED","--base requires --head")
            if args.working_tree and (args.head or args.pr): raise ProvanError("CANDIDATE_INPUT_CONFLICT","--working-tree cannot be combined with --head or --pr")
            brief_text=args.brief
            if args.brief_file: brief_text=read_bounded_file(args.brief_file,limit=256*1024)[0]
            agent_claim=args.agent_claim
            if args.agent_claim_file: agent_claim=read_bounded_file(args.agent_claim_file,limit=128*1024)[0]
            value=explain(repo=args.repo,base=args.base,head=args.head,working_tree=args.working_tree,brief_text=brief_text,agent_claim=agent_claim,context_files=args.context,aliases=args.alias,journeys=args.user_journey,journey_files=args.user_journey_file,previous_brief=args.previous_brief,previous_manifest=args.previous_brief_manifest,provider_id=args.model_provider,no_model=args.no_model,pr=args.pr)
            print(render_brief(value,args.format)); return 0
        elif args.command == "acceptance" and args.acceptance_command == "promote": value=promote(args.brief)
        elif args.command == "acceptance" and args.acceptance_command == "contract":
            if args.show_items:value=disposition_items(args.preparation,args.foundry_projection)
            else:
                if not args.actor_label:raise ProvanError("ACTOR_LABEL_REQUIRED","--actor-label is required when creating a contract")
                value=create_contract(args.preparation,_json_file(args.dispositions_file,1024*1024),args.actor_label,supersedes=args.supersedes,foundry_projection=args.foundry_projection)
        elif args.command == "acceptance" and args.acceptance_command == "foundry":
            value,rendered=foundry(brief_id=args.brief,source_manifest=args.source_manifest,interpretation=args.interpretation,depth=args.depth,provider_id=args.model_provider,no_model=args.no_model,format_name=args.format,information_boundary=args.information_boundary,view=args.view);print(rendered,end="" if rendered.endswith("\n") else "\n");return 0
        elif args.command == "acceptance" and args.acceptance_command == "patterns":
            library=pattern_library()
            if args.show:
                matches=[row for row in library["patterns"] if row["pattern_id"]==args.show]
                if not matches:raise ProvanError("VERIFICATION_PATTERN_NOT_FOUND",args.show)
                value=matches[0]
            else:value=library
        elif args.command == "acceptance" and args.acceptance_command == "foundry-cleanup": value=cleanup_source_bundle(args.run)
        elif args.command == "acceptance" and args.acceptance_command == "freeze": value=freeze_contract(args.contract,args.repo)
        elif args.command == "acceptance" and args.acceptance_command == "attest":
            if len(args.evidence)>32:raise ProvanError("EVIDENCE_INPUT_LIMIT_EXCEEDED","at most 32 evidence files are accepted")
            evidence=[];total=0
            for path in args.evidence:
                text,_=read_bounded_file(path,limit=8*1024*1024);raw=text.encode("utf-8");total+=len(raw)
                if total>32*1024*1024:raise ProvanError("EVIDENCE_INPUT_LIMIT_EXCEEDED","evidence aggregate exceeds 32 MiB")
                evidence.append((path.name,raw))
            value=attest(args.freeze,evidence)
        elif args.command == "acceptance" and args.acceptance_command == "decide": value=decide(args.attestation,_json_file(args.decision_file,1024*1024),args.actor_label)
        elif args.command == "acceptance" and args.acceptance_command == "record":
            record_id,text=render_record(args.attestation,args.decision,args.format);print(text,end="" if text.endswith("\n") else "\n");return 0
        elif args.command == "reinspect":
            external=_json_file(args.external_change_receipt_file,1024*1024) if args.external_change_receipt_file else None
            value=reinspect(args.record,args.repo,args.head,external)
        elif args.command == "telemetry":
            if args.telemetry_command == "status": value = telemetry.status()
            elif args.telemetry_command == "schema": value = {"schema_id": "provan.telemetry_schema_index.v1", "events": ["doctor_completed", "inspection_completed"], "additional_fields": False}
            elif args.telemetry_command == "preview": value = telemetry.preview()
            elif args.telemetry_command == "enable": value = telemetry.configure(True)
            elif args.telemetry_command == "disable": value = telemetry.configure(False)
            elif args.telemetry_command == "clear-pending": value = telemetry.clear_pending()
            elif args.telemetry_command == "reset-id":
                print("DEPRECATED: use 'provan telemetry clear-pending'; no removal date is authorized.", file=sys.stderr)
                value = telemetry.clear_pending()
            else: return _parser().print_help() or 2
        else: return _parser().print_help() or 2
        print(json.dumps(value, sort_keys=True, indent=2))
        return 0
    except ProvanError as exc:
        value={"schema_id":"provan.error.v1","error":exc.code,"message":exc.message}
        try:validate_error_serialized(canonical_bytes(value))
        except ProvanError:value={"schema_id":"provan.error.v1","error":exc.code,"message":"Operation failed with a typed, redacted error."}
        print(json.dumps(value,sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

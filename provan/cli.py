from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .doctor import run_doctor
from .errors import ProvanError
from .repository import inspect_repository
from .change_brief import explain, promote, render_brief
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
    return parser


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

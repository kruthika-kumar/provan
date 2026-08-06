from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .doctor import run_doctor
from .errors import ProvanError
from .repository import inspect_repository
from . import telemetry


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "doctor": value = run_doctor()
        elif args.command == "repository" and args.repository_command == "inspect": value = inspect_repository(args.repo, args.base, args.head, args.output, allow_exec=args.allow_exec)
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
        print(json.dumps({"error": exc.code, "message": exc.message}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

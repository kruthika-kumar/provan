# Shiproom

Shiproom is a fresh-built release-assurance agency operated through Hermes. A release manager selects independent review modules, gathers typed evidence, applies only allowlisted branch fixes, independently reruns failed checks, and publishes a structured verdict.

## Fresh-build provenance

The implementation, schemas, prompts, tests, demo patient, and reports in this repository were created during the event. The prior blueprint is a read-only specification and is excluded from Git.

## Quick start

Install Core and optional development dependencies:

```powershell
python -m pip install -e ".[dev]"
shiproom modules list
```

Start the patient in **Terminal A** and leave it running:

```powershell
python -m demo_patient.server
```

Start the named Hermes operator session in **Terminal B**:

```powershell
hermes -p buildathon --tui --continue "shiproom-judged-release" --skills shiproom
```

Inside that Hermes session, invoke `/shiproom` with the repository, URL, promise, target user, and critical journey. The executable workflow is:

```powershell
shiproom release init --repo . --live-url http://127.0.0.1:8787 --promise "Users can generate and open a public launch card."
shiproom review --all --release release-state/release.json
shiproom decision add --release release-state/release.json --id decision_publish_promise --title "Beta publication promise"
python scripts/remediate_demo.py --repo . --release release-state/release.json
# Restart Terminal A from the remediation branch, or deploy that branch to the same Worker.
python scripts/verify_demo.py --release release-state/release.json
shiproom decision record --release release-state/release.json --id decision_publish_promise --choice "Revise the beta promise" --resolution accepted_condition
python scripts/verify_demo.py --release release-state/release.json
shiproom report render --release release-state/release.json
python scripts/run_evals.py
python scripts/reset_demo.py --repo . --release release-state/release.json
```

Hermes owns intake, dynamic delegation, and presentation through `skills/shiproom/SKILL.md`. Python owns schemas, evidence, transitions, verdicts, remediation policy, and report rendering.

Core works with local state and text output. Convex, Langfuse, OpenTelemetry, and ElevenLabs are optional adapters and never determine the release verdict.

See `docs/event-readiness.md` for the frozen runtime record, completed proofs, and live-service blockers. Deploy the patient/report after Cloudflare authentication with `npx wrangler deploy --config cloudflare/wrangler.toml`.

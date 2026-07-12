# Shiproom

Shiproom is a fresh-built release-assurance agency operated through Hermes. A release manager selects independent review modules, gathers typed evidence, applies only allowlisted branch fixes, independently reruns failed checks, and publishes a structured verdict.

## Fresh-build provenance

The implementation, schemas, prompts, tests, demo patient, and reports in this repository were created during the event. The prior blueprint is a read-only specification and is excluded from Git.

## Quick start

```powershell
python -m pip install -e .
shiproom modules list
shiproom release init --repo . --live-url http://127.0.0.1:8787 --promise "Users can generate and open a public launch card."
python -m demo_patient.server
shiproom review --all --release release-state/release.json
shiproom report render --release release-state/release.json
python scripts/run_evals.py
```

Hermes owns intake, dynamic delegation, and presentation through `skills/shiproom/SKILL.md`. Python owns schemas, evidence, transitions, verdicts, remediation policy, and report rendering.

Core works with local state and text output. Convex, Langfuse, OpenTelemetry, and ElevenLabs are optional adapters and never determine the release verdict.


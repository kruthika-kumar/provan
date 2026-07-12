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

For the judged public run, first generate the single allowlisted projection from the private canonical state:

```powershell
shiproom hermes packet --release release-state/release.json --output public-artifacts/public-release-view.json
```

Run `python scripts/disclosure_audit.py --repo .` only after committing. Review its fail-closed receipt, make the GitHub repository public explicitly, and clone it into a fresh temporary directory. Do not run judged Hermes from this original event workspace.

In **Terminal B**, from the fresh public clone, start the named Hermes TUI session:

```powershell
hermes -p buildathon --tui --continue "shiproom-judged-release-rel_35e58f680a1a"
```

Invoke `/shiproom` and paste only `public-artifacts/public-release-view.json`. Hermes must dynamically select modules, explain every selected/skipped module, and delegate substantive Product/UX and Engineering/QA reviews. After the run, create a local receipt with only `release_id`, native `session_id`, session name, ISO start/end timestamps, and `public_inputs_only: true`, then ingest it:

```powershell
shiproom hermes receipt --release release-state/release.json --receipt <receipt.json>
shiproom hermes verify-join --release release-state/release.json --receipt hermes-receipts/receipt.json
```

The original executable local workflow remains:

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

The public report, GitHub comment, Hermes packet, and joined checks must all be derived from `public_release_view`; canonical state remains private. The report never embeds the canonical object. If publication fails, use a manually sanitized packet as a documented fallback; this repository does not implement a second disclosure architecture.

Core works with local state and text output. Convex, Langfuse, OpenTelemetry, and ElevenLabs are optional adapters and never determine the release verdict.

## Private-project onboarding

Private alpha onboarding is separate from the historical public external-release contract. From an already cloned private repository, preview and activate a minimal human-owned project contract:

```powershell
shiproom init --repo .
shiproom project show
shiproom doctor
```

The shared, commit-safe authority lives at `.shiproom/project-contract.json`; machine paths, activation receipts, deployment locators, cached context, and private reports live under ignored `.shiproom/local/`. Normal onboarding asks only for the project name, one-sentence purpose, primary users, and capability confirmation. Reports are private and memory is disabled by default.

`inspect` permits bounded file, Git metadata/diff, and configured deployment reads. `verify` additionally permits only activated, hash-bound argv command grants with no shell. `remediate` additionally permits allowlisted changes in an isolated Shiproom Git worktree; it never patches the active checkout. Push, PR, merge, publication, and deployment remain separately disabled.

`shiproom init`, `shiproom project show`, and `shiproom doctor` make no outbound network calls by default. Use `shiproom doctor --probe` for explicit bounded connectivity checks.

See `docs/event-readiness.md` for the frozen runtime record, completed proofs, and live-service blockers. Deploy the patient/report after Cloudflare authentication with `npx wrangler deploy --config cloudflare/wrangler.toml`.

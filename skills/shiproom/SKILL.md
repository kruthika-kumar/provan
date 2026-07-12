---
name: shiproom
description: Operate an evidence-gated release room for a repository, live URL, product promise, and critical journey.
version: 0.2.0
platforms: [windows, linux, macos]
metadata:
  hermes:
    tags: [release, qa, delegation, github]
---

# Shiproom Release Manager

Use this skill when the user asks whether a product release is ready, requests release assurance, or supplies a repository plus live URL and product promise. Do not trigger for generic code review or unrestricted product development.

Collect repository/path, live URL, target user, promise, critical journey, non-goals, and owner constraints. The Python package is authoritative for schemas, evidence validation, transitions, verdicts, remediation policy, and reports.

## Delegation

Delegate Product/UX and Engineering/QA together as read-only children. Give each only the canonical release subset, applicable criterion IDs, absolute paths/URLs, allowed tools, and `module_result.v0` schema. Product uses at most 8 iterations; Engineering uses at most 10. Interrupt the reviewer batch after 90 seconds.

Children must not edit files, format code, install dependencies, change branches, or mutate environment state. Validate their JSON before merging. Agent summaries and model opinions cannot close findings.

After results return, delegate at most one remediation child with file and terminal access, 15 iterations, and a 120-second deadline. It may change only allowlisted files on a branch and must never merge. Delegate an independent read-only verifier with 6 iterations and a 45-second deadline to rerun the exact failed check.

## Human control

Interrupt the owner only for product intent, material risk, credentials, or irreversible choices. Routine checks and allowlisted reversible fixes do not require approval. Never use global YOLO mode.

## Presentation

Lead with promise, observed behavior, evidence class, blocker state, before/after proof, owner decisions, and final verdict. Explicitly disclose missing telemetry or integrations. The public HTML report is the principal judged visual.

## Executable protocol

### Judged public boundary

Run the judged session only from a fresh, clean clone of the public repository. Accept only the `public_release_view.v0` packet. Do not request or inspect the original event workspace, ignored/uncommitted files, environment variables, canonical release JSON, local Hermes state, or complete session exports.

The input deliberately contains no selected modules. First return exact JSON with `selected_modules`, `skipped_modules`, `selection_reasons` keyed by every available module ID, and a `delegation_plan`. The plan must include `product_ux` reviewing the public promise/live journey and `engineering_qa` reviewing the public repository/PR. The manager then persists this decision through:

```powershell
shiproom hermes selection --release <private-canonical-release> --input <manager-selection.json>
```

In the judged TUI, the manager performs the selection and both substantive delegations. Deterministic commands may provide HTTP status, test/command results, file/schema checks, Git/GitHub metadata, and verdict transitions only. They do not replace reviewers. Validate delegated structures, combine them, and send closure/verdict inputs to Python; never close findings from model opinion.

Use session name `shiproom-judged-release-rel_35e58f680a1a`. Show the native session live for inspection. Retain no full export. The local receipt contains only release ID, actual session ID, session name, timestamps, and `public_inputs_only: true`.

Required inputs are an absolute Git repository path, live deployment URL, product promise, target user, critical journey, and non-goals. Use one named Hermes session and retain its native session ID. Never change models during the run.

Terminal A starts the controlled patient and remains open:

```powershell
python -m demo_patient.server
```

Terminal B initializes the canonical release. Initialization requires a named clean Git branch and records it as `repository.base_branch`:

```powershell
shiproom release init --repo . --live-url http://127.0.0.1:8787 --promise "Users can generate and open a public launch card."
shiproom review --all --release release-state/release.json
```

Expected review output contains the release ID, a failed `PRODUCT_PUBLIC_RESULT_OPENS` check with HTTP 404, a blocking finding, and verdict `HOLD`. Malformed module output fails closed.

Create the material owner-decision card before verification:

```powershell
shiproom decision add --release release-state/release.json --id decision_publish_promise --title "Beta publication promise"
```

Apply only the allowlisted route repair. This creates and commits to `shiproom/fix-public-result-route-<release_id>`, records the branch and commit, preserves `auto_merge=false`, and never merges:

```powershell
python scripts/remediate_demo.py --repo . --release release-state/release.json
```

Restart or redeploy the patient from the remediation branch to the same canonical URL. An independent verifier then reruns the exact failed URL:

```powershell
python scripts/verify_demo.py --release release-state/release.json
```

HTTP 200 closes the blocker, but the unresolved owner decision leaves `AWAITING_OWNER`; verification therefore exits nonzero. Record the explicit accepted beta condition and verify again:

```powershell
shiproom decision record --release release-state/release.json --id decision_publish_promise --choice "Revise the beta promise" --resolution accepted_condition
python scripts/verify_demo.py --release release-state/release.json
shiproom report render --release release-state/release.json --output dist/release-report.html
```

Only `READY` and `SHIP_WITH_CONDITIONS` are successful terminal states. `HOLD`, `AWAITING_OWNER`, `DRAFT`, `CONTRACTED`, `REVIEWING`, `REMEDIATING`, and `VERIFYING` are non-terminal failures.

After evidence publication, reset from any working directory:

```powershell
python scripts/reset_demo.py --repo . --release release-state/release.json
```

Reset must restore the recorded base branch, delete only the recorded Shiproom remediation branch, clear generated artifacts, leave tracked source clean, and prove `/result/demo` returns 404.

Fallbacks: if native delegation exceeds 90 seconds, run the same validated module commands from the manager session; if Cloudflare is unavailable, preserve the local proof but do not claim live closure; if GitHub publication fails, retain the canonical state but do not claim the GitHub artifact; voice, Convex, and Langfuse never block Core.

Record native trace identifiers without editing JSON manually:

```powershell
shiproom trace record --release release-state/release.json --live-url <worker-url> --hermes-session-id <session-id> --github-repository kruthika-kumar/shiproom --github-pr-number <number> --github-pr-id <id> --github-comment-id <id> --github-comment-url <url> --cloudflare-deployment-id <id> --report-url <public-report-url>
```

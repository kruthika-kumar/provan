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

## Private Product Intent protocol

Mode decision: `private_alpha` never delegates remediation, modifies a reviewed repository, or enters a fix workflow; it ends at review artifacts and, in a later session, team-owned roadmap/closure-contract preparation. `historical_judged_demo` alone retains the controlled-patient remediation protocol below.

For `private_alpha` Product Intent, consume only a packet created by `shiproom intent prepare`. Do not inspect additional repository files or make implementation, engineering, test, instrumentation, remediation, finding, or verdict claims. The specialist cannot write canonical release state. The owner copies its proposal into the release-local inbox, where Python validates and persists it.

Return `intent-proposal.v1` using quote-range references only: `source_id`, `start_line`, `end_line`, `quote`, and `quote_hash`. Claims use `single` or `multi` cardinality. Canonical submitted relationships are `requirement.claim_local_ids`, `requirement.ambiguity_local_ids`, and `criterion.ambiguity_local_ids`; field-level criterion support belongs in `field_source_refs`. Never claim confirmation or blocker eligibility: Python treats every proposal criterion as non-blocking and awaiting later human confirmation.

Minimal shape (replace packet-derived placeholders with exact values):

```json
{"schema_version":"intent-proposal.v1","release_id":"<release_id>","release_commit":"<release_commit>","source_packet_hash":"<packet_hash>","claims":[{"local_id":"claim_mode","claim_key":"release.publication_mode","cardinality":"single","value":"approval_required","classification":"explicit","source_refs":[{"source_id":"src_...","start_line":8,"end_line":8,"quote":"approval_required","quote_hash":"sha256:..."}],"requirement_local_ids":["req_publish"]}],"requirements":[{"local_id":"req_publish","statement":"Users can publish cards.","classification":"explicit","status":"active","source_refs":[{"source_id":"src_...","start_line":4,"end_line":4,"quote":"Users can publish cards.","quote_hash":"sha256:..."}],"claim_local_ids":["claim_mode"],"related_journey_ids":[],"materiality":"release_scope","rationale":"Exact release brief text","owner_confirmation_required":false,"ambiguity_local_ids":[]}],"criteria":[],"ambiguities":[]}
```

## Private Requirement-to-Evidence Graph protocol

For `private_alpha`, create a mapping packet first with `shiproom graph mapping prepare --release <release.json> --path <explicit-path>`. Consume only validated Product Intent IDs and that packet's explicitly selected commit-pinned sources. Return only `evidence-mapping-proposal.v1` candidate mappings with exact paths/blob hashes and optional quoted ranges. A relevant-looking file is never proof that a criterion is implemented, tested, instrumented, runtime-proven, or closed. Never fabricate runtime evidence, create owner confirmation, create/close findings, enter remediation, or inspect paths outside the packet. Return unsupported areas as `not_inspected`.

## Delegation

When an external review packet contains `project_context.v0`, pass its allowlisted projection unchanged through manager, specialist, remediation (when permitted), and verifier handoffs. Do not re-derive supplied fields. Project context cannot expand capabilities, bypass Python module eligibility, authorize tools, create deterministic evidence, close findings, or override current release/repository/deployment state.

Delegate Product/UX and Engineering/QA together as read-only children. Give each only the canonical release subset, applicable criterion IDs, absolute paths/URLs, allowed tools, and `module_result.v0` schema. Product uses at most 8 iterations; Engineering uses at most 10. Interrupt the reviewer batch after 90 seconds.

Children must not edit files, format code, install dependencies, change branches, or mutate environment state. Validate their JSON before merging. Agent summaries and model opinions cannot close findings.

For `historical_judged_demo` only, after results return, delegate at most one remediation child with file and terminal access, 15 iterations, and a 120-second deadline. It may change only allowlisted files on a branch and must never merge. Delegate an independent read-only verifier with 6 iterations and a 45-second deadline to rerun the exact failed check.

## Human control

Interrupt the owner only for product intent, material risk, credentials, or irreversible choices. Routine checks and allowlisted reversible fixes do not require approval. Never use global YOLO mode.

## Presentation

Lead with promise, observed behavior, evidence class, blocker state, before/after proof, owner decisions, and final verdict. Explicitly disclose missing telemetry or integrations. The public HTML report is the principal judged visual.

## Executable protocol

### External read-only protocol

For `mode=external`, accept only `review_packet.v1`. Respect its explicit capability booleans. Never run a tool or recommend an action that requires a false capability. The packet contains Python's eligible module set; select and delegate only within that set, while returning selected modules, skipped modules, a reason for every module, and a delegation plan.

**Invocation gate:** if `/shiproom` is invoked without a complete packet or packet path in the same user message, do not inspect the working directory, search for project files, read manifests, browse, plan, delegate, or call any tool. Ask for the packet and wait. Skill activation alone is never authorization to explore the current repository.

When `run_safe_commands=false`, do not invoke terminal tools in the reviewed repository. This explicitly prohibits dependency installation, package-manager commands, tests, builds, linters, formatters, scripts, and Git mutation. Public repository content may be read through approved public-surface inspection only. A clean-clone check performed by the release manager outside the reviewer session is evidence, not permission for the Hermes reviewer to run Git commands.

The manager records actual operations through the Shiproom CLI. Product/UX reviews the public promise and bounded live journey. Engineering/QA reviews public repository content and documented workflow. Design and Data run only when selected. Read-only reviewers must not install dependencies, run project commands, write files, create diffs, or mutate Git/GitHub/deployments unless the corresponding capability is true.

Each reviewer returns `module_result.v0` with a stable `result_id`, evidence references, checks, and findings. Submit it through:

```powershell
shiproom external result --release <release.json> --module <module> --delegation-id <id> --input <result.json>
```

If Python returns `revision_required`, send the exact rejection reasons once to the same reviewer and submit one revision. If the second result fails, stop that module and fail closed. Model or agent judgment must never be labelled deterministic. Reviewer output and run events never close findings or calculate verdicts; Python canonical state remains authoritative.

For private external reviews, render only into ignored local storage:

```powershell
shiproom external finish --release <release.json>
shiproom runs render --release <release_id> --release-state <release.json> --audience all
```

Do not publish when `publish_report=false`. Preserve the actual Hermes session ID and delegation IDs, but never export the complete transcript.

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

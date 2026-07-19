---
name: shiproom
description: Operate an evidence-gated release room for a repository, live URL, product promise, and critical journey.
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

For graph mappings, use one exact target shape: repository candidates include `reference` (`path`, `returned_git_path`, `git_blob_hash`, optional exact quote range); runtime and finding candidates include their packet-projected `canonical_id`; journey candidates include an allowlisted `journey_id`. All candidate relationships remain `model_mapped_candidate`. A missing mapping or unsupported check kind is `not_inspected`, not a claim that evidence is missing.

The following are the only valid mapping-entry shapes; substitute exact active
packet values and put them in an otherwise fully bound `evidence-mapping-proposal.v1`:

```json
{"mapping_id":"repository","criterion_id":"<packet criterion_id>","target_type":"implementation_reference","rationale":"Exact packet source.","reference":{"path":"<packet path>","returned_git_path":"<packet returned path>","git_blob_hash":"<packet blob hash>","start_line":1,"end_line":1,"quote":"<exact packet text>","quote_hash":"sha256:<quote hash>"}}
```

```json
{"mapping_id":"runtime","criterion_id":"<packet criterion_id>","target_type":"runtime_evidence","rationale":"Packet fact.","canonical_id":"<packet runtime_evidence_id or check_id>"}
```

```json
{"mapping_id":"finding","criterion_id":"<packet criterion_id>","target_type":"finding","rationale":"Packet fact.","canonical_id":"<packet finding id>"}
```

```json
{"mapping_id":"journey","criterion_id":"<packet criterion_id>","target_type":"critical_journey","rationale":"Packet journey.","journey_id":"<packet journey_id>"}
```

The proposal is inbox-only and packet-bound. A candidate link to a canonical
404 or closed historical finding does not make the new criterion failed or
closed: it remains `unknown` until the final criterion has its own exact
deterministic lineage. `missing` is reserved for canonical missing evidence;
an omitted or unsupported mapping is `not_inspected`.

Graph summaries retain traversable direct and criterion paths. Treat their
`effective_classification` as the criterion-scoped authority: a canonical fact
reached through any candidate step remains candidate context for that
criterion, including decisions, remediation records, and closure evidence.

## Private Assessment protocol

For `private_alpha` assessment, consume exactly one issued role work order and its prepared role packet. Follow the snapshotted `shiproom.assessment-role.v1` method and return only the exact result schema named by the work order. Write `result.json` and a separate `completion-receipt.json` to the exact preparation-scoped inbox. A human completion receipt is valid and must not invent harness metadata.

Never use `module_result.v0` for this workflow. Never request or inspect additional files, widen allowed paths or URLs, mutate the repository or release, execute remediation, create findings or verdicts, or claim that a candidate source, passing command, screenshot, or model judgment is deterministic proof. Packet-source references remain `model_reviewed` provenance. New shell output, when an issued work order permits a command, may inform rationale only.

Product, Engineering, test-adequacy, and targeted-test records use only `model_reviewed` or `not_inspected`. Targeted test specifications are recommendations, never test code or evidence. Every assigned record receives one disposition; omission is invalid.

For an issued `shiproom.work-order.v3` browser work order, return `browser-journey-result.v3`. Navigate only the exact allowed target set. Use absolute ASCII HTTP(S) URLs without fragments; preserve query bytes. Record a redirect chain of at most 16 entries beginning at an issued URL and ending at the final observation URL. Keep every hop inside the granted origin, effective port, and path. Give every assessed criterion an observation, every observation exclusively owned evidence, and every judgment a same-criterion observation. Evidence paths must be casefold-unique POSIX-relative paths and the evidence directory must contain only the declared files. A direct validated observation is `browser_observed`; any interpretation remains `model_reviewed`. Browser evidence cannot change base graph gaps, close findings, or alter a verdict.

The authoritative base graph and canonical assessment overlay remain separate. Treat `effective-assessment-view.v3` as a derived presentation only. Preserve its separate `observation_authority`, `judgment_authority`, `observation_ids`, and `judgment_ids`; never report model-reviewed judgment as browser-observed.

## Private Measurement & AI Readiness protocol

Consume exactly one `shiproom.work-order.v6` role packet for `measurement` or `ai_evaluation`. Follow the snapshotted `shiproom.measurement-ai-role.v3` method. Never request additional files, execute commands/models/SQL/evals, inspect a data platform, mutate state, or submit top-level readiness status, factual classifications, arbitrary graph paths, or forged owner/source/runtime authority. Return the exact v3 result schema named by the work order plus a separate completion receipt.

Keep factual basis and reviewer authority separate. A source or runtime fact reached through a candidate criterion path remains candidate context; guided or dual review changes only reviewer authority. Measurement fields from owners or canonical sources cannot be overwritten by a model proposal.

Use only compiler-issued basis IDs and required criterion-path IDs. Python derives factual authority with `not_inspected` before `model_mapped_candidate`, then a fully deterministic path, then a source-only or valid source/deterministic path. Owner confirmation establishes only `contract_declaration`; it never establishes implementation, instrumentation, tests, runtime, downstream execution, data accuracy, or AI performance. Cite a guidance rule only when the packet marks it eligible, disposition every registered exception, and abstain or ask the owner when a material exception is unknown. Curated guidance constrains review; it is never project evidence.

Qualification packets are blind: use only `reviewer-packet/qualification-task.json` and its response schema. Never request, read, or infer the compiler-private rubric. Qualification is capability-scoped, and a completion receipt must match the exact prepared human or model participant. For model work preserve candidate, provider, model, qualification ID, and qualification-bundle hash exactly. A contract-only harness remains unbound and must not claim qualified semantic authority.

For typed project sources, v3 accepts only explicit SHA-1 Git identity: `git_object_format: sha1`, a 40-hex blob ID, normalized-text SHA-256, exact quote range, and quote hash. Preserve all five bindings. A declared-external measurement definition proves only its owner declaration; its definition content is `not_inspected` with `external_definition_declaration` scope and cannot be presented as inspected source proof.

For `expert_escalated_review`, complete the primary work order first. A later immutable v3 verifier preparation and work order bind the validated primary semantic hash, result snapshot hash, and receipt snapshot hash. The verifier challenges every material recommendation and cannot choose or overwrite a metric. Its `supported`, `downgrade`, `disputed`, or `owner_confirmation_required` disposition changes the canonical effect within policy ceilings. Submit verifier output only to its separate verifier inbox; mutation of the primary submission invalidates it.

In `contract_only`, report structural completeness, provenance/conflicts, bounded instrumentation mapping, and owner questions only. For guided semantic advice, cite an exact snapshotted guidance rule and an exact project basis, consider its exceptions, respect its effect ceiling, and abstain when context is insufficient. Never impose a ratio, denominator, window, cohort, attribution rule, or guardrail. Guidance is a review method, not evidence that the project is defective.

Keep product outcomes and AI behavior separate. An eval filename is not a qualified fixed case; preserve fixed input, oracle/rubric, pass condition, criterion linkage, versions, execution results, deterministic validation, and production traces as separate states. Treat tracing libraries as candidates only. Manual human completion is first-class; model participants require bound qualification for guided/expert capabilities, and no model switch occurs without explicit permission.

Treat model qualification as a three-file authority bundle: rebuilt qualification task, complete qualification result, and derived receipt. Shiproom regrades the result whenever preparation or generation authority is loaded; never rely on a receipt alone. Preserve the bundle hash and exact candidate binding.

Session closeout uses the executable claim registry against final-run JUnit XML and a real applicable Measurement-and-AI artifact bundle. It also requires executed production-boundary reports for all 27 portable contracts plus the separately governed private rubric. Empty collections, key-presence checks, fabricated passed-test sets, aggregate counts, and named-but-uninvoked functions are not proof. The final report binds the parity reports and final commit and validates its own hash.

For AI claims, declare exactly one scope: `configuration`, `eval_structure`, `offline_behavior`, `runtime_behavior`, or `product_outcome`. Source definitions may support configuration or eval structure only. They never prove offline behavior, runtime behavior, model performance, or product outcomes. A readiness `gap` does not itself authorize a blocker or condition effect.

Every accepted substantive record has a compiler-derived semantic ID and registered canonical destinations. Do not omit contract proposals, gaps, AI claims, LLM-judge assessments, exception analyses, verifier dispositions, or batched owner-confirmation proposals from the exact result payload; Shiproom rejects any accepted field that cannot be projected and rederived.

For a compiler-issued typed source binding, preserve `prepared_object_type`, `declaration_authority`, and `semantic_assessment_authority` separately. An owner-bound exact quote proves only the declaration and exact range at source-definition scope. Your assessment of whether it is a valid event, property, fixed input, oracle, pass condition, version binding, or failure case remains reviewer judgment. Never convert the label or quote into source-verified semantic adequacy, implementation, execution, runtime behavior, or AI quality. Cite only the exact typed basis and required criterion-path IDs supplied in the packet.

Cover all thirteen AI maturity rungs: case candidate, fixed input, oracle/rubric, pass condition, journey/criterion linkage, prompt/model binding, known failure, fallback, malformed output, unavailable model, supplied execution, deterministic validation, and production trace linkage. For an LLM judge, return its type/model, rubric or prompt, version binding, human calibration evidence, agreement evidence, and limitations. Missing calibration is `not_established`; do not call the eval invalid solely for that reason or certify statistical representativeness, judge validity, threshold quality, production quality, or causal impact.

## Historical judged-demo delegation

The remaining delegation and remediation instructions apply only to `historical_judged_demo`. They are not reachable from the private assessment protocol above.

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

## Sessions 6–8 private-alpha extensions

Use remediation roadmaps only as packet-only recommendations. Do not edit the
reviewed repository, create a PR, merge, deploy, or close a canonical finding
from private-alpha output. Closure verification returns a candidate status only
and requires an independent verifier. The optional remediation planner is
separate from the review-plan catalogue: ordinary human work is
`human_reviewed`, harness work is `model_reviewed`, and `owner_declared`
requires an existing release-bound owner authority.

Use the closed review-plan specialist catalogue and exact result schemas. A
manual reviewer, Codex execution package, or Hermes adapter is transport
provenance, not semantic authority. Do not invent specialists, prompts, or
Data Engineering capability.

Contestation appends actions without rewriting prior evidence. A named-risk
action requires an existing release-bound owner authority reference. Management
artifacts render canonical state locally from one shared dependency vector;
Measurement/AI authority is passed through rather than recomputed. GitHub JSON
and Markdown are generated but never posted. Preserve unknowns, candidate
authority, and independence limits.

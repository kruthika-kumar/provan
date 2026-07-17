# Shiproom

Shiproom is a packet-only, read-only release-assessment compiler. It prepares portable reviewer work orders, validates independently produced Product and Engineering results, and composes a canonical assessment overlay without changing the release, evidence graph, findings, decisions, or verdict.

## Fresh-build provenance

The implementation, schemas, prompts, tests, demo patient, and reports in this repository were created during the event. The prior blueprint is a read-only specification and is excluded from Git.

## Private assessment quick start

Install Core and optional development dependencies:

```powershell
python -m pip install -e ".[dev]"
shiproom assessment prepare --release release-state/release.json
```

Complete each issued work order manually or through a compatible harness using only its prepared role packet. Write the exact result and separate completion receipt into the preparation-scoped inbox, then compile and inspect the derived assessment:

```powershell
shiproom assessment compile --release release-state/release.json
shiproom assessment show --release release-state/release.json
shiproom graph show --release release-state/release.json --effective
```

Work orders are commit-, Product Intent-, graph-, role-, and schema-bound. Manual completion is first-class. Product, Engineering, test-adequacy, and targeted-test conclusions remain `model_reviewed`. A valid optional browser observation is `browser_observed`, while its interpretation remains `model_reviewed`; neither can refine deterministic base-graph state. Missing submissions fail closed for required roles. Browser absence is explicit and criterion-specific.

The production private-alpha path never invokes a model, browser, network, project command, or remediation workflow from domain logic. It writes only ignored release-local preparation and assessment generations.

## Measurement & AI Readiness

After Product Intent and the Requirement-to-Evidence Graph are current, prepare a bounded, read-only Measurement & AI review:

```powershell
shiproom measurement-ai prepare --release release-state/release.json --review-mode contract_only
# Complete only the issued measurement-result.v3 / ai-evaluation-result.v3 work orders.
shiproom measurement-ai compile --release release-state/release.json
shiproom measurement-ai show --release release-state/release.json
```

The capability answers whether the release can measure its promised outcome, distinguish success from failure, and evaluate AI behavior separately and honestly. It has exactly two portable roles: `measurement` and `ai_evaluation`. `contract_only` performs deterministic structure/provenance checks. `guided_review` applies only the immutable 13-rule Measurement Guidance Pack; model participants require a capability-specific qualification receipt, while guided humans use the same rules and effect ceilings without Shiproom certifying their expertise. `expert_escalated_review` additionally requires permission and a skeptical verifier. Shiproom never switches models silently.

New preparations use `shiproom.work-order.v6`, `shiproom.measurement-ai-role.v3` (`3.0.0`), and the additive v3 result/artifact contracts. V1/v2 snapshots remain immutable and fail closed with an instruction to prepare again; there is no migration or reinterpretation path. Reviewers cite compiler-issued basis and criterion-path IDs; they never submit factual classifications. Criterion factual authority is derived conservatively: an uninspected required step, then a candidate relationship, then a fully deterministic path, then a source-only or valid source/deterministic path. Reviewer and curated-guidance authority are always shown separately and never strengthen the factual basis.

Expert review is explicitly staged. First complete and validate the primary role result. Then issue `shiproom measurement-ai verifier prepare --release <release> --preparation <prep_id> --role <role>`. The immutable verifier preparation binds the primary semantic hash, result byte hash, and receipt byte hash. Complete its separate result and receipt, then pass its preparation ID to the final compile with `--verifier-preparation`. Changing the primary submission invalidates the verifier output.

Canonical v3 artifacts retain the complete decision, estimand, denominator/ratio, inference, delayed-outcome, downstream-definition, metric-quality, AI-evaluation, LLM-judge, and typed basis records. Owner confirmation establishes a contract declaration only; it never proves code, instrumentation, tests, runtime behavior, downstream execution, data accuracy, or AI performance. Every accepted reviewer field has a closed compiler projection, and verifier dispositions are applied to the canonical readiness and launch-plan effects.

Model qualification is blind and capability-scoped. Shiproom issues a public reviewer packet containing neutral scenarios and a response schema, while the packaged private grading rubric remains in a separate compiler-only snapshot. Qualification receipts are rederived from the task, complete response, and private rubric; passing one capability never awards an unrelated capability. Shiproom proves only that its issued packet excludes the rubric—it cannot prove an operator did not disclose private material outside Shiproom.

Completion receipts are bound to the resolved participant. Guided or expert human work accepts only a human receipt; model work accepts only the exact candidate, provider, model, qualification ID, and qualification-bundle hash. Contract-only work may use a human or an unbound harness. Session 5 v3 currently supports SHA-1 Git repositories only: every general and typed source binding carries `git_object_format: sha1`, the exact 40-hex blob ID, a separate normalized-text SHA-256, and an independently bound quote hash. It fails closed for another Git object format.

Downstream definitions remain scoped to their declared requirement, criterion, or journey. An inspected commit-pinned definition has source-verified definition-content authority. A declared-external definition establishes only the owner declaration: its content remains `not_inspected` under `external_definition_declaration`, and execution and data accuracy remain independently unverified. The executable Session 5 closeout report resolves claim-specific tests and non-empty real workflow artifacts; passing totals alone do not close the session.

Typed source bindings preserve three independent dimensions: the prepared object type, the declaration authority, and the semantic-assessment authority. An exact owner-bound quote deterministically establishes only that the owner identified that range as (for example) an event, oracle, or pass-condition definition. A qualified reviewer may assess whether the content is adequate, but that judgment remains model-reviewed and never becomes deterministic eval-quality proof. Unlinked files remain candidates. Static source expansion is limited to literal one-hop imports from original seeds and one-hop helpers from exact tests; imported helpers never become recursive discovery seeds.

AI evaluation keeps all thirteen rungs separate: case candidate, fixed input, oracle/rubric, pass condition, criterion/journey linkage, prompt/model binding, known failure, fallback, malformed output, unavailable model, supplied execution, deterministic validation, and production trace linkage. LLM-judge calibration that is absent is reported as `not_established`, not as an automatically invalid evaluation. Shiproom does not certify judge validity, statistical representativeness, threshold quality, production model quality, or causal product impact.

Guidance eligibility is calculated by Python from closed predicates over the prepared packet. A reviewer may cite only eligible rules and must disposition every registered exception. Unknown material exceptions require abstention or owner confirmation. Model qualification is mechanically graded by capability; free-text persuasiveness is not a qualification signal. Qualification authority is an exact three-file bundle (rebuilt task, complete submitted result, derived receipt), regraded during preparation and generation loading; a standalone receipt is never trusted. Provider, model, harness, and executor identity remain provenance and do not affect substantive assessment IDs.

Canonical projection is executable: the overlay records verified semantic-record destination tuples. Contract proposals, gaps, AI claims, LLM-judge assessments, guidance-exception analyses, verifier dispositions, and batched journey owner questions must each appear exactly once in every registered destination. AI claim honesty is assertion-scope specific: configuration and eval structure need exact typed definition bases, offline behavior needs deterministic execution, runtime behavior needs deterministic runtime or trace evidence, and product outcomes need product-outcome runtime evidence. A readiness gap remains distinct from a release effect.

Guidance constrains reviewer reasoning; it is not project proof. Every formal warning needs separate project and guidance bases, considers documented exceptions, and remains within the packaged recommendation-effect ceiling. Counts are not categorically wrong, ratios are not automatically better, and insufficient context leads to abstention or owner confirmation. Owner/source fields are never overwritten by model proposals.

Measurement definitions may be inspected only at exact owner-supplied, commit-pinned paths. Definition presence does not prove execution, deployment, lineage, or data accuracy. AI eval source structure, supplied execution results, deterministic upstream evidence, and production traces remain separate maturity rungs. Langfuse, OpenTelemetry, logs, provider tracing, and custom tracing are vendor-neutral source candidates only.

This is not a Data Engineering, dbt, orchestration, warehouse, lakehouse, semantic-layer, BI, SQL-execution, or analytics-platform audit. Domain logic runs no model, SQL, warehouse, BI, Langfuse, browser, network, or external eval service, and it never changes findings, verdicts, release state, Product Intent, or the evidence graph.

## Historical judged-demo compatibility

The following workflow is retained solely for the historical buildathon demonstration. It is not the forward private-alpha product.

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

For the revised private-alpha product, Shiproom operates in `private_alpha` mode: it reads release-bound authority and produces review artifacts, but never delegates remediation, modifies the reviewed repository, or runs a fix workflow. Future private-alpha output may describe a team-owned remediation roadmap and closure contract only. The legacy `remediate` capability profile and its isolated-worktree behavior remain historical controlled-demo compatibility, not a forward private-alpha capability.

`shiproom init`, `shiproom project show`, and `shiproom doctor` make no outbound network calls by default. Use `shiproom doctor --probe` for explicit bounded connectivity checks.

Verify has no executable commands until normalized command grants have been explicitly added to the project contract and activated. Local review and remediation enforce the release-bound project authority; the historical public/external contract remains a separate workflow. Approved commands run in disposable Git worktrees with bounded output and timeouts, but this is not a complete OS, process, filesystem, or network sandbox.

Controlled reset is a validated single-use operation. It removes only the exact clean, commit-matched remediation worktree and branch, the selected release-state file, and exact release-recorded artifacts under ignored runtime roots.

## Product Intent (private alpha)

Product Intent is a `private_alpha` source-backed preparation step for later review. It never changes the customer repository, delegates remediation, runs project commands, probes a deployment, creates findings or verdicts. The separate `historical_judged_demo` workflow retains its controlled-demo remediation compatibility.

```powershell
shiproom intent prepare --release release-state/release.json --source docs/release-brief.md --supporting-source README.md
# Copy a specialist-produced intent-proposal.v1 into .shiproom/local/releases/<release_id>/product-intent/inbox/
shiproom intent compile --release release-state/release.json --proposal .shiproom/local/releases/<release_id>/product-intent/inbox/proposal.json
shiproom intent show --release release-state/release.json
```

Packets include complete normalized text only for selected Markdown files below the conservative cap; excluded and oversized inputs fail closed. Source reads are commit-pinned and retain Git blob and normalized-content hashes. Packets, proposals, compiled artifacts, and their atomic manifest stay under ignored local release state. Current release input outranks supporting project context, but conflicts remain visible as batched material ambiguities. Explicit records are directly source-backed; inferred records require owner confirmation and cannot be blocker-eligible.

See `docs/event-readiness.md` for the frozen runtime record, completed proofs, and live-service blockers. Deploy the patient/report after Cloudflare authentication with `npx wrangler deploy --config cloudflare/wrangler.toml`.
# Requirement-to-Evidence Graph (private alpha)

Prepare Product Intent first, then optionally prepare an explicit mapping-source packet and compile the read-only graph:

```powershell
shiproom graph mapping prepare --release <release.json> --path <repository-relative-file>
shiproom graph compile --release <release.json> [--proposal <release-local-inbox-proposal.json>]
shiproom graph show --release <release.json> [--criterion <criterion_id>]
```

Candidate code, test, and instrumentation mappings are traceability candidates only; they are not implementation, test, runtime, or closure proof. Graph artifacts are private ignored release-local state.

Mapping proposals live only in the graph inbox and bind to the active mapping packet. Valid targets are a packet-pinned repository reference, a packet-projected runtime or finding ID, or an allowlisted journey ID. Candidate mappings remain `model_mapped_candidate`; unsupported check types are recorded as import limitations, while absent inspection is `not_inspected` rather than missing evidence.

Each mapping entry uses exactly one target form (with the surrounding proposal's
release, commit, Product Intent, projection, and packet bindings copied from
the active packet):

```json
{"mapping_id":"route_candidate","criterion_id":"<packet criterion_id>","target_type":"implementation_reference","rationale":"Exact selected source.","reference":{"path":"demo_patient/server.py","returned_git_path":"demo_patient/server.py","git_blob_hash":"<packet blob hash>","start_line":1,"end_line":1,"quote":"<exact text>","quote_hash":"sha256:<exact quote hash>"}}
```

```json
{"mapping_id":"runtime_candidate","criterion_id":"<packet criterion_id>","target_type":"runtime_evidence","rationale":"Packet-projected canonical fact.","canonical_id":"<packet runtime_evidence_id or check_id>"}
```

```json
{"mapping_id":"finding_candidate","criterion_id":"<packet criterion_id>","target_type":"finding","rationale":"Packet-projected canonical finding.","canonical_id":"<packet finding id>"}
```

```json
{"mapping_id":"journey_candidate","criterion_id":"<packet criterion_id>","target_type":"critical_journey","rationale":"Allowlisted journey context.","journey_id":"<packet journey_id>"}
```

Canonical evidence remains true about the historical release even when its
criterion link is merely a candidate: candidate-linked failures leave the new
criterion `unknown`, and can never open or close its deterministic gap. Only
an exact indexed rerun lineage and a canonically closed finding can close a
deterministic runtime failure.

Criterion summaries expose `direct_relationships` and an ordered
`criterion_path`; every step includes `edge_id` plus `forward` or `reverse`
traversal. This keeps owner decisions, remediation, and closure auditable even
when their canonical edges point away from the criterion path.

## Portable assessment (private alpha)

`assessment prepare` issues immutable `shiproom.work-order.v3` documents with snapshotted role definitions and packaged result schemas. Core roles remain `2.0.0` with result v2; browser work uses role `3.0.0` and `browser-journey-result.v3`. Preparations use source-packet/work-order-manifest v3, completed assessment generations use `portable-assessment-manifest.v3`, browser artifacts use `browser-journey.v3`, and the derived presentation is `effective-assessment-view.v3`. Earlier packaged contracts and snapshots remain unchanged. Capabilities may be declared only through bounded JSON under `.shiproom/local/releases/<release_id>/assessment/inputs/`. Results belong only in the exact preparation/work-order inbox named by the work-order manifest:

| Boundary | Current contract |
|---|---|
| Preparation compiler | `assessment-preparation.v6` |
| Work order | `shiproom.work-order.v3` |
| Source packet / work-order manifest | `assessment-source-packet.v3` / `assessment-work-orders.v3` |
| Core roles and results | role `2.0.0`, result v2 |
| Browser role and result | role `3.0.0`, `browser-journey-result.v3` |
| Completion receipt / overlay | receipt v2 / overlay v2 |
| Assessment compiler / manifest | `portable-assessment.v6` / `portable-assessment-manifest.v3` |
| Browser artifact / derived view | `browser-journey.v3` / `effective-assessment-view.v3` |
| Pointer | `current-portable-assessment.v1` |

```text
.shiproom/local/releases/<release_id>/assessment/inbox/<preparation_id>/<work_order_id>/
  result.json
  completion-receipt.json
  evidence/
```

The result never hashes itself. The separate completion receipt binds the exact result bytes and records either human or harness provenance. Prepared packet-source citations are role-bound assessment provenance, not base-graph proof. Newly run shell output may inform reviewer rationale only and is never imported as deterministic command evidence.

Browser work is issued only for `browser_or_http` criteria with an exact release-authorized target plus available and granted browser capability. Every assessed criterion needs a same-criterion observation, every observation needs exclusively owned evidence, and every judgment cites a same-criterion observation. URLs are absolute ASCII HTTP(S), fragments are forbidden, queries remain exact, and the bounded redirect chain must start at an issued URL, end at the reported final URL, and remain inside the grant. Evidence paths are strict casefold-unique POSIX paths and the evidence directory must contain exactly the declared regular files. Bound PNG, JPEG, JSON, JSONL, or UTF-8 text artifacts are observations, not product truth by themselves. Invalid receipts, timestamps, media bytes, hashes, paths, redirects, or grants reject the whole browser result. A browser observation cannot establish implementation, test adequacy, finding closure, or verdict change.

`effective-assessment-view.v3` is derived-only. It exposes browser observation authority and model-reviewed judgment authority separately, with their respective IDs. It keeps the authoritative base evidence dimensions separate from Product, Engineering, test-adequacy, targeted-test, and browser judgments; it is never a replacement Requirement-to-Evidence Graph.

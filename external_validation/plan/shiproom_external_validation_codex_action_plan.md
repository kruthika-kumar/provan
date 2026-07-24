# Shiproom External Validation — Codex Execution Action Plan

**Document version:** 1.0  
**Source plan:** `shiproom_external_validation_testing_plan_v2.md`  
**Status:** Execution-ready  
**Goal:** Complete the beta, controlled comparison, remediation assessment, natural-PR cohort, and publication package as quickly as possible without weakening the study's evidence or fairness boundaries.

---

## 0. Executive decision

Execute the v2 testing plan in **six substantial Codex sessions**:

1. **Evaluation substrate, security, and run integrity**
2. **Dataset qualification, mutation governance, and cohort freeze**
3. **Beta execution, general repairs, and experiment freeze**
4. **Controlled benchmark production run**
5. **Adjudication, remediation comparison, and controlled-study analysis**
6. **Natural cohort, field evidence, and publication package**

These are durable execution boundaries, not narrow implementation fragments. Each session contains multiple internal parts. Codex should use a **reviewer agent at every mini-boundary**:

```text
execute Part A
→ inspect evidence
→ draft Part B implementation plan
→ reviewer agent critiques plan and evidence
→ revise Part B plan
→ execute Part B
→ reviewer agent audits closeout
```

Do not split the work further merely because a session has several phases. Split only when a durable freeze, claim boundary, or evidence-generation boundary requires it.

---

# Part I — Global operating contract

## 1. Source of truth

The normative methodology is:

```text
shiproom_external_validation_testing_plan_v2.md
```

This action plan governs sequencing and implementation. It does not weaken or replace the v2 methodological decisions.

When this document and v2 appear to conflict:

1. preserve v2's claim and evidence boundaries;
2. record the ambiguity;
3. ask the reviewer agent to resolve it from the two documents;
4. fail closed if the ambiguity could change case selection, ground truth, fairness, or public claims.

## 2. Repository and artifact separation

Use two roots.

### Version-controlled control plane

Recommended location:

```text
<shiproom-repo>/external_validation/
```

Contains:

- schemas;
- manifests;
- selection and qualification code;
- arm adapters;
- run scheduler;
- receipt validators;
- analysis code;
- prompts and policies;
- public reports;
- tests.

### External evidence root

Configured through:

```text
SHIPROOM_EXTERNAL_VALIDATION_ROOT
```

Contains:

- cloned patient repositories;
- containers and worktrees;
- large run outputs;
- raw logs;
- model receipts;
- hidden oracles;
- private mutations;
- adjudication packets;
- cached dependencies;
- temporary patches.

Large or private evidence must not be committed accidentally.

## 3. Protected boundaries

Before Session 1 changes anything:

- record the current Shiproom commit;
- confirm the main test and eval suites pass;
- snapshot protected public artifacts and schemas;
- record the clean working-tree state;
- create a dedicated validation branch;
- define which Shiproom production files may be modified during beta repairs.

After the beta freeze:

- no production Shiproom changes during controlled benchmark execution;
- no case-specific rules;
- no target-definition changes;
- no prompt changes;
- no model changes;
- no replacements except documented reproducibility failures under the frozen replacement rule.

## 4. Non-negotiable evidence rules

- Models do not establish ground truth.
- A natural PR does not have known complete ground truth.
- A fixed twin proves closure of the named target, not overall cleanliness.
- Missing analytics is not a finding without a measurement requirement.
- Repository type does not determine applicable review modules.
- A blocker requires a mandatory frozen criterion, repository policy, or owner/maintainer confirmation.
- `model_reviewed` and `agent_reported` cannot become deterministic proof.
- All clean, skipped, inconclusive, errored, budget-exceeded, and timed-out runs remain in results.
- Hidden tests, mutations, and oracles must not be exposed to evaluated arms.
- No auto-merge or production deployment is permitted.

## 5. Untrusted-code policy

Every evaluated repository must run in a disposable, resettable environment with:

- network disabled by default;
- explicit domain allowlist only where essential;
- no production credentials;
- no Docker socket;
- CPU, RAM, process, disk, and wall-time limits;
- read-only source before remediation mode;
- isolated writable worktree for remediation;
- complete command log;
- complete changed-file log;
- environment destruction after receipts are exported.

A repository that cannot run safely is excluded with a recorded reason.

## 6. Standard reviewer-agent mandate

Use this mandate for every internal review:

> Act as the independent validation-plan reviewer. Compare the proposed work and produced evidence against `shiproom_external_validation_testing_plan_v2.md`, this session prompt, the frozen manifests, and the current repository state. Look specifically for selection leakage, hidden-oracle leakage, case-specific tuning, unfair comparator inputs, incomplete receipts, unsafe execution, unsupported ground-truth claims, invalid exclusions, non-idempotent runs, and claims stronger than the evidence. Return `GO`, `REVISE`, or `STOP`; list every material issue with exact artifact references; and define the evidence required for closure. Do not approve based on summaries alone.

The implementing agent must answer every reviewer finding in a disposition table:

| Finding | Decision | Change made | Evidence | Residual limitation |
|---|---|---|---|---|

## 7. Required session closeout

Every session must end with:

- commit and branch;
- clean or explicitly documented working tree;
- commands run;
- tests and evals;
- reviewer-agent verdict;
- artifacts created;
- frozen hashes where applicable;
- open blockers;
- exact next-session entry condition;
- claim audit separating:
  - established;
  - provisionally supported;
  - not yet tested;
  - failed;
  - out of scope.

---

# Part II — Session map

## 8. Critical path

```text
Session 1
Evaluation substrate
    ↓
Session 2
Cases and cohorts frozen
    ↓
Session 3
Beta passes and experiment freezes
    ↓
Session 4
Controlled evidence generated
    ↓
Session 5
Evidence adjudicated and agency tested
    ↓
Session 6
Natural cohort and public package
```

Sessions 4–6 must not retroactively alter the frozen case selection or benchmark rules.

---

# Session 1 — Evaluation Substrate, Security, and Run Integrity

## 9. Objective

Build the complete reusable validation control plane before selecting outcomes:

- schemas and manifests;
- untrusted-code runner;
- arm interfaces;
- idempotent scheduling;
- run receipts;
- cost and price capture;
- hidden-oracle separation;
- validation and resume behavior;
- baseline tests.

This session should produce a system capable of running a synthetic smoke case through every arm adapter, even though final cases and prompts are not yet frozen.

## 10. Part A — Authority, architecture, and schemas

Implement:

1. `external_validation/README.md`
2. schema/version registry;
3. case manifest schemas for:
   - beta;
   - controlled paired cases;
   - natural PRs;
4. full run-receipt schema from v2;
5. applicability schema for:
   - Engineering;
   - Product Journey;
   - Product Measurement;
   - Data Contract/Pipeline;
   - AI/Eval;
6. evidence and adjudication enums;
7. immutable ID rules;
8. artifact-hash and provenance conventions;
9. external evidence-root contract;
10. protected-path and secret-leak rules.

Add validators that fail closed on:

- missing commit SHA;
- mutable branch reference where immutable SHA is required;
- incomplete cost receipt;
- unknown evidence type;
- missing applicability decision;
- inconsistent buggy/fixed pair;
- oracle path inside a visible patient repository;
- duplicate case or run IDs;
- case output written outside approved roots.

### Mini-boundary review

The reviewer agent must verify:

- exact alignment with v2;
- no combined generic `DATA` category;
- no star-based quality assumption;
- no natural-case recall fields;
- no hidden-oracle path leakage;
- no model-only ground-truth state.

Part B may start only after the architecture receives `GO`.

## 11. Part B — Disposable execution and arm adapters

Implement the execution substrate:

- disposable container or VM abstraction;
- default-deny network policy;
- resource ceilings;
- repository checkout by immutable SHA;
- clean reset between runs;
- read-only detection mode;
- writable remediation mode;
- command/file audit;
- timeout and termination receipts;
- dependency cache that does not leak outputs across arms;
- cold-cache and warm-cache execution modes.

Implement adapters for:

1. `NATIVE_CHECKS_ONLY`
2. `SHIPROOM_DETERMINISTIC_ONLY`
3. `SHIPROOM_FULL`
4. `SOTA_AGENT`
5. `SHIPROOM_NO_DETERMINISTIC_CORE`

At this stage, adapters may use a synthetic fixture rather than final prompts/models. They must already share:

- the same release packet;
- the same repository snapshot;
- the same tool and network policy;
- the same output schema;
- the same timeout mechanism.

## 12. Part C — Scheduler, receipts, and integrity tests

Implement:

- run queue;
- randomized arm order;
- deterministic seed support;
- idempotent run keys;
- resumable execution;
- retry policy that distinguishes infrastructure retry from a new experimental run;
- immutable raw receipt export;
- receipt checksum;
- aggregate run index;
- partial-run recovery;
- duplicate-run prevention;
- price-table versioning;
- token and cost normalization without discarding provider-native counts.

Create synthetic fixtures for:

- pass;
- known failure;
- timeout;
- malformed output;
- budget exceeded;
- unsafe command;
- hidden-oracle leak attempt;
- fixed-twin inconsistency;
- interrupted run and resume.

## 13. Session 1 acceptance gate

Required evidence:

- all new substrate tests pass;
- existing Shiproom tests/evals still pass;
- one synthetic case completes through all five adapters;
- unsafe execution is rejected;
- an interrupted run resumes without duplicating completed work;
- every run produces a schema-valid receipt;
- hidden oracle remains inaccessible;
- exact source and output hashes are recorded;
- reviewer closeout verdict is `GO`.

## 14. Session 1 stop conditions

Stop and repair before close if:

- untrusted code can access host secrets or Docker socket;
- receipt validation can be bypassed;
- arm adapters receive different case context unintentionally;
- caches leak one arm's findings to another;
- a failed run can be silently dropped;
- the validation layer modifies protected Shiproom artifacts without authorization.

## 15. Codex execution prompt — Session 1

```text
Execute Session 1 of the Shiproom External Validation action plan.

Read first:
- shiproom_external_validation_testing_plan_v2.md
- shiproom_external_validation_codex_action_plan.md
- current Shiproom architecture, schemas, tests, and external-evidence conventions

Objective:
Build the complete evaluation substrate, security boundary, arm interfaces, run receipts, resumable scheduler, and integrity tests. Do not select final benchmark cases yet.

Work in three parts:
A. Authority, schemas, and provenance
B. Disposable execution and arm adapters
C. Scheduler, receipts, and integrity tests

After Part A:
- inspect the actual diff and tests;
- create a concrete Part B plan;
- spawn an independent reviewer agent using the standard reviewer mandate;
- revise the plan until all material findings are resolved;
- execute Part B.

Repeat the same process before Part C and before session closeout.

Non-negotiables:
- fail closed;
- hidden oracles outside patient repos;
- no model output as ground truth;
- natural cases must not contain recall/true-negative claims;
- default-deny network;
- no production credentials or Docker socket;
- identical release packet and execution policy across model-using arms;
- idempotent resumable runs;
- provider-native token/cost data preserved;
- existing Shiproom behavior must remain stable.

Finish only when the Session 1 acceptance gate passes. Commit with:
feat: add external validation execution substrate
```

---

# Session 2 — Dataset Qualification, Mutation Governance, and Cohort Freeze

## 16. Objective

Convert the provisional v2 design into immutable execution inputs:

- qualify beta cases;
- qualify six fresh real engineering pairs;
- construct private mutations and hidden oracles;
- score repository consequence and review saturation;
- select primary repositories;
- enumerate and seed-select natural PRs;
- freeze prompts, model, prices, containers, manifests, and hashes.

No Shiproom or baseline outputs may be generated on candidate cases during selection.

## 17. Part A — Executable-pair qualification

Qualify:

### Beta

- BugsInPy FastAPI pair;
- BugsInPy HTTPie pair;
- two fresh post-cutoff engineering bug/fix pairs;
- one private Product Journey pair;
- one private Product Measurement or Data Contract pair.

### Main controlled benchmark

- six fresh real engineering pairs;
- three private engineering mutations;
- three private Product Journey mutations;
- two private Product Measurement mutations;
- two private Data Contract/Pipeline mutations;
- two private AI/Eval mutations.

For each pair, prove:

- buggy target oracle fails for the expected reason;
- fixed target oracle passes;
- protected/pass-to-pass checks are valid;
- setup stays within the case ceiling;
- no paid secret, GPU, or proprietary service is required;
- target requirement is frozen;
- hidden oracle is external;
- visible repository does not reveal mutation identity;
- case classification follows release surface, not repository identity.

Older public pairs are harness cases only and must be marked as such.

### Fresh-pair fallbacks

If six fresh pairs cannot be qualified:

1. use the next-most-recent reproducible case;
2. record contamination risk;
3. preserve the same selection rule;
4. do not silently replace with SWE-bench Verified as equivalent fresh evidence.

## 18. Part B — Independent mutation governance

For every private mutation:

- document the real incident/bug pattern it represents;
- have an independent reviewer agent inspect the mutation class and oracle without exposing them to evaluated arms;
- confirm the mutation is not a direct mirror of one narrow Shiproom rule;
- verify the fixed twin removes only the named target;
- hash mutation, oracle, visible patient snapshot, and fixed twin;
- generate a leakage scan proving hidden text/paths do not appear in visible context.

Create a private mutation inventory with access controls. The public manifest should contain only safe metadata.

### Mini-boundary review

The reviewer must explicitly answer:

- Does the case test a real release obligation?
- Is the target independently executable?
- Could Shiproom infer the mutation from leaked naming or fixtures?
- Is the fixed twin valid?
- Does the portfolio over-favor deterministic patterns already implemented?
- Are Product Measurement cases backed by explicit event contracts?
- Are privacy and `not_applicable` cases represented?

## 19. Part C — Repository consequence and maturity preflight

Evaluate the provisional natural pool without running Shiproom:

Primary pool:

- `healthchecks/healthchecks`
- `pretix/pretix`
- `pretalx/pretalx`
- `inventree/InvenTree`
- `pypa/hatch`
- `dlt-hub/dlt`
- `formbricks/formbricks`

Mature controls:

- `streamlit/streamlit`
- `pytest-dev/pytest`
- `dbt-labs/dbt-core`

Backups:

- `documenso/documenso`
- `paperless-ngx/paperless-ngx`
- `sqlfluff/sqlfluff`
- `evidentlyai/evidently`

For each candidate, record independently verifiable:

- adoption/consequence signals;
- review-saturation signals;
- supported execution path;
- authoritative context availability;
- language/runtime compatibility;
- safety constraints;
- applicable release surfaces;
- exclusion reasons.

Select six primary repositories using the frozen eligibility procedure. Do not choose based on expected defect yield.

## 20. Part D — PR frame and deterministic selection

For each selected primary repository:

1. enumerate PRs merged 120–540 days before freeze;
2. calculate reviewable churn;
3. remove excluded mechanical changes;
4. label release surfaces from authoritative context only;
5. publish the full candidate frame and exclusions;
6. choose one large PR using the public seed and deterministic hash order;
7. select one same-surface moderate PR merged within ±90 days;
8. verify immutable checkout and minimum execution path.

For each mature control:

- select one large PR using the same deterministic procedure.

Freeze:

- 12 primary natural PRs;
- 3 mature-control PRs;
- replacement order;
- retrospective 90-day evidence window;
- all PR SHAs and context packets.

## 21. Part E — Freeze prompts, models, prices, and manifests

Freeze:

- exact model/provider identifier available for execution;
- model settings;
- SOTA-agent prompt;
- Shiproom prompt/policy versions;
- arm tool permissions;
- current price table;
- container images;
- public random seed;
- beta manifest;
- controlled benchmark manifest;
- remediation subset selection rule;
- natural cohort manifest;
- owner-context repositories or documented public fallbacks.

Run a final cross-artifact integrity validator and hash the freeze packet.

## 22. Session 2 acceptance gate

Required:

- six beta pairs qualified;
- 18 controlled pairs qualified;
- all buggy/fixed oracles independently pass qualification;
- six primary repositories selected without Shiproom output;
- 15 natural PRs frozen;
- full selection frame and exclusions preserved;
- no hidden-oracle leakage;
- model, prompts, price table, containers, policies, and public seed frozen;
- all manifests schema-valid and hashed;
- reviewer verdict `GO`.

## 23. Session 2 stop conditions

Stop if:

- fewer than the minimum viable fresh/controlled portfolio can be qualified;
- selected PRs depend on expected findings;
- an event/instrumentation case lacks a frozen measurement contract;
- a natural Product/Data case lacks authoritative intent but is still labelled assessable;
- private mutations are visible to evaluated systems;
- the exact model or price version is not recordable;
- selection cannot be replayed deterministically.

## 24. Codex execution prompt — Session 2

```text
Execute Session 2 of the Shiproom External Validation action plan.

Objective:
Qualify and freeze every beta, controlled, remediation, and natural-cohort input without running evaluated review outputs on candidate cases.

Work in five parts:
A. Executable-pair qualification
B. Independent private-mutation governance
C. Repository consequence/review-saturation preflight
D. PR frame construction and deterministic selection
E. Model, prompts, prices, containers, manifests, and hash freeze

Use parallel subagents for:
- fresh-pair discovery and qualification;
- mutation/oracle construction;
- repository adoption and review-saturation evidence;
- natural PR enumeration and reviewable-churn computation.

Do not let any subagent run Shiproom or the SOTA review prompt on candidate natural PRs during selection.

After each part:
- inspect actual artifacts;
- create the next-part implementation plan;
- spawn the independent reviewer agent;
- resolve every material finding before execution continues.

Non-negotiables:
- release-surface classification, not repository-industry classification;
- Product Measurement requires an explicit event/decision contract;
- mature projects are controls, not presumed clean;
- natural PRs do not provide complete ground truth;
- public old benchmark cases are beta/harness cases only;
- hidden oracles remain external;
- selection frame and exclusions are preserved;
- public seed and deterministic ordering;
- exact immutable SHAs;
- no case substitution because a result may be inconvenient.

Finish only when the Session 2 freeze packet is complete and independently replayable. Commit with:
test: freeze external validation cases and cohorts
```

---

# Session 3 — Beta Execution, General Repairs, and Experiment Freeze

## 25. Objective

Run the complete beta, repair only general Shiproom or harness failures, rerun after material changes, derive the main-study resource ceilings, and freeze the production system for comparison.

This is the last session in which general Shiproom repairs may enter the controlled-study version.

## 26. Part A — Beta dry run and integrity check

Before model-using runs:

- verify all frozen hashes;
- rebuild containers;
- run native checks and hidden oracles independently;
- confirm arm context equality;
- confirm model, prompt, tool, and price versions;
- execute one non-scored dry run on a dedicated smoke fixture;
- verify receipt completeness and randomization.

No target case should be consumed as a dry-run fixture.

## 27. Part B — Six paired beta cases

Run buggy and fixed snapshots through:

1. `NATIVE_CHECKS_ONLY`
2. `SHIPROOM_DETERMINISTIC_ONLY`
3. `SHIPROOM_FULL`
4. `SOTA_AGENT`

Use the beta safety ceiling:

- maximum 30 minutes;
- maximum USD 5 billed model inference per model-using run.

Run two selected controlled cases three times to qualify repeatability.

Preserve all:

- outputs;
- timeouts;
- malformed findings;
- unsupported claims;
- receipts;
- target-detection mappings;
- applicability decisions;
- fixed-twin behavior.

## 28. Part C — Owner-context or public natural beta

Run three real beta cases in preferred order:

1. ordinary product with explicit critical journey;
2. product release changing events or measurement;
3. engineering or data-contract release.

Use public fallbacks only when owner-context access is unavailable, and record that substitution.

Evaluate:

- setup effort;
- context packet adequacy;
- module applicability;
- privacy/non-goal handling;
- quality of the owner-facing verdict;
- unsupported-claim rejection;
- report usability.

These runs do not contribute to target-recall claims.

## 29. Part D — Beta adjudication and repair plan

Produce a beta failure inventory:

- harness failures;
- security failures;
- general discovery failures;
- applicability errors;
- evidence-policy errors;
- model routing failures;
- cost/receipt gaps;
- case-specific misses;
- baseline failures.

Separate:

```text
general defect eligible for repair
case-specific behavior not eligible for special-casing
methodology issue requiring STOP
expected limitation
```

Create a repair plan. Spawn the reviewer agent to verify that every proposed repair is general and does not leak or encode target cases.

## 30. Part E — General repairs and full beta rerun

Apply only reviewer-approved general repairs.

After any material change to:

- Shiproom production logic;
- prompts;
- policy;
- receipt logic;
- applicability rules;
- arm interface;

rerun the complete beta.

Do not report only the improved subset.

## 31. Part F — Go/no-go and final freeze

Check beta gates:

- at least 11 of 12 paired snapshots complete;
- at least 5 of 6 targets detected;
- all reproducible fixed twins clear;
- zero unsupported claims promoted to deterministic proof;
- 100% receipt completeness;
- at least 8 of 9 applicability decisions correct;
- deterministic verdict identical across three repeats on two cases;
- at least 2 of 3 real beta repositories succeed.

Derive the common main-study ceiling from the worse p95 of Full Shiproom and SOTA Agent beta usage, subject to the v2 maximums.

Freeze:

- Shiproom commit;
- prompts and policy;
- model/settings;
- price table;
- containers;
- budget;
- all manifests;
- run scheduler;
- reviewer qualification report.

Tag the freeze.

## 32. Session 3 acceptance gate

Required:

- final beta run passes gates;
- beta report includes all failed and repeated runs;
- all general repairs are justified and independently reviewed;
- no case-specific logic exists;
- main-study budget is derived and frozen;
- Shiproom experiment commit/tag is immutable;
- reviewer verdict `GO_TO_CONTROLLED_BENCHMARK`.

If `NO_GO`, close with an exact blocker list rather than starting Session 4.

## 33. Codex execution prompt — Session 3

```text
Execute Session 3 of the Shiproom External Validation action plan.

Objective:
Run the full beta, repair only general product/harness failures, rerun after material changes, derive the resource ceiling, and freeze the experiment version.

Parts:
A. Frozen-artifact and smoke integrity check
B. Six paired beta cases across four arms
C. Three owner-context or public natural beta runs
D. Beta adjudication and general-repair plan
E. Reviewer-approved repairs and complete rerun
F. Go/no-go report, p95 budget derivation, and immutable freeze

Use parallel execution only where isolation, model quotas, and receipt integrity are preserved. A parallel worker must never share writable patient state with another arm.

At the Part D boundary:
- produce a complete failure inventory;
- distinguish general repairs from case-specific tuning;
- spawn the independent reviewer agent;
- do not implement repairs until the reviewer returns GO on the repair plan.

After repairs:
- rerun the complete beta;
- preserve pre-repair and post-repair results;
- do not discard failures.

Non-negotiables:
- old public pairs are harness evidence only;
- natural beta has no recall claim;
- model outputs are not ground truth;
- fixed twin clearance is explicit;
- no special-case rule for a named case/repo;
- no changing target definitions;
- all model/token/cost and applicability receipts complete;
- experiment freeze only after gates pass.

Commit the approved repair separately, then commit and tag the freeze:
test: qualify Shiproom external validation beta
```

---

# Session 4 — Controlled Benchmark Production Run

## 34. Objective

Generate the complete frozen controlled-study evidence without interpreting the result or modifying Shiproom.

This session is intentionally a production-run boundary. No outcome-driven repair is allowed.

## 35. Part A — Production preflight

Verify:

- freeze tag and hashes;
- exact 18 positive/fixed pairs;
- exact budget and price version;
- identical model version and settings;
- arm context equivalence;
- container images;
- default-deny network;
- raw receipt destination;
- random arm ordering;
- no hidden-oracle access;
- no uncommitted evaluation-code changes.

Create a signed preflight receipt.

## 36. Part B — Main 36-snapshot × four-arm run

Run:

```text
18 buggy snapshots
+ 18 fixed twins
× 4 primary arms
```

Primary arms:

- Native Checks Only
- SOTA Agent
- Shiproom Deterministic Only
- Full Shiproom

Schedule by case-family tranches:

1. fresh real Engineering;
2. private Engineering;
3. Product Journey;
4. Product Measurement;
5. Data Contract/Pipeline;
6. AI/Eval.

Tranches are operational checkpoints, not separate sessions.

After each tranche:

- validate receipt completeness;
- check for infrastructure corruption;
- confirm no hidden-oracle leak;
- compare arm input hashes;
- have the reviewer agent issue:
  - `CONTINUE`;
  - `RETRY_INFRASTRUCTURE_ONLY`;
  - or `STOP_FOR_INTEGRITY`.

Do not inspect performance to tune the system.

## 37. Part C — Six-pair deterministic-core ablation

Run `SHIPROOM_NO_DETERMINISTIC_CORE` on the six preselected pairs.

Verify that:

- deterministic results are genuinely unavailable;
- all other context/modules/prompts remain equivalent;
- no cached deterministic result leaks from previous runs;
- output schema remains identical.

## 38. Part D — Repeated-run stability

Run the six preselected repeated cases three times for model-using arms under reset cold-run conditions.

Record:

- target-detection consistency;
- finding overlap;
- severity;
- final verdict;
- evidence references;
- model cost;
- duration;
- termination.

If natural operating costs differ by more than 25%, execute the frozen matched-budget rerun rule on these six cases.

## 39. Part E — Evidence lock

After execution:

- validate every raw receipt;
- create immutable run index;
- hash all raw output directories;
- record missing or invalid runs;
- perform only infrastructure retries allowed by the frozen retry policy;
- close the production evidence set;
- prohibit subsequent modification.

Do not calculate or announce a winner in this session.

## 40. Session 4 acceptance gate

Required:

- every scheduled run has a valid terminal receipt or documented permanent failure;
- no arm-context mismatch;
- no hidden-oracle leak;
- no experimental product changes;
- retries comply with frozen policy;
- ablation integrity passes;
- repeated-run receipts complete;
- evidence set hashed and locked;
- reviewer verdict `EVIDENCE_SET_VALID`.

## 41. Session 4 stop conditions

Stop the entire benchmark if:

- the model version changes mid-run;
- hidden oracle becomes visible;
- one arm receives materially different context or tools;
- container/cache contamination is detected;
- outputs are lost without recoverable receipts;
- selection or target manifests change;
- any code change could affect evaluated behavior.

## 42. Codex execution prompt — Session 4

```text
Execute Session 4 of the Shiproom External Validation action plan.

Objective:
Generate and lock the complete controlled-comparison evidence set. Do not repair Shiproom, change prompts, change cases, or interpret outcomes.

Parts:
A. Signed production preflight
B. 36 snapshots across four primary arms
C. Six-pair no-deterministic-core ablation
D. Three-repeat stability runs and conditional matched-budget subset
E. Receipt validation and immutable evidence lock

Use a resumable parallel scheduler with strict case/arm isolation. Run by case-family tranches. After each tranche:
- validate receipt and input hashes;
- run hidden-oracle-leak checks;
- spawn the reviewer agent for CONTINUE / RETRY_INFRASTRUCTURE_ONLY / STOP_FOR_INTEGRITY.

Allowed retry:
- only infrastructure failures defined in the frozen policy.

Forbidden:
- case-specific tuning;
- prompt/model/policy changes;
- target changes;
- dropping bad outcomes;
- replacing inconvenient cases;
- using performance observations to modify later tranches;
- announcing comparative conclusions before evidence lock.

Finish with an immutable evidence index and reviewer verdict EVIDENCE_SET_VALID. Commit only run-index and integrity metadata, not mutable raw evidence:
test: execute frozen Shiproom controlled benchmark
```

---

# Session 5 — Adjudication, Remediation Comparison, and Controlled-Study Analysis

## 43. Objective

Turn the locked evidence into defensible results, test Shiproom’s remediation/closure claim, and produce the controlled-study report.

Evidence interpretation and remediation are combined because they share target oracles and closure standards, but the detection evidence remains immutable.

## 44. Part A — Blinded target mapping

Create normalized, blinded finding packets.

For every buggy case determine separately:

1. target detected;
2. evidence independently reproduced.

For every fixed twin determine:

3. named target cleared.

Where target mapping needs judgment:

- remove system identity;
- randomize finding order;
- preserve raw wording and evidence links;
- record adjudicator reason;
- preserve disagreement.

Do not collapse the three outcomes into one score.

## 45. Part B — Novel finding verification

For every novel blocker claim:

- attempt deterministic/browser/source reproduction;
- classify under v2 taxonomy.

For remaining findings, draw a stratified random sample covering:

- every arm;
- blocker and non-blocker;
- every release surface;
- deterministic and model-originated findings.

Prepare packets for two blinded senior Engineering adjudicators where execution cannot resolve the issue.

Report:

- agreement;
- disagreement;
- adjudicated category;
- unreviewed remainder;
- verification effort.

Do not infer precision for unreviewed model opinions.

## 46. Part C — Six-case remediation comparison

Use the preselected remediation subset:

- two Engineering;
- two Product Journey;
- one Product Measurement or Data Contract;
- one AI/Eval.

Compare:

- Full Shiproom;
- SOTA Agent.

Both receive:

- identical writable branch/worktree permissions;
- no auto-merge;
- same time/model budget policy;
- same hidden target oracle;
- same protected tests;
- same prohibited-path policy.

Measure:

- correct patch;
- target oracle pass;
- pass-to-pass/protected tests;
- prohibited changes;
- patch size;
- unrelated churn;
- exact failed-check rerun;
- independent closure evidence;
- escalation quality where no safe fix is possible;
- cost and wall time.

The fixer must not be the sole closer for Shiproom.

## 47. Part D — Statistical and economic analysis

Compute and publish:

### Primary controlled outcomes

- targets detected;
- evidence reproduced;
- fixed twins cleared;
- model cost per evidence-backed target.

### Secondary outcomes

- incremental targets beyond native checks;
- cases resolved without frontier inference;
- unsupported blocker rate;
- completion;
- time to evidence;
- applicability accuracy;
- stability;
- cold and warm cost;
- novel confirmed findings;
- remediation success and regressions.

Use:

- exact case-level table;
- paired differences;
- paired bootstrap intervals;
- McNemar test where appropriate;
- medians and distributions;
- no overpowered significance language.

Check the directional success rule from v2 without changing it.

## 48. Part E — Claim audit and controlled report

Draft:

```text
controlled_benchmark_report.md
remediation_comparison_report.md
limitations.md
```

The reviewer agent must audit every proposed headline against the actual tables.

Required claim categories:

- supported;
- directionally supported;
- mixed/tradeoff;
- not supported;
- not measured.

The report must include:

- all cases;
- failed and timed-out runs;
- fixed-twin persistence;
- rejected findings;
- price/version details;
- contamination limitations;
- sample-size limitation;
- exact ablation result;
- native-check baseline;
- remediation result.

## 49. Session 5 acceptance gate

Required:

- target outcomes adjudicated separately;
- novel blockers verified or correctly labelled;
- Engineering expert sample completed or transparently pending;
- remediation subset complete;
- all statistical tables reproducible from locked receipts;
- no result omitted;
- headline passes reviewer claim audit;
- controlled report and limitations complete;
- reviewer verdict `CONTROLLED_RESULT_PUBLISHABLE`.

## 50. Codex execution prompt — Session 5

```text
Execute Session 5 of the Shiproom External Validation action plan.

Objective:
Adjudicate the locked controlled evidence, run the six-case remediation comparison, calculate reproducible results, and produce a claim-safe controlled-study report.

Parts:
A. Blinded target detection/evidence/clearance mapping
B. Novel-finding verification and stratified expert packets
C. Six-case Full Shiproom vs SOTA remediation comparison
D. Statistical, cost, ablation, and stability analysis
E. Claim audit and controlled-study reports

Keep the Session 4 detection evidence immutable.

Use reviewer-agent gates:
- after target mapping;
- before launching remediation;
- before accepting aggregate tables;
- before approving any headline.

Non-negotiables:
- target detection, evidence reproduction, and fixed-twin clearance are separate;
- model judgment is not ground truth;
- unverified findings remain unverified;
- no precision claim from unreviewed findings;
- report native checks as the floor;
- report the no-deterministic ablation;
- preserve failures/timeouts;
- directional result only for the 18-pair sample;
- fixer cannot self-close Shiproom remediation;
- no auto-merge.

Commit with:
docs: publish controlled Shiproom validation results
```

---

# Session 6 — Natural Cohort, Field Evidence, and Publication Package

## 51. Objective

Run the frozen natural cohort, add retrospective and owner-value evidence, compare large and moderate PRs, and publish the complete external validation package.

The natural cohort demonstrates real-world usefulness. It does not provide complete ground truth.

## 52. Part A — Natural-cohort execution

Run all 15 frozen PRs.

Minimum arms:

- `NATIVE_CHECKS_ONLY`;
- `SHIPROOM_FULL`.

Run `SOTA_AGENT` on the six primary large PRs as a predeclared exploratory comparison if that subset is included in the Session 2 frozen manifest. Do not add the subset after seeing Shiproom results.

For every PR:

- use merge-commit-faithful checkout/preview;
- load only temporally valid authoritative context;
- run applicable modules only;
- record `not_applicable` and `not_assessable`;
- preserve privacy and non-goal constraints;
- retain all failures and skips.

## 53. Part B — Retrospective evidence

Within the frozen 90-day post-merge window, search for:

- explicit revert;
- linked regression issue;
- follow-up fix naming the PR/commit;
- regression test failing at merge and passing after fix;
- maintainer confirmation.

Use SZZ-style methods only to locate candidates, never as ground truth.

Classify findings using the v2 natural taxonomy.

## 54. Part C — Verification and large-vs-moderate comparison

Attempt reproduction for every blocker.

For the six primary repositories compare:

- large PR;
- same-surface matched moderate PR.

Report:

- verified finding yield;
- source-backed gaps;
- unsupported findings;
- not-assessable rates;
- module applicability;
- cost;
- duration;
- review-saturation and consequence band;
- retrospective confirmation.

Do not report repository bug prevalence or natural-case recall.

## 55. Part D — Owner-context evidence and case studies

Consolidate the three beta owner-context runs.

Assess:

- whether the report helped a release decision;
- whether a missing-context refusal was useful;
- whether Product Measurement respected privacy/non-goals;
- which findings the owner accepted, rejected, or corrected;
- setup burden;
- decision burden;
- whether exact evidence reduced review effort.

Select three to five public examples **only after aggregate results are complete**:

- one Product Journey;
- one Engineering;
- one Measurement/Data/AI;
- one clean/no-verified-blocker case;
- one not-applicable/not-assessable case where useful.

Label examples as illustrative, not the source of aggregate claims.

## 56. Part E — Final publication package

Publish:

- v2 methodology;
- Codex execution plan;
- frozen manifests;
- candidate frames and exclusions;
- public random seed;
- model/prompt/policy/container/price versions;
- beta report;
- controlled report;
- remediation report;
- natural cohort report;
- case-level tables;
- cost and token receipts;
- rejected/unverified findings;
- errors and timeouts;
- limitations;
- reproducibility instructions;
- public case studies;
- LinkedIn-ready factual summary.

The public summary must use exact counts and claim categories approved by the reviewer agent.

## 57. Session 6 acceptance gate

Required:

- 15 natural PRs have terminal receipts;
- all blocker claims receive a verification attempt;
- large/moderate comparison complete;
- retrospective evidence window processed;
- owner-context evidence incorporated without mixing it into ground-truth metrics;
- examples selected only after aggregate lock;
- no “X% of repos have bugs” language;
- full package reproducible;
- reviewer verdict `FINAL_PACKAGE_PUBLISHABLE`.

## 58. Codex execution prompt — Session 6

```text
Execute Session 6 of the Shiproom External Validation action plan.

Objective:
Run and verify the frozen 15-PR natural cohort, compare large and matched moderate PRs, integrate owner-context evidence, and publish the complete external-validation package.

Parts:
A. Natural cohort execution
B. Retrospective 90-day evidence review
C. Finding verification and large-vs-moderate analysis
D. Owner-context evidence and post-aggregate case-study selection
E. Final publication package and claim audit

Minimum natural arms:
- Native Checks Only
- Full Shiproom

Run any SOTA natural subset only if it was explicitly frozen in Session 2.

Non-negotiables:
- natural PRs do not have known complete ground truth;
- no recall or repository-defect-prevalence claim;
- Product/Data may return not_applicable or not_assessable;
- run historical commits, not today's production as historical proof;
- mature controls are not presumed clean;
- every blocker receives a verification attempt;
- illustrative cases selected only after aggregate lock;
- preserve failures, clean cases, skips, and rejected findings;
- exact counts and limitations in public summary.

Use reviewer-agent gates after:
- cohort execution;
- retrospective classification;
- aggregate analysis;
- headline/case-study selection;
- final publication build.

Commit with:
docs: publish Shiproom external validation cohort
```

---

# Part III — Cross-session execution controls

## 59. Commit and freeze sequence

Recommended commit sequence:

```text
Session 1
feat: add external validation execution substrate

Session 2
test: freeze external validation cases and cohorts

Session 3
fix: repair general external validation failures
test: qualify Shiproom external validation beta
tag: external-validation-experiment-v1

Session 4
test: execute frozen Shiproom controlled benchmark

Session 5
docs: publish controlled Shiproom validation results

Session 6
docs: publish Shiproom external validation cohort
tag: external-validation-publication-v1
```

A repair commit in Session 3 is created only when the beta finds a valid general defect.

## 60. Parallelization rules

Parallelize:

- fresh-pair qualification across independent subagents;
- repository evidence collection;
- PR frame enumeration;
- isolated case/arm runs;
- receipt validation;
- retrospective issue mining;
- independent finding reproduction.

Do not parallelize through shared mutable state.

Every parallel worker needs:

- unique patient worktree;
- unique output root;
- immutable input hashes;
- independent receipt;
- no access to other arm outputs;
- no hidden-oracle access.

## 61. Retry policy

Retry without creating a new experimental observation only for:

- container startup failure;
- provider transport failure before model completion;
- corrupted dependency download;
- runner crash before the evaluated system receives the task;
- infrastructure interruption explicitly covered by the frozen policy.

Do not retry merely because:

- the system missed the target;
- it produced poor output;
- it timed out after useful work;
- it exceeded budget;
- its tests failed;
- the finding was unsupported.

## 62. Change-control policy

### Before beta freeze

Allowed:

- general production fixes;
- harness repairs;
- applicability-policy corrections;
- receipt and sandbox fixes.

Requires:

- reviewer approval;
- full beta rerun after material change.

### After beta freeze

Forbidden:

- Shiproom logic changes;
- prompt or policy changes;
- case changes;
- target changes;
- output-schema semantic changes;
- resource-ceiling changes;
- model changes;
- selection changes.

An integrity failure after freeze requires stopping and either:

- restarting the entire affected experiment under a new version; or
- publishing the limitation and excluding the experiment from comparative claims.

## 63. Fast-path rules

To finish quickly without compromising validity:

- build one reusable control plane in Session 1;
- qualify cases in parallel in Session 2;
- keep only six beta pairs and three real beta runs;
- freeze after one general repair cycle where possible;
- run the controlled benchmark through an idempotent parallel queue;
- use the 18-pair result as directional rather than expanding scope;
- keep the natural cohort at 15 PRs;
- do not add dashboards beyond what is required to inspect receipts and reports;
- do not add languages that fail preflight;
- do not add extra comparator models;
- do not expand the cohort after results;
- publish limitations rather than running an endless methodology programme.

---

# Part IV — Completion definition

## 64. Programme complete when

All are true:

- evaluation substrate is secure and reproducible;
- frozen beta passes;
- 18 paired controlled targets and fixed twins are executed;
- native, SOTA, deterministic-only, and full Shiproom results exist;
- six-case deterministic-core ablation exists;
- six-case remediation comparison exists;
- target detection, evidence, and closure are separately adjudicated;
- 15 natural PRs are executed;
- large vs matched moderate comparison exists;
- owner-context evidence is documented;
- all costs and tokens are traceable;
- all failures, rejections, and limitations are public;
- reviewer agent approves final claim language;
- artifacts are tagged and reproducible.

## 65. Final public claim template

Populate only with established results:

> On a frozen set of 18 executable release failures and their fixed twins, Shiproom detected **[N]** targets compared with **[M]** for a strong frontier repository agent. It used **[X%]** less median billed model inference, attached independently reproducible evidence to **[A/B]** detected targets, and correctly cleared **[C/18]** fixed twins. Across 15 frozen natural PRs, it produced **[P]** execution- or source-confirmed findings, returned `not_applicable` or `not_assessable` in **[Q]** cases, and preserved all clean, failed, and inconclusive outcomes.

If the directional success rule is not met, use the tradeoff language from the controlled report instead of this template.

# Shiproom External Validation and Comparative Testing Plan — v2

**Document version:** 2.0  
**Status:** Execution reference  
**Supersedes:** `shiproom_external_validation_testing_plan_v1.md`  
**Primary objective:** Test whether Shiproom's deterministic-first release-assurance architecture preserves most of a strong frontier agent's useful coverage while reducing inference cost, improving reproducibility, and correctly refusing to overclaim when product or data intent is unavailable.

---

## 0. Executive decisions

V2 changes the study in six material ways.

1. **Classify the PR by the release obligation it changes, not the repository by the industry of its maintainer.** A dbt PR is not automatically a Data case; a survey, ticketing, inventory, or SaaS PR may be the strongest Product Measurement case.
2. **Split “Data” into three testable surfaces:** Product Measurement, Data Contract/Pipeline, and AI/Evaluation. They have different applicability rules and different oracles.
3. **Use mid-maturity, consequence-qualified projects as the primary natural cohort.** Use highly mature projects as controls for scale, review saturation, and false-positive behavior—not as the only place where Shiproom is expected to find issues.
4. **Use paired, executable cases for ground-truth claims.** Natural PRs measure verified finding yield and practical usefulness; they do not support complete recall claims.
5. **Add project-native CI as a baseline and use fresh/private tasks to reduce benchmark contamination.** Older public bug benchmarks remain useful for harness qualification, but not as the main evidence against a frontier model.
6. **Add a six-case remediation subset.** Shiproom is supposed to own detect → fix → exact rerun, not merely emit review comments.

The central public claim, if supported, should be:

> **On a frozen set of executable release failures, Shiproom achieved comparable target detection to a strong frontier repository agent while using materially less model inference and attaching reproducible evidence to more findings.**

It should not be:

> “Shiproom found all the bugs,” “data companies have data gaps,” or “popular repositories are clean.”

---

# Part I — First-principles model of the evaluation

## 1. What Shiproom is actually trying to assure

Shiproom is not a generic defect miner. Its object is a release outcome:

```text
release promise
→ applicable release obligations
→ deterministic and semantic checks
→ evidence-backed findings
→ bounded remediation
→ independent closure proof
```

Therefore, a useful evaluation case needs as much of the following as the case legitimately provides:

- a repository and immutable commit;
- a PR, issue, specification, documentation statement, or release contract;
- an expected behavior or invariant;
- an executable surface such as tests, CLI, API, browser journey, schema, pipeline, or eval;
- a way to determine whether the target failure exists;
- for closure tests, a fixed twin or valid remediation oracle.

A repository's topic, stars, or employer is not itself a release contract.

## 2. Four distinct questions and their evidence

| Question | Dataset | Legitimate conclusion |
|---|---|---|
| Does Shiproom execute reliably on unfamiliar code? | Beta | Product/harness readiness |
| Does the deterministic-first architecture improve cost and evidence at comparable target coverage? | Controlled paired benchmark | Comparative architectural result |
| What does Shiproom find on real, non-cherry-picked PRs? | Natural cohort | Verified finding yield, applicability, cost, and failure modes |
| Does Shiproom help its intended owner make a shipping decision? | Owner-context field pilot | User value and decision usefulness |

These questions must not be collapsed into one percentage.

---

# Part II — Critical audit of v1

## 3. Audit findings

### A. Construct validity and module applicability

| # | Severity | Finding in v1 | Why it matters | V2 correction |
|---:|---|---|---|---|
| 1 | Critical | Repositories were classified as Product, Engineering, or Data by what the project builds. | The unit Shiproom reviews is a release/PR. A data-tool PR may be a parser refactor; an ordinary SaaS PR may change analytics, migrations, and success events. | Tag each PR by release surface after a context-only preflight, before any review output is seen. |
| 2 | Critical | “Data” combined product analytics, data reliability, and AI evaluation. | These require different inputs and oracles. Combining them makes both selection and results uninterpretable. | Use separate tags: `PRODUCT_MEASUREMENT`, `DATA_CONTRACT_PIPELINE`, and `AI_EVAL`. |
| 3 | Critical | Missing telemetry could be interpreted as a data gap. | Open-source products may intentionally avoid telemetry for privacy, self-hosting, or scope reasons. Absence alone is not a defect. | Product Measurement applies only when a release contract requires a measurable event, the PR changes instrumentation/experimentation, or the owner asks for it. Otherwise return `not_applicable` or `missing_context`. |
| 4 | High | Data-native repositories were implicitly expected to produce Data findings. | Selecting dbt, Dagster, or MLflow does not imply they are deficient. It may instead create a domain-specialist, heavily tested control. | Include data-native repositories only for applicable schema/pipeline/eval PRs or as mature controls. Never state an expected defect direction. |
| 5 | High | Product review could run without an authoritative product promise or journey. | Without intent, Shiproom can test build/runtime facts but cannot determine whether behavior satisfies the intended product. | Require an issue, PR description, documentation promise, acceptance criterion, or owner-provided contract. Otherwise Product findings remain `not_assessable`. |
| 6 | High | “Product-facing” included several developer libraries and frameworks. | Streamlit, FastAPI, and HTTPie have product surfaces, but they are not substitutes for ordinary transaction and workflow products. | Primary product candidates now include monitoring, ticketing, conference, inventory, and signing/survey workflows. Developer tools remain a distinct surface. |
| 7 | High | The plan did not explicitly test correct module skipping. | A selective system creates value partly by not running irrelevant reviews. | Add applicability accuracy and privacy-aware `not_applicable` behavior as measured outcomes. |

### B. Repository maturity, consequence, and sampling

| # | Severity | Finding in v1 | Why it matters | V2 correction |
|---:|---|---|---|---|
| 8 | Critical | The natural cohort over-weighted famous, mature repositories. | These projects may have deeper CI, more reviewers, and more user feedback. They are useful controls, but may understate Shiproom's expected value in smaller teams. | Use six consequence-qualified, mid-maturity projects as the primary cohort and three highly mature projects as controls. |
| 9 | High | Stars were treated too close to a user/quality measure. | GitHub describes stars as bookmarks and an approximate signal of interest; they do not directly measure active users, review quality, or business consequence. | Use a portfolio of adoption and consequence signals. Stars are one screening input only. |
| 10 | High | The plan did not distinguish popularity from review saturation. | A project can be popular but maintained by few people, or modestly starred but deeply deployed. | Measure adoption evidence and review-saturation evidence separately, before outcomes are observed. |
| 11 | High | Very small repositories were not explicitly excluded from headline prevalence claims. | They may yield defects but have little demonstrated user consequence and poor external validity for Shiproom's target buyer. | Use small projects only for controlled cases unless they show independent adoption/consequence evidence. |
| 12 | Critical | “Largest eligible PR” was the sole natural-PR selector. | This over-selects migrations, refactors, imports, and mechanical work, even after exclusions, and may miss the release surfaces Shiproom is meant to assess. | Select from a surface-eligible large-PR frame using a published random seed; add matched moderate PRs. |
| 13 | High | The PR-size threshold was not adapted to repo size and change type. | A 1,500-line change can be extreme in one project and routine in another. | Require absolute and relative size: reviewable churn threshold or repository top percentile, plus source-file and subsystem breadth. |
| 14 | High | There was no matched ordinary-PR comparison. | Without it, the “large PRs are especially hard to assure” thesis is not tested. | For each primary mid-maturity repository, select one same-surface moderate PR near the large PR's merge date. |
| 15 | High | The study could compare an old PR with today's live site. | Current production may contain many later fixes, invalidating the inference. | Check out and run the tested commit or a commit-faithful preview. Today's live surface is used only for current releases. |

### C. Ground truth and benchmark validity

| # | Severity | Finding in v1 | Why it matters | V2 correction |
|---:|---|---|---|---|
| 16 | Critical | Natural PRs were close to being treated as if their complete defect set could be known. | Neither the researcher nor a SOTA scan can prove all defects present or absent. | Natural cohort reports only verified findings, unverified concerns, and `no verified blocker found`; it does not report recall or true negatives. |
| 17 | Critical | A thorough SOTA-model scan could be mistaken for ground truth. | It is another reviewer and may share errors or training exposure with the evaluated systems. | Models may normalize and deduplicate, but ground truth requires executable, browser, source, maintainer, or expert evidence. |
| 18 | Critical | V1 relied substantially on older public bug benchmarks for the main comparison. | Frontier models may have seen public issues, patches, or benchmark tasks. In 2026, SWE-bench Verified was publicly criticized for contamination and flawed tests. | Use old benchmarks only for beta harness qualification. Main comparisons use private mutations and fresh post-cutoff executable bug/fix pairs. |
| 19 | High | Controlled mutations could be tailored to Shiproom's current rules. | This would overstate the deterministic core's value. | Derive mutation classes from real bugs, author them outside Shiproom, hide manifests/oracles, and freeze them before runs. |
| 20 | High | The fixed twin was present but not fully separated from a “clean repository” claim. | A fixed twin proves a named target is closed; it does not prove the snapshot has no other defects. | Call it target clearance, not overall cleanliness. |
| 21 | High | Historical bug-introducing commit mining was not bounded. | SZZ-style methods are noisy and can misidentify inducing commits. | Use SZZ only to generate candidates. Accept a pair only after direct reproduction and explicit evidence. |
| 22 | Medium | Benchmark reproducibility was assumed rather than treated as a qualification result. | Public bug datasets can rot because of dependencies and environments. | Every case must pass a containerized preflight; failures are replaced by the predefined rule and logged. |

### D. Comparator fairness and economics

| # | Severity | Finding in v1 | Why it matters | V2 correction |
|---:|---|---|---|---|
| 23 | Critical | Project-native CI was absent as a formal baseline. | Shiproom's value must be incremental to tests/build/lint already present, not merely incremental to doing nothing. | Add `NATIVE_CHECKS_ONLY` on every controlled snapshot. |
| 24 | Critical | The SOTA baseline could receive a different practical task than Shiproom. | Unequal context, tools, or evidence requirements confound architecture with prompting. | Give the same frozen release packet, repository, shell/browser permissions, time ceiling, and output/evidence contract. |
| 25 | High | The deterministic-only arm was treated like a complete competitor. | It is an ablation/floor, not the full product. | Report it as architectural decomposition, not as the main alternative. |
| 26 | High | A fixed USD 3 / 20-minute cap was arbitrary. | It may truncate one arm more often and create an artificial winner. | Observe beta usage under a safety cap, then freeze a common main-study ceiling from the worse p95 of the two principal arms, capped for safety. |
| 27 | High | Dollar cost alone was insufficient. | Prices, caching, and tokenization change. Local execution also has cost and latency. | Preserve tokens, calls, cache use, wall time, compute seconds, external-tool charges, and contemporaneous prices. |
| 28 | High | Cold and repeated-repository economics were mixed. | Shiproom may gain most after deterministic project discovery is cached. The baseline may also reuse indexes. | Report cold runs as primary and symmetrical warm sequential-review runs as secondary. |
| 29 | Medium | Run-order effects were not fully controlled. | Caches, rate limits, and transient services can bias results. | Randomize arm order and run in isolated, resettable environments. |

### E. Metrics, adjudication, and claims

| # | Severity | Finding in v1 | Why it matters | V2 correction |
|---:|---|---|---|---|
| 30 | High | The 2/1/0/−2 score mixed detection, evidence, and closure. | A single number hides why a system succeeded or failed. | Report three separate binary outcomes: target detected, evidence reproduced, fixed twin cleared. |
| 31 | High | Evidence-backed rate risked verification bias. | Easy-to-reproduce findings may be verified more often than difficult findings or one system's findings. | Attempt verification for all target findings and a stratified random sample of novel findings from every arm. |
| 32 | High | One engineer reviewing ten findings was too weak for broad precision claims. | Expert judgments vary, and the sample may not represent all arms/severities. | Use two blinded engineers on a stratified sample; report agreement and disagreements. |
| 33 | High | Severity could be inferred without owner policy. | “P0” or release blocker depends on impact, scope, and policy. | Use source-defined severity or “Shiproom blocker under contract”; otherwise report technical impact without P0/P1 language. |
| 34 | High | Eighteen targets were treated close to a definitive experiment. | It is sufficient for a directional product proof, not a narrow scientific non-inferiority claim. | Retain 18 for speed, publish exact counts and paired intervals, and label the result directional. Expand to 30+ fresh pairs before a strong general claim. |
| 35 | High | The plan omitted a repair-quality comparison. | Shiproom's product promise includes branch fixes and exact reruns. | Add a six-case remediation subset with patch correctness, protected-test pass, scope, cost, and closure evidence. |
| 36 | High | Untrusted public repositories could be executed without an explicit security policy. | Build scripts can access the network, filesystem, credentials, or excessive resources. | Use disposable, network-restricted containers, no production secrets, read-only mounts where possible, and CPU/memory/time limits. |
| 37 | Critical | Public OSS alone did not faithfully represent Shiproom's intended buyer context. | Product and measurement intent often lives with the release owner, not in the repository. | Add three owner-context field runs in the beta, with public fallbacks only when owner access is unavailable. |

---

# Part III — Revised taxonomy

## 4. Release-surface tags

A PR may receive multiple tags. One tag is declared primary for sampling.

| Tag | Applies when | Typical evidence | Must not be inferred from |
|---|---|---|---|
| `ENGINEERING_EXECUTION` | Build, tests, API/CLI contracts, config, artifacts, failure handling, deployment behavior change | Exit codes, tests, schemas, files, HTTP responses | Repository fame or language alone |
| `PRODUCT_JOURNEY` | User-visible or operator-visible workflow changes and an authoritative promise/journey exists | Browser trace, API sequence, screenshot, observable state | “Frontend files changed” without intent |
| `PRODUCT_MEASUREMENT` | Release contract names a success/failure event or the PR changes analytics, experiments, funnels, event schemas, or business-state instrumentation | Event fixture, payload/schema assertion, deduplication/timing invariant | Absence of telemetry in a privacy-conscious OSS project |
| `DATA_CONTRACT_PIPELINE` | Schema, migration, model grain, transformations, ingestion, exports, lineage, quality contracts, freshness, or reconciliation changes | dbt/data tests, schema checks, fixtures, row invariants | Being maintained by a data company |
| `AI_EVAL` | Prompts, models, retrieval, ranking, evals, safety/fallback, or model-output claims change | Frozen eval IDs, deterministic fixtures, expected labels, fallback tests | Use of an AI SDK with no release impact |

## 5. Data applicability decision

The Data/AI review must answer these gates in order:

```text
1. Does the release contract make a measurable data/AI claim?
2. Does the PR change an event, metric, experiment, schema, pipeline, model, retrieval path, or eval?
3. Is the required evidence available or explicitly expected?
4. Is telemetry constrained or prohibited by privacy/non-goal policy?
```

Outcomes:

- **Applicable:** run the relevant sub-surface checks.
- **Not applicable:** no relevant release obligation changed.
- **Missing context:** a judgment requires owner intent that is unavailable.
- **Accepted constraint:** privacy or scope intentionally excludes the evidence; retain the constraint visibly.

“Analytics are absent” is never, by itself, a finding.

## 6. Repository maturity and consequence bands

Do not call stars “users.” Construct two pre-outcome scores.

### 6.1 Adoption/consequence evidence

Count independently verifiable signals:

- hosted service or documented public instances;
- package downloads or downstream dependents;
- Docker pulls or deployed integrations;
- workflow handles money, inventory, alerts, documents, schedules, or another consequential state;
- external issue/discussion authors from multiple organizations;
- frequent releases and non-maintainer usage reports.

A primary natural-cohort repository must have at least **two** such signals.

### 6.2 Review-saturation evidence

Record:

- active maintainers and contributors;
- human review participation per PR;
- required CI/check breadth;
- merge latency;
- external issue volume;
- organization-backed engineering capacity where publicly evident.

### 6.3 Sampling bands

| Band | Role in study |
|---|---|
| Consequence-qualified, moderate review saturation | Primary natural cohort; closest public proxy for Shiproom's expected leverage |
| High consequence, high review saturation | Mature control; tests scale, applicability, and false alarms |
| Low consequence or very small | Controlled cases only unless owner-context evidence establishes real impact |

Maturity is a sampling dimension, not an assumption that one band contains bugs.

---

# Part IV — Stage A: Beta

## 7. Beta scope

The beta has two components:

1. **Six paired executable cases** to qualify the harness and evidence policy.
2. **Three owner-context or public natural runs** to test applicability and usability.

### 7.1 Six paired beta cases

| ID | Source | Surface | Target |
|---|---|---|---|
| B-ENG-01 | BugsInPy FastAPI reproducible pair | Engineering | Known JSON-encoding regression |
| B-ENG-02 | BugsInPy HTTPie reproducible pair | Engineering | Known filename/download regression |
| B-FRESH-01 | Fresh executable bug/fix pair selected by preflight | Engineering | Post-cutoff real defect with failing/passing oracle |
| B-FRESH-02 | Fresh executable bug/fix pair selected by preflight | Engineering | Different repository and defect class |
| B-PROD-01 | Private Launch Card/reference app mutation | Product journey | Returned result URL fails while UI claims success |
| B-DATA-01 | Private ordinary-product or dbt fixture | Product measurement or data contract | Success/failure event conflation or entity-grain violation |

The two older public cases are **harness sanity checks only**. Do not use them as headline evidence against a frontier model.

### 7.2 Three real beta runs

Preferred order:

1. A consenting ordinary product repository with an explicit critical journey.
2. A consenting product repository whose release changes events/measurement.
3. A consenting engineering or data-contract repository.

Public fallbacks:

- `healthchecks/healthchecks` — product/operations workflow;
- `pretalx/pretalx` — submission, review, scheduling, and public-release workflow;
- `dlt-hub/dlt` or `pypa/hatch` — data-contract or engineering workflow.

The real beta runs are not ground-truth benchmark cases. Their purpose is to expose setup, context, module-selection, and report-quality failures.

## 8. Beta arms

Run:

- `NATIVE_CHECKS_ONLY`;
- `SHIPROOM_DETERMINISTIC_ONLY`;
- `SHIPROOM_FULL`;
- `SOTA_AGENT` on the six paired cases.

The natural/owner-context beta runs may use only Full Shiproom first; run the SOTA baseline when environment cost permits.

## 9. Beta safety ceiling and gates

Use a safety stop of **30 minutes and USD 5 of billed model inference per model-using run**. This is an observation ceiling, not the final comparison budget.

Proceed only when:

| Gate | Requirement |
|---|---:|
| Paired-run completion | At least 11 of 12 buggy/fixed snapshots |
| Target detection | At least 5 of 6 buggy cases |
| Target clearance | 6 of 6 fixed twins, or all reproducible fixed twins |
| Unsupported claim promoted to deterministic proof | 0 |
| Cost/token/evidence receipt completeness | 100% |
| Module applicability correctness | At least 8 of 9 manually labelled beta decisions |
| Repeatability | Deterministic verdict identical across three repeats on two cases |
| Natural-run setup success | At least 2 of 3 real repositories |

General repairs are allowed during beta. Case-specific rules are not.

---

# Part V — Stage B: Controlled comparative benchmark

## 10. Dataset composition

Use **18 positive cases and 18 fixed twins**.

| Case family | Positive pairs | Purpose |
|---|---:|---|
| Fresh real engineering bug/fix pairs | 6 | Ecologically valid executable defects with reduced contamination risk |
| Private engineering mutations | 3 | Deterministic/core failure classes hidden from all systems |
| Private product-journey mutations | 3 | Promise-to-runtime assurance |
| Private product-measurement mutations | 2 | Instrumentation in ordinary products where an event contract is explicit |
| Private data-contract/pipeline mutations | 2 | Schema, grain, relationship, or transformation assurance |
| Private AI/eval mutations | 2 | Frozen eval and fallback assurance |
| **Total** | **18** | **Directional comparative result** |

Each positive case has a fixed twin. A fixed twin establishes closure of the named target only.

## 11. Fresh real-pair qualification

Prefer tasks from a continuously refreshed benchmark such as SWE-rebench or a fresh GitHub-Actions-derived corpus.

Eligibility:

- issue and fix created after the frozen model knowledge cutoff where feasible;
- Python/Linux or another language Shiproom has explicitly qualified;
- clear expected behavior;
- target test fails on the buggy revision for the expected reason;
- target test passes on the fixed revision;
- pass-to-pass checks remain valid;
- no paid credential, GPU, or proprietary service;
- target path completes within 15 minutes;
- no more than two cases from one repository;
- web search disabled during all evaluated runs.

If fewer than six fresh pairs qualify, use the next-most-recent reproducible cases and disclose the contamination risk. Do not silently substitute SWE-bench Verified as equivalent evidence.

## 12. Private target catalogue

### 12.1 Engineering

- claimed artifact is not created;
- public response/schema drifts from the declared contract;
- failure is swallowed and reported as success.

### 12.2 Product journey

- returned share/result URL fails;
- required state is lost after refresh/navigation;
- backend failure produces a false success state.

### 12.3 Product measurement

- success and failure emit indistinguishable terminal events;
- a release-required success event is omitted or emitted before the durable outcome.

These cases use ordinary product applications and a frozen event contract. They are not tests of whether every OSS product should collect telemetry.

### 12.4 Data contract/pipeline

- join changes entity grain and creates duplicates;
- required key becomes null or loses referential integrity.

### 12.5 AI/eval

- release gate samples random cases rather than frozen versioned IDs;
- unsupported model output has no required fallback or is reported as valid success.

## 13. Mutation governance

- Derive classes from real incident/bug patterns.
- Keep mutation code, target manifest, and hidden oracle outside the visible repository.
- Have at least one person or independent process other than the Shiproom implementation author create or review each mutation.
- Freeze hashes before running any arm.
- Do not alter a case because one system misses it.

---

# Part VI — Experimental arms and fairness

## 14. Primary arms

### Arm A — `NATIVE_CHECKS_ONLY`

Run the repository's documented or safely discovered build, test, lint, type, schema, and existing browser checks. No model.

This establishes what the project already catches without Shiproom.

### Arm B — `SOTA_AGENT`

A strong frontier repository agent receives:

- the same frozen release packet as Shiproom;
- repository and immutable snapshot;
- shell, test, and browser access where applicable;
- the same network restrictions;
- the same time ceiling;
- a strong standardized release-assurance prompt;
- the same finding/evidence output schema.

It may plan, inspect, run tests, and iterate. This is not a weak one-shot prompt.

### Arm C — `SHIPROOM_DETERMINISTIC_ONLY`

Runs project discovery, native checks, schema/file/HTTP/browser assertions, and deterministic requirement-evidence checks. No frontier semantic reviewer.

This is an architectural floor/ablation, not the complete product.

### Arm D — `SHIPROOM_FULL`

Runs the deterministic core first and escalates selectively to semantic review under Shiproom's evidence policy.

### Arm E — `SHIPROOM_NO_DETERMINISTIC_CORE`

Run on six representative pairs only. Preserve Shiproom's release context, modules, prompts, and finding schema, but hide deterministic check results. This isolates the incremental contribution of the deterministic core.

## 15. Input fairness

The primary task is **contract-aware release assurance**, not blind bug hunting.

Every model-using arm receives the same:

- product/release promise or issue statement;
- target user and critical journey when applicable;
- PR diff and repository snapshot;
- explicit non-goals/privacy constraints;
- available documentation;
- allowed tools;
- evidence definitions.

The hidden oracle and mutation are never revealed.

On six cases, optionally run a secondary open-ended scan with the target-specific requirement removed. Label it separately.

## 16. Model and environment fairness

Freeze:

- exact provider/model/version;
- temperature or equivalent controls;
- prompts and policy versions;
- tool set;
- Shiproom commit;
- container image;
- release packet;
- case manifest;
- contemporaneous model prices.

Use the same frontier model for Shiproom semantic calls, the SOTA agent, and the no-deterministic ablation.

Randomize arm order per case. Reset containers and caches between cold runs.

## 17. Main-study budget rule

During beta, observe cost and latency for Full Shiproom and SOTA Agent.

Set the common main-study ceiling to:

```text
wall-clock ceiling
= rounded-up worse p95 beta wall time
= maximum 30 minutes

model-spend ceiling
= rounded-up worse p95 beta model spend
= maximum USD 5
```

Freeze both before the main run.

Report:

- cold-run inference cost;
- cold-run total variable cost;
- warm sequential-review cost on a secondary subset;
- input, cached-input, output, and reasoning tokens where available;
- model calls and tool calls;
- local compute duration;
- external-tool charges;
- wall-clock time.

If natural operating costs differ by more than 25%, run the six repeated cases again under matched dollar budgets and show the cost-quality curve.

---

# Part VII — Primary outcomes

## 18. Controlled-benchmark primary metrics

Do not collapse these into one score.

### 18.1 Target detected

Binary, on the buggy snapshot:

```text
Did the system identify the named release failure
at the correct behavioral or implementation locus?
```

### 18.2 Evidence reproduced

Binary:

```text
Can the submitted evidence independently reproduce
or source-verify the target failure?
```

### 18.3 Fixed twin cleared

Binary:

```text
Does the system stop claiming the named target as unresolved
on the fixed snapshot?
```

### 18.4 Model cost per evidence-backed target

```text
total billed model cost
/
targets both detected and evidence-reproduced
```

## 19. Secondary metrics

- incremental targets beyond native checks;
- percentage of cases resolved without a frontier call;
- unsupported blocker rate;
- time to first evidence-backed target;
- total run completion;
- finding and verdict consistency across repeats;
- applicability classification accuracy;
- human adjudication minutes;
- cold-to-warm cost change;
- novel execution-confirmed findings;
- protected-test regressions after remediation.

## 20. Analysis

For the 18-pair study:

- publish exact case-level outcomes;
- use paired confidence intervals/bootstraps for differences;
- use an exact paired test such as McNemar's test where appropriate;
- report medians and distributions, not only means;
- label the result **directional** because the sample is small.

Do not claim a narrow scientific non-inferiority result from 18 targets. Expand to at least 30 fresh pairs before a stronger general statement.

## 21. Directional success rule

Treat the architecture as supported directionally when Full Shiproom:

1. detects at least **14 of 18 targets** and finishes no more than **two targets behind** the SOTA Agent;
2. reduces median billed model cost by at least **40%** relative to the SOTA Agent;
3. improves evidence reproduction by at least **20 percentage points**;
4. has fixed-twin false persistence no worse by more than **one case**;
5. resolves at least **35%** of controlled cases without a frontier semantic call;
6. produces zero deterministic blocker claims without qualifying evidence.

If these conflict, report the tradeoff rather than declaring a winner.

---

# Part VIII — Remediation subset

## 22. Six cases

Select before results:

- two Engineering;
- two Product Journey;
- one Product Measurement/Data Contract;
- one AI/Eval.

Compare Full Shiproom and SOTA Agent with identical branch permissions and no auto-merge.

## 23. Remediation outcomes

- correct patch created;
- hidden target oracle passes;
- pass-to-pass/protected tests pass;
- no prohibited files changed;
- patch size and unrelated churn;
- exact original failure rerun;
- independent closure evidence;
- model cost and wall time;
- escalation quality when a safe fix is unavailable.

This subset supports Shiproom's agency claim. The detection benchmark alone does not.

---

# Part IX — Natural PR cohort

## 24. Purpose

The natural cohort tests:

- operational robustness;
- module applicability;
- verified finding yield;
- evidence quality;
- cost and latency;
- behavior across maturity bands;
- whether large PRs produce more verified gaps than matched moderate PRs.

It does **not** estimate complete recall or prove that a PR was defect-free.

## 25. Provisional repository pool

### 25.1 Primary, consequence-qualified mid-maturity pool

Select six after environment and adoption preflight:

| Repository | Why it belongs in the pool | Likely applicable surfaces |
|---|---|---|
| `healthchecks/healthchecks` | Real monitoring product with dashboard, API, alerts, and hosted use | Product Journey, Engineering, operational state semantics |
| `pretix/pretix` | Transactional ticketing product where orders, payments, and tickets have real consequences | Product Journey, Engineering, Data Contract |
| `pretalx/pretalx` | Conference workflow from submissions through review, schedule, and public release | Product Journey, Engineering, workflow-state/data semantics |
| `inventree/InvenTree` | Inventory and stock-control product with Python/Django backend and API | Product Journey, Engineering, Data Contract |
| `pypa/hatch` | Developer workflow product covering builds, environments, tests, and publishing | Engineering, CLI/artifact contracts |
| `dlt-hub/dlt` | Python data-loading library with typed schemas/contracts and many destinations | Engineering, Data Contract/Pipeline |
| `formbricks/formbricks` | Ordinary product-measurement and survey workflows with explicit privacy positioning | Product Journey, Product Measurement, privacy constraints |

Select six by the frozen eligibility procedure. If JS/TS execution is not qualified, defer Formbricks and use the owner-context measurement case instead of pretending another repo supplies equivalent evidence.

### 25.2 Mature controls

| Repository | Control role |
|---|---|
| `streamlit/streamlit` | Mature user/developer product control |
| `pytest-dev/pytest` | Mature engineering/review control |
| `dbt-labs/dbt-core` | Mature data-domain control |

These are not presumed clean. They test scale, review saturation, applicability, and unsupported-finding behavior.

### 25.3 Backups

- `documenso/documenso` — consequential signing workflow;
- `paperless-ngx/paperless-ngx` — document-management workflow;
- `sqlfluff/sqlfluff` — engineering/data-contract tooling;
- `evidentlyai/evidently` — AI/eval domain-specialist control.

## 26. Repository eligibility

Before outcomes are observed, require:

- public, non-archived, and cloneable;
- usable open-source license;
- active releases/merges in the sampling window;
- reproducible target path without production secrets;
- at least two adoption/consequence signals;
- enough authoritative release context for the intended surface;
- compatible execution environment;
- no mandatory GPU or inaccessible paid service on the selected path.

## 27. PR sampling frame

Use PRs merged **120 to 540 days before cohort freeze**. This leaves at least a 90-day retrospective outcome window.

A large PR must satisfy:

```text
reviewable churn >= 1,000
OR
repository top 5% by reviewable churn with churn >= 500
```

and:

- at least 10 human-authored source files;
- at least two meaningful components/subsystems;
- not dependency-only, formatting-only, generated, vendored, snapshot-heavy, or rename-only;
- an identifiable release surface;
- reproducible checkout and minimum execution path.

Reviewable churn excludes lockfiles, generated/vendor code, minified assets, snapshots, and mechanical changes.

## 28. Non-cherry-picked selection

For each primary repository:

1. enumerate eligible large PRs;
2. label release surfaces without running Shiproom;
3. publish the candidate frame and exclusions;
4. select one eligible large PR using a public seed and deterministic hash ordering;
5. select one moderate PR from the same primary surface, merged within ±90 days, with 100–500 reviewable lines;
6. freeze PR numbers and SHAs.

For each mature control, select one eligible large PR using the same seeded procedure.

Natural cohort total:

```text
6 primary repositories × (1 large + 1 matched moderate) = 12 PRs
3 mature controls × 1 large PR = 3 PRs
Total = 15 PRs
```

If a repository has no eligible PR, replace it using the frozen backup order. Do not choose a more “interesting” PR after seeing results.

## 29. Natural-PR context packet

Include only authoritative, temporally valid sources:

- PR body and review discussion;
- linked issue/specification;
- documentation at the base and merge commits;
- release notes;
- tests and repository authority files;
- owner-provided promise/non-goals when available.

If no authoritative product or data intent exists:

- Engineering may still run;
- Product/Data returns `not_assessable` or `not_applicable`;
- missing context is not converted into a defect.

Run the merge commit locally or in a commit-faithful preview. Do not use today's production behavior as proof about a historical PR.

## 30. Retrospective evidence window

Within 90 days after merge, search for:

- explicit revert;
- linked regression issue naming the PR/commit;
- follow-up fix referencing the regression;
- regression test that fails at the merge commit and passes after the fix;
- maintainer confirmation.

Classify:

- `retrospectively_confirmed_regression`;
- `execution_confirmed_novel_finding`;
- `source_or_maintainer_confirmed`;
- `plausible_unverified`;
- `incorrect`;
- `no_verified_blocker_found`.

`No issue found in 90 days` is not a true negative.

Use SZZ-style mining only to locate candidate inducing commits. It cannot establish ground truth by itself.

## 31. Natural-cohort reporting

Report by PR and aggregate:

- selected/skipped modules and reasons;
- execution-confirmed findings;
- source-backed gaps;
- model-reviewed recommendations;
- unsupported findings rejected;
- no-verified-blocker and not-assessable outcomes;
- large versus matched-moderate verified yield;
- model tokens/cost and wall time;
- review-saturation and consequence band;
- retrospective confirmations;
- Shiproom errors/timeouts.

Never report “X% of repositories contain bugs” from this cohort.

A defensible statement is:

> “Across 15 frozen natural PRs, Shiproom produced N execution- or source-confirmed findings, declined to assess Product/Data intent in M cases, and used a median of $X in model inference.”

---

# Part X — Adjudication

## 32. Target findings

For controlled cases, an oracle determines:

- target exists on buggy snapshot;
- target is closed on fixed twin;
- attached evidence actually reproduces the target.

Normalize outputs and blind system identity before target mapping where human judgment is needed.

## 33. Novel findings

Attempt reproduction for every novel blocker claim.

For the remaining novel findings, draw a stratified random sample across:

- all arms;
- blocker and non-blocker severities;
- Engineering, Product, Measurement, Data, and AI surfaces;
- deterministic and model-originated findings.

Classify:

- `execution_confirmed`;
- `browser_confirmed`;
- `source_confirmed`;
- `maintainer_confirmed`;
- `expert_confirmed`;
- `plausible_unverified`;
- `incorrect`;
- `duplicate`;
- `out_of_scope`.

Use two blinded senior engineers for sampled unexecutable Engineering findings. Report inter-rater agreement and preserve disagreements.

## 34. Severity

A finding may be called a release blocker only when:

- the frozen release contract says the criterion is mandatory;
- repository policy defines the severity; or
- an owner/maintainer confirms it.

Otherwise use technical language such as:

- execution-confirmed regression;
- critical journey failure under the test contract;
- missing mandatory evidence;
- model-reviewed concern.

---

# Part XI — Security and execution controls

## 35. Untrusted-code policy

- disposable container/VM per run;
- network disabled by default and domain allowlist only when essential;
- no production credentials;
- read-only source mount until a remediation branch is explicitly enabled;
- CPU, memory, process, disk, and wall-time limits;
- no Docker socket exposure;
- record all commands and files changed;
- destroy environment after receipt export.

## 36. Required run receipt

```yaml
case_id:
dataset: beta | controlled | natural
snapshot: buggy | fixed | natural_pr
arm: native_checks | sota_agent | shiproom_deterministic | shiproom_full | shiproom_no_deterministic
repository:
pr_number:
base_sha:
target_sha:
release_surface_tags: []
maturity_band:
shiproom_commit:
container_image:
model:
model_version:
prompt_version:
policy_version:
price_version:
started_at:
completed_at:
termination: completed | timeout | error | budget_exceeded

applicability:
  engineering:
  product_journey:
  product_measurement:
  data_contract_pipeline:
  ai_eval:

native_checks:
  attempted:
  passed:
  failed:
  skipped:
  duration_seconds:

model_usage:
  calls:
  input_tokens:
  cached_input_tokens:
  output_tokens:
  reasoning_tokens:
  tool_calls:
  billed_cost_usd:

findings:
  - finding_id:
    target_id:
    origin:
    severity:
    evidence_status:
    evidence_refs:
    reproduction_status:
    adjudication:

totals:
  wall_time_seconds:
  local_compute_seconds:
  model_cost_usd:
  external_tool_cost_usd:
```

---

# Part XII — Execution sequence

## 37. Step 1: Preflight and freeze

1. Implement complete run receipts.
2. Qualify two BugsInPy beta cases.
3. Qualify two fresh beta pairs and six fresh main pairs.
4. Build and independently review private mutations/oracles.
5. Score repository adoption and review saturation without viewing Shiproom output.
6. Enumerate and seed-select natural PRs.
7. Freeze model, prompts, policies, containers, prices, manifests, and public random seed.
8. Hash all artifacts.

## 38. Step 2: Beta

1. Run all six buggy/fixed pairs.
2. Run three owner-context or fallback natural cases.
3. Repeat two controlled cases three times.
4. Repair only general failures.
5. Rerun the complete beta after material changes.
6. Issue a go/no-go report.

## 39. Step 3: Controlled benchmark

1. Randomize arm order.
2. Run 18 buggy and 18 fixed snapshots through four primary arms.
3. Run the no-deterministic ablation on six pairs.
4. Blind and score targets.
5. Verify novel findings by the stratified protocol.
6. Run six-case remediation comparison.
7. Calculate paired quality, evidence, cost, and stability results.

## 40. Step 4: Natural cohort

1. Run 15 frozen PRs.
2. Preserve clean, inconclusive, skipped, failed, and timed-out runs.
3. Complete retrospective evidence review.
4. Verify blocker claims.
5. Compare large and matched moderate PR yield.
6. Select public case studies only after aggregate results are complete.

## 41. Step 5: Publish

Publish:

- v2 plan and frozen manifests;
- selection frame and exclusions;
- model/environment/price versions;
- all case-level controlled outcomes;
- cost and token receipts;
- rejected and unverified findings;
- errors and timeouts;
- natural-cohort case table;
- limitations;
- three to five illustrative examples from the already frozen cohorts.

---

# Part XIII — Decisions now closed

## 42. Closed methodology decisions

- PR/release-surface classification replaces repository-industry classification.
- Data is split into Product Measurement, Data Contract/Pipeline, and AI/Eval.
- Missing telemetry is not a defect without a requirement.
- Mid-maturity, consequence-qualified projects form the primary natural cohort.
- Highly mature repositories are controls.
- Small/low-consequence repositories are controlled-case material, not headline prevalence evidence.
- Natural PRs do not provide complete ground truth.
- Older public bug benchmarks are beta/harness material only.
- Main controlled comparison uses 18 private/fresh paired targets and fixed twins.
- Native project checks are a formal baseline.
- Same model, context, tools, output contract, and resource ceiling are required for model-using arms.
- Cold cost is primary; warm sequential cost is secondary.
- Detection, evidence, and closure are separate outcomes.
- Six remediation cases test actual agency.
- Six primary natural repositories plus three mature controls yield 15 PRs with matched moderate changes.
- Selection uses a published deterministic seed, not “largest PR wins.”
- The initial comparative result is directional, not a universal scientific claim.

## 43. Operational choices remaining

These are preflight outputs, not unresolved methodology:

- exact fresh bug/fix instance IDs;
- exact six primary repositories that pass environment and consequence preflight;
- exact natural PR numbers and SHAs;
- final owner-context repositories;
- final current frontier-model identifier;
- main-study budget derived from beta p95;
- independent mutation reviewer and two Engineering adjudicators;
- frozen price table.

---

# Part XIV — Final compact reference

```text
BETA
- 6 paired executable cases
- 3 owner-context/public natural runs
- Purpose: harness, evidence policy, applicability, usability

CONTROLLED COMPARISON
- 18 buggy targets + 18 fixed twins
- Native CI, SOTA agent, deterministic Shiproom, full Shiproom
- 6-case no-deterministic ablation
- 6-case remediation subset
- Purpose: detection, evidence, closure, cost, and agency

NATURAL COHORT
- 6 consequence-qualified mid-maturity repositories
- 1 seeded large + 1 matched moderate PR each
- 3 mature-control repositories with 1 seeded large PR each
- 15 PRs total
- Purpose: real-world verified yield, applicability, scale, and large-PR comparison

NON-NEGOTIABLE CLAIM BOUNDARIES
- Data-native repo does not imply a data defect
- Missing analytics is not a defect without a measurement contract
- Popularity is not ground truth or quality
- Natural PRs do not support recall
- Fixed twin proves target closure, not overall cleanliness
```

---

# Research and repository references

- GitHub, [REST API endpoints for starring](https://docs.github.com/rest/activity/starring): stars indicate an approximate level of interest.
- GitHub, [Saving repositories with stars](https://docs.github.com/en/get-started/exploring-projects-on-github/saving-repositories-with-stars): stars are also bookmarks/appreciation signals.
- McIntosh et al., [The Impact of Code Review Coverage and Code Review Participation on Software Quality](https://posl.ait.kyushu-u.ac.jp/~kamei/publications/McIntosh_MSR2014.pdf).
- OpenAI, [Why SWE-bench Verified no longer measures frontier coding capabilities](https://openai.com/index/why-we-no-longer-evaluate-swe-bench-verified/).
- SWE-rebench, [About](https://swe-rebench.com/about) and [GitHub organization](https://github.com/SWE-rebench).
- BugsInPy, [official repository](https://github.com/soarsmu/bugsinpy).
- Defects4J, [official repository](https://github.com/rjust/defects4j).
- Lyu et al., [Evaluating SZZ implementations: an empirical study](https://arxiv.org/html/2308.05060v2).
- Candidate repositories: [Healthchecks](https://github.com/healthchecks/healthchecks), [pretix](https://github.com/pretix/pretix), [pretalx](https://github.com/pretalx/pretalx), [InvenTree](https://github.com/inventree/InvenTree), [Hatch](https://github.com/pypa/hatch), [dlt](https://github.com/dlt-hub/dlt), [Formbricks](https://github.com/formbricks/formbricks), [Streamlit](https://github.com/streamlit/streamlit), [pytest](https://github.com/pytest-dev/pytest), and [dbt-core](https://github.com/dbt-labs/dbt-core).

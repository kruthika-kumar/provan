# Contract Foundry (historical 0.5.0; semantic successor 0.5.1)

Contract Foundry is an `IMPLEMENTED_UNQUALIFIED` source-only capability until Gate 12. It proposes an Acceptance Contract surface for explicit Session 11 owner disposition. It neither establishes evidence nor creates owner, policy, verifier, execution, or challenge authority.

```text
provan acceptance foundry --brief <canonical-brief-id> --source-manifest sources.json --depth standard --no-model
provan acceptance patterns
provan acceptance patterns --show community.pattern.api_schema_backward_compatibility.v1
```

The manifest accepts at most 32 contained UTF-8 `.txt`, `.md`, `.json`, `.yaml`, or `.yml` files. Text/Markdown is limited to 512 KiB each; structured files to 1 MiB each, depth 32, and 50,000 nodes; aggregate input is limited to 8 MiB. Binary, PDF, DOCX, HTML, device, FIFO, socket, linked/reparse, absolute, traversing, replaced, or invalid UTF-8 inputs are rejected.

Standard uses the frozen order: blind intent -> goal/obstacle -> bounded pre-mortem -> proposal -> adversarial audit -> at most one revision -> witnesses -> pattern selection -> readiness. Deep requires two stateless isolated blind paths, each producing a candidate or structured critique before synthesis. No call uses persistent conversation state, `previous_response_id`, or background mode.

The configured live provider identity is `openai-responses-primary` at `https://api.openai.com`. Tier 1 is explicitly pinned to `gpt-5.6-luna` with medium reasoning and requires workload qualification; Tier 2 is pinned to `gpt-5.6-sol` with high reasoning; Tier 3 is pinned to `gpt-5.6-sol` with xhigh reasoning. The model-list endpoint validates only the configured model and never chooses or upgrades it. All semantic calls are stateless with `reasoning.context=current_turn`, no `previous_response_id`, and no background mode. `store:false` is a requested transport setting only and does not establish zero provider retention. The `scripted-test` provider is deterministic test infrastructure and can never qualify semantic output. Live semantic egress additionally requires an exact operator-confirmed `PUBLIC_SAFE` digest closure in `model_egress_authorization`; filesystem selection or a source role alone never authorizes transmission.

Seven earlier `gpt-5.2` calls are preserved as `PRE_STEERING_LEGACY_MODEL_RUN` sensitivity/development evidence. They are not eligible for final semantic qualification, headline Arms A–D comparison, Deep qualification, or Community quality claims. Responses-API Arms A/B are frontier prompt baselines, not coding-harness comparisons. Using Sol for both Deep paths does not establish provider or model-family independence.

`contract_readiness` describes owner-review readiness of the proposal and evidence/oracle plan. `run_eligibility` describes whether required roles were available. Pattern selection never means pattern execution. `execution_available` and `challenge_available` remain false.

## Semantic successor boundary

The unpublished `0.5.1` successor remains `IMPLEMENTED_UNQUALIFIED` and `GO_SESSION_13:NO` until the additive successor closeout passes. Historical `0.5.0` artifacts and schemas are not rewritten.

Before statement extraction, the successor reads each selected source once and creates an immutable private-local Source Bundle. Every later semantic stage consumes that frozen snapshot. A live-source reread can only confirm digest continuity; it cannot replace run input. Raw bundle bytes are excluded from telemetry, public and client-safe views, package members, proof artifacts, and cache names. Terminal cleanup produces a digest-bound deletion tombstone.

Source coverage partitions every text or Markdown UTF-8 byte span. JSON and YAML scalar leaves are also accounted by canonical JSON Pointer. Every item is semantic, explicitly non-semantic with a reason, explicitly ignored with reason and authority, or unresolved. YAML comments remain textual coverage spans and are contextual/untrusted by default: they may surface a proposal, conflict, or owner question, but cannot establish mandatory authority or silently disappear through parser comment loss.

Standard runs Source Bundle → coverage → statement authority → blind intent → goal/obstacle → pre-mortem → candidate → adversarial audit → at most one revision → witnesses → semantic freeze → implementation-aware mapping → pattern/oracle/capability planning → readiness → projection. Deep uses two stateless blind paths against the same frozen input, freezes both before synthesis, and permits at most two revisions. Auditors see only frozen upstream artifacts; revisers see the explicit frozen candidate and audit. No semantic role inherits hidden provider conversation state.

The implementation-aware stage binds the exact immutable candidate digest and Session 10 changed-file, entity, relationship, schema, API, test, and CI surfaces after the blind semantic freeze. It is source-only, read-only, non-authoritative, cannot rewrite Blind Intent, and reports unsupported, unresolved, and not-discoverable mappings. A mutable candidate is explanatory only and always forces `NOT_READY`.

Pattern selection requires a criterion, failure dimension, oracle/evidence need, future capability, and distinct verification contribution. Select-all is forbidden. Broad portfolios require a distinct material basis for every pattern. A material mutation changes portfolio membership, criterion-pattern binding, dimension, oracle, or capability requirement; wording-only change does not require pattern-ID churn.

The compact owner-review view is selected with `--view owner-review` and contains, in order: `Sources require`, `Provan inferred`, `Audit changed`, `Intentionally non-mandatory`, `Ambiguities`, `Patterns & evidence`, and `Owner decisions`. It retains canonical proposal refs and never creates Acceptance authority.

Use `--information-boundary blind` for the default qualified boundary. `implementation-informed` is explicit, degraded, and cannot reach owner-confirmation readiness. Source Bundle and internal-run artifacts remain private-local; the v2 owner projection alone enters the existing Session 11 disposition path.

The successor records actual wall time, model calls, input/output/reasoning tokens when reported, and cost status/amount per case. It does not infer percentiles from the bounded sample. Public real use, six semantic stability runs, and semantic dogfood must finish before the implementation/model/prompt/policy/scorer freeze and authoritative `0.5.1` wheel build. Protected hidden evaluation occurs once afterward and cannot be tuned within this successor.

# Contract Foundry (unreleased 0.5.0)

Contract Foundry is an `IMPLEMENTED_UNQUALIFIED` source-only capability until Gate 12. It proposes an Acceptance Contract surface for explicit Session 11 owner disposition. It neither establishes evidence nor creates owner, policy, verifier, execution, or challenge authority.

```text
provan acceptance foundry --brief <canonical-brief-id> --source-manifest sources.json --depth standard --no-model
provan acceptance patterns
provan acceptance patterns --show community.pattern.api_schema_backward_compatibility.v1
```

The manifest accepts at most 32 contained UTF-8 `.txt`, `.md`, `.json`, `.yaml`, or `.yml` files. Text/Markdown is limited to 512 KiB each; structured files to 1 MiB each, depth 32, and 50,000 nodes; aggregate input is limited to 8 MiB. Binary, PDF, DOCX, HTML, device, FIFO, socket, linked/reparse, absolute, traversing, replaced, or invalid UTF-8 inputs are rejected.

Standard uses the frozen order: blind intent -> goal/obstacle -> bounded pre-mortem -> proposal -> adversarial audit -> at most one revision -> witnesses -> pattern selection -> readiness. Deep requires two stateless isolated blind paths, each producing a candidate or structured critique before synthesis. No call uses persistent conversation state, `previous_response_id`, or background mode.

The configured live provider identity is `openai-responses-primary` at `https://api.openai.com`, pinned to `gpt-5.2`; the model-list endpoint may validate that exact configured model but cannot choose or upgrade it. `store:false` is a requested transport setting only and does not establish zero provider retention. The `scripted-test` provider is deterministic test infrastructure and can never qualify semantic output. Live semantic egress additionally requires an exact operator-confirmed `PUBLIC_SAFE` digest closure in `model_egress_authorization`; filesystem selection or a source role alone never authorizes transmission.

`contract_readiness` describes owner-review readiness of the proposal and evidence/oracle plan. `run_eligibility` describes whether required roles were available. Pattern selection never means pattern execution. `execution_available` and `challenge_available` remain false.

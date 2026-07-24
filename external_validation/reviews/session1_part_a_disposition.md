# Session 1 Part A disposition

| Finding | Decision | Change made | Evidence | Residual limitation |
| --- | --- | --- | --- | --- |
| EV-001 | accepted | Deferred runner/adapter implementation to Part B/C boundary | Session structure | Not Part A completion evidence |
| EV-002 | accepted | Added dispatchable applicability, price, and run-index validators | focused validator tests | Schema-parity expansion pending |
| EV-003 | accepted | Recompute receipt ID/hash from canonical receipt payload | `test_registry_entries_resolve_and_receipt_hash_is_recomputed` | Full nested receipt contract pending |
| EV-004/005 | accepted | Canonicalized oracle comparison and added root helpers | focused security tests | Trusted configured-root integration pending |
| EV-006 | accepted | Kept Python validation independent of `jsonschema` | `test_case_validators_are_independent_from_jsonschema` | Full parity matrix pending |
| EV-007 | accepted | Added `verify_preflight` plan-hash and clean/upstream checks | source inspection | Dirty-tree invocation is intentionally rejected |
| PA-01 | accepted | Added case authority and receipt identity bindings | focused contract tests | Full JSON schema parity remains open |
| PA-02 | accepted | Enforced configured external root and runner mount separation | root and Docker-policy tests | Docker runtime proof blocked on engine |
| PA-03 | accepted | Typed evidence origin/severity/reproduction/adjudication states; model/agent evidence cannot verify or close targets | receipt adversarial test | Full registry-wide schema matrix remains open |

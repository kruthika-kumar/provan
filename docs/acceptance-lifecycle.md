# Acceptance Lifecycle v1

Session 11 adds an unreleased, `QUALIFIED_BOUNDED` source-only Acceptance lifecycle. It turns an existing immutable Change Brief preparation into a human-disposition-backed Acceptance Contract, freezes one exact candidate, settles eligible evidence, records Provan's recommendation separately from an optional owner decision, and can reinspect exact source-level closure requirements on a later descendant.

The lifecycle remains read-only. It does not build, test, import, install, execute, remediate, deploy, generate challenges, qualify a verifier, or establish Enterprise identity or policy.

## Commands

```text
provan acceptance promote --brief <brief-id>
provan acceptance contract --preparation <preparation-id> --show-items
provan acceptance contract --preparation <preparation-id> --dispositions-file <canonical-json> --actor-label <label>
provan acceptance freeze --contract <contract-id> --repo <local-repository>
provan acceptance attest --freeze <freeze-id> [--evidence <file>]...
provan acceptance decide --attestation <attestation-id> --decision-file <canonical-json> --actor-label <label>
provan acceptance record --attestation <attestation-id> [--decision <decision-id>] --format terminal|json|markdown|html
provan reinspect --record <record-id> --repo <local-repository> --head <full-commit> [--external-change-receipt-file <path>]
```

All file options use Provan's bounded regular-file reader. File content cannot self-declare evidence authority. In Session 11 arbitrary evidence remains `imported_unverified` unless an inherited content-addressed producer qualification independently establishes compatibility; no such trust root is manufactured.

## Contract and evidence boundaries

An Acceptance Contract is immutable and versioned. A material amendment creates a successor contract and requires a new contract-bound Candidate Freeze even when the source commit is unchanged. Conditional criteria are frozen as `active`, `inactive`, or `unresolved`; materially unresolved activation prevents clearance. Missing evidence never becomes `not_applicable`.

Current source-only checks are limited to exact repository-relative blob existence, bounded JSON Pointer equality, static Python symbol/`__all__` inspection, and resolution of a typed protected invariant. Python source is parsed but never imported or executed. Runtime, human-confirmation without a new canonical operator action, and challenge requirements remain unable to establish.

Evidence authority derives from ingestion and validated provenance, not fields inside a file. Owner decisions do not rewrite Provan's recommendation or evidence settlement. An override on `held` or `not_eligible` remains visibly an override.

## Record identity and expiry

Canonical state objects use UUIDv4 identity and separate SHA-256 integrity. A logical Acceptance Record locator is derived from the exact Attestation digest, optional Decision digest, and Record contract/version. JSON, Markdown, HTML, terminal, internal, and client-safe views have independent projection digests. Reinspection resolves and validates the canonical chain; rendered prose is never authority.

Expiry is evaluated with the current UTC clock when the chain is resolved or rendered. Provan does not rewrite the immutable artifacts or claim external revocation.

## Reinspection

Automatic Reinspection requires the same canonical repository, a distinct later descendant head, and the original closure contract. It evaluates every material open requirement and all referenced protected invariants. Overall status follows the frozen precedence: disputed, closed, partially closed, unable to establish, then open. A matching file on divergent history does not close the record, and an external change receipt is only untrusted change-claim input.

Session 12 verifier execution and Session 13 challenge generation are not implemented.

# Session 1 effective status

The canonical effective status resolves only from
`external_validation/status/session1-status-authority.v1.json` and its
required root-owned external attestation; this markdown is a non-authoritative
public view.

The tracked public resolver, which intentionally has no private attestation,
resolves to:

```text
Detection: QUALIFIED
Remediation: BLOCKED
Overall: PARTIALLY_QUALIFIED
```

The original qualification and reopening remain immutable history but are not
independent current authorities. A root-owned, content-addressed external
attestation can activate the final `QUALIFIED` profile records only after
descriptor-safe loading from the fixed trusted root verifies its SHA-256
identifier, status-authority, status-chain, complete closeout manifest,
implementation Commit A/tree, and proof-only Commit B/tree bindings. Cycles,
missing predecessors, competing successors, changed historical hashes,
malformed/uncommitted chain blobs, unavailable `openat2`, or any
missing/mismatched attestation binding fail closed to the public state above.
Intentional remediation-root teardown removes the private attestation and
consequently returns authorized resolution to this public state.

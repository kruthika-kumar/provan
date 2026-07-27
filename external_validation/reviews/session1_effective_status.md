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
independent current authorities. A root-owned external attestation can
activate the final `QUALIFIED` profile records only after its status-authority,
status-chain, proof-manifest, implementation Commit A/tree, and proof-only
Commit B/tree bindings are verified. Cycles, missing predecessors, competing
successors, changed historical hashes, malformed/uncommitted chain blobs, or
any missing/mismatched attestation binding fail closed to the public state
above.

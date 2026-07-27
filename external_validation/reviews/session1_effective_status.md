# Session 1 effective status

The canonical effective status resolves only from
`external_validation/status/session1-status-authority.v1.json` and its
required root-owned external attestation; this markdown is a non-authoritative
public view.

The resolved effective status is:

```text
Detection: QUALIFIED
Remediation: QUALIFIED
Overall: QUALIFIED
```

The original qualification and reopening remain immutable history but are not
independent current authorities. The attestation binds the proof-only status
commit and its proof manifest; without it the resolver fails closed to
remediation `BLOCKED` and overall `PARTIALLY_QUALIFIED`. Cycles, missing
predecessors, competing successors, changed historical hashes, and malformed
or uncommitted chain blobs fail closed.

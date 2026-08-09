# Change Brief v1

`provan explain` creates a source-only, evidence-classified explanation of an immutable pinned comparison or a bounded local working tree. It is a `QUALIFIED_BOUNDED` capability on unreleased `main`, not a released PyPI feature.

## Explicit inputs

Literal text and file paths are separate options. Provan never guesses from filesystem existence:

```text
--brief TEXT | --brief-file PATH
--agent-claim TEXT | --agent-claim-file PATH
--user-journey TEXT
--user-journey-file PATH
--previous-brief CANONICAL_ID | --previous-brief-manifest PATH
```

Brief text is source-attributed product intent, agent claims remain agent-reported, and supplied journeys remain proposals. None is owner-confirmed Acceptance authority. Session 11 performs confirmation.

## Candidate modes

Immutable mode requires full base and head commit IDs. Credential-free public GitHub HTTPS is the only remote protocol. PR metadata, when requested, is fetched only from the canonical GitHub API with no credentials or redirects and must match the explicit commits.

Mutable mode compares the filesystem with committed `HEAD`, reports staged/index state separately, includes bounded non-ignored untracked regular files, and never lets the index replace the filesystem candidate. Ignored, generated, linked, unsafe, and sensitive paths are explicit noncoverage. Mutable Briefs cannot be promoted.

This Session 10 qualification covers ordinary repositories with a real `.git` directory and loose current HEAD/index objects. Linked worktrees and packed-only current object stores are explicit unsupported boundaries: Provan rejects them instead of following repository indirection or copying a complete object store.

## Context, policy, and models

The bundled `CaseLocalContextProvider` reads only explicit bounded files. It cannot manufacture owner confirmation, approved policy, runtime verification, or execution verification. `community.default.v1` is deterministic and can emit only `explain_only` or `acceptance_recommended`.

`--no-model` guarantees zero calls and zero egress. A model is used at most once and only through an explicitly operator-configured, Provan-allowlisted provider. The complete semantic request is bound to a local `provan.model_input_envelope.v1`; outputs remain model-reviewed or unresolved.

## Previous Briefs and preparation

Previous Briefs are comparison-only. Canonical IDs reverify local manifests. External inputs must be self-contained manifest-backed Provan exports with contained relative paths and matching digests. No prior evidence or authority is carried forward.

`provan acceptance promote --brief ID` creates only a proposed preparation packet. It does not confirm criteria, execute verification, create a challenge, clear a release, or issue a verdict.

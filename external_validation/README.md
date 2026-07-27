# Shiproom external validation

## Current Session 1 status

The root-owned external attestation for the committed control-plane proof
bundle has been verified: detection, remediation, and overall profiles are
`QUALIFIED`. The authoritative current view is
`status/session1-status-authority.v1.json` plus its required external
attestation—not historical status-chain files or markdown closeout summaries.
Without that attestation the resolver deliberately reports remediation
`BLOCKED` and overall `PARTIALLY_QUALIFIED` rather than accepting an unsigned
public claim. Session 2, case, model, mutation, and benchmark work remain
outside this Session 1 closeout.

This directory is the public, version-controlled control plane for Shiproom's external validation programme. The normative methodology is [the v2 testing plan](plan/shiproom_external_validation_testing_plan_v2.md); the [Codex action plan](plan/shiproom_external_validation_codex_action_plan.md) governs execution sequencing and cannot weaken that methodology.

## Incorporated authority

| Document | Version | SHA-256 |
| --- | --- | --- |
| `shiproom_external_validation_testing_plan_v2.md` | 2.0 | `sha256:d821c15e67ed06200e23d7bf77de39842310b318d821e56a23993c8d980d9886` |
| `shiproom_external_validation_codex_action_plan.md` | 1.0 | `sha256:c9e8a1944f1b023f753092827eb35a3901f77d6b0b1432b107421c2cbb6aad0b` |

The preflight command rechecks this table against the exact committed bytes.

## Boundary

Only public methodology, schemas, execution code, non-answer-bearing fixtures, proof ledgers, and Session 1 governance reviews belong here. Private case manifests, mutations, hidden oracles, patient clones, raw outputs, credentials, blinded adjudication, and private reviewer comments must live below `SHIPROOM_EXTERNAL_VALIDATION_ROOT`, never in this repository.

Package schemas live in `shiproom/external_validation/schemas/` so installed Shiproom distributions can validate the same canonical files. `python -m shiproom.external_validation.doctor` performs the Docker qualification gate; an unavailable Docker daemon is reported as `IMPLEMENTED_BUT_RUNTIME_QUALIFICATION_BLOCKED`, not as a pass.

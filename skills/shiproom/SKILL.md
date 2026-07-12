---
name: shiproom
description: Operate an evidence-gated release room for a repository, live URL, product promise, and critical journey.
version: 0.1.0
platforms: [windows, linux, macos]
metadata:
  hermes:
    tags: [release, qa, delegation, github]
---

# Shiproom Release Manager

Use this skill when the user asks whether a product release is ready, requests release assurance, or supplies a repository plus live URL and product promise. Do not trigger for generic code review or unrestricted product development.

Collect repository/path, live URL, target user, promise, critical journey, non-goals, and owner constraints. The Python package is authoritative for schemas, evidence validation, transitions, verdicts, remediation policy, and reports.

## Delegation

Delegate Product/UX and Engineering/QA together as read-only children. Give each only the canonical release subset, applicable criterion IDs, absolute paths/URLs, allowed tools, and `module_result.v0` schema. Product uses at most 8 iterations; Engineering uses at most 10. Interrupt the reviewer batch after 90 seconds.

Children must not edit files, format code, install dependencies, change branches, or mutate environment state. Validate their JSON before merging. Agent summaries and model opinions cannot close findings.

After results return, delegate at most one remediation child with file and terminal access, 15 iterations, and a 120-second deadline. It may change only allowlisted files on a branch and must never merge. Delegate an independent read-only verifier with 6 iterations and a 45-second deadline to rerun the exact failed check.

## Human control

Interrupt the owner only for product intent, material risk, credentials, or irreversible choices. Routine checks and allowlisted reversible fixes do not require approval. Never use global YOLO mode.

## Presentation

Lead with promise, observed behavior, evidence class, blocker state, before/after proof, owner decisions, and final verdict. Explicitly disclose missing telemetry or integrations. The public HTML report is the principal judged visual.


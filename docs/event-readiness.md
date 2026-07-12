# Event readiness record

Recorded 2026-07-12 Asia/Calcutta.

## Hermes runtime

- Reported version: `0.18.2 (2026.7.7.2)`
- Install method: Git
- Recorded commit: `022c4991fc0c5245b8cc84b9e275ae7a64b27d30`
- Python: 3.11.9
- Config schema: v33
- Default state backup: `20260712-065412-shiproom-pre-repair`
- Isolated profile: `buildathon`
- Operator: native TUI
- Management surface: native dashboard; localhost `/api/status` returned 200
- Global YOLO: not enabled

The checkout did not resolve to an exact Git tag and contains extensive pre-existing modifications. It was not reset or updated because those files are outside the event repository and may be user-owned. The runtime-reported v0.18.2 version is frozen pending a safe clean reinstall.

## Model benchmark

- Model/provider: `gpt-5.4-mini` / `openai-api`
- Synthetic public fixture only; no Shiproom source was sent
- Two parallel read-only children: passed
- Exact manager JSON schema: passed
- Malformed result rejection: passed
- Elapsed: 47.3 seconds
- API calls: 4
- Total tokens reported: 60,637, including cache and reasoning categories
- Cost: unavailable (`cost_status: unknown`)
- Session: `20260712_123048_b63b58`

## Functional proof

- Unit tests: 10 passed
- Fixed eval corpus: 12 passed
- Red check: generated `/result/demo` returned 404 and produced HOLD
- Branch-only route remediation: passed
- Independent exact rerun: returned 200 and produced READY
- Reset: restored `/results/demo` mismatch and returned to `master`

## External gates

- Cloudflare CLI available through `npx wrangler`; account is not authenticated.
- GitHub CLI installation hung and was stopped; no GitHub credentials are configured.
- Langfuse credentials are absent, so the bundled plugin cannot yet produce a verified trace.
- Convex and ElevenLabs credentials are absent; local-state and text fallbacks remain functional.
- Wispr 500-word activity and partner screenshots require manual event participation.


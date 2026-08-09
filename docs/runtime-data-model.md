# Runtime and data model

Provan reads Git object and tree metadata through an isolated, time/storage/output-bounded Git process. It creates disposable scratch data and a typed receipt only under the dedicated `.provan/outputs` boundary. The target repository, its working tree, refs, objects, configuration, hooks, and alternates remain unchanged. Receipts report observations and limitations, never acceptance verdicts.

Telemetry preview produces immutable pending-envelope bytes and a digest under a dedicated `.provan` state root outside any Git repository. A transport, if explicitly configured later, may send only those exact bytes.

Change Brief v1 separates candidate identity, source-established facts, source-attributed product intent, agent reports, model-reviewed implications, and unresolved coverage. Case-local context cannot confer owner or policy authority. The pure `community.default.v1` PromotionPolicy can recommend Acceptance preparation only from supported source/configuration triggers. Acceptance Seeds and preparation packets remain explicitly proposed.

Canonical case artifacts are stored beneath `<PROVAN_HOME>/outputs/change-brief/<brief-id>/` with a content-addressed manifest. Case-neutral deterministic repository analysis may be reused beneath `<PROVAN_HOME>/cache/repository-analysis/<digest>/`; every case-bound artifact is freshly constructed.

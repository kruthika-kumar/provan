# Runtime and data model

Provan reads Git object and tree metadata through an isolated, time/storage/output-bounded Git process. It creates disposable scratch data and a typed receipt only under the dedicated `.provan/outputs` boundary. The target repository, its working tree, refs, objects, configuration, hooks, and alternates remain unchanged. Receipts report observations and limitations, never acceptance verdicts.

Telemetry preview produces immutable pending-envelope bytes and a digest under a dedicated `.provan` state root outside any Git repository. A transport, if explicitly configured later, may send only those exact bytes.

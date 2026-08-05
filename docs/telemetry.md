# Telemetry

Telemetry is disabled by default and no collector endpoint is deployed. `preview` creates immutable canonical bytes locally. Enabling does not transmit without a separately configured endpoint. A send can use only the referenced pending bytes and digest.

Envelopes use a new non-persistent identifier each time. There is no timed rotation policy; `reset-id` invalidates pending envelopes. A transport would expose ordinary transport metadata including destination host, TLS/HTTP headers, timing, retry behavior, and source IP. Provan does not describe this mechanism as anonymous.

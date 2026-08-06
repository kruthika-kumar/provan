# Telemetry

Telemetry is disabled by default and no collector endpoint is deployed. `preview` creates immutable canonical bytes locally. Enabling does not transmit without a separately configured endpoint. A send can use only the referenced pending bytes and digest.

Envelopes use a new pseudonymous, non-persistent identifier each time. Provan does not collect an installation identity, cannot correlate installations across runs, and cannot centrally measure recurring installation-level usage. Timed rotation is not applicable. `clear-pending` invalidates pending envelopes; the documented `reset-id` spelling remains an untimed deprecated alias with no authorised removal date and performs only that operation. A transport would expose ordinary transport metadata including destination host, TLS/HTTP headers, timing, retry behavior, and source IP. Provan does not describe this mechanism as anonymous.

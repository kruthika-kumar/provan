# Retention and deletion

Scratch inspection data is deleted when an inspection ends. Receipts remain beneath the operator's resolved `PROVAN_HOME` state root unless copied elsewhere. Pending telemetry envelopes stay local until `provan telemetry clear-pending` or operator deletion. The deprecated `reset-id` alias clears the same pending bytes and does not reset an installation identity, because none is collected. Provan does not automatically upload, retain, or delete target repository content because it does not collect that content.

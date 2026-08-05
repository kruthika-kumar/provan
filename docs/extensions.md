# Extensions

The first public extension contract generation uses API major `1` and entry-point group `provan.extensions`. Supported overlay kinds are context, organisation policy, historical challenge, entitlement receipt, report section, and deployment diagnostics.

Each kind has its own `provan.extension_<kind>_overlay.v1` schema. Every overlay declares bounded authority, non-mutation, and public provenance; independent Python validation enforces the negotiated kind, kind-specific payload, cross-field provenance rules, and recursively rejects mutation or canonical-authority requests.

The Community CLI does not discover or execute third-party providers. Its bundled no-op provider returns a schema-valid empty overlay and has no target handle. The schemas validate overlay data; they do not sandbox arbitrary Python code. Installing or executing a third-party provider is outside the current qualified capability and cannot inherit Provan evidence authority.

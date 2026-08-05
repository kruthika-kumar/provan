# Product boundary

Provan Community provides source-only inspection, environment diagnostics, bounded extension contracts, local diagnostic previews, and opt-in telemetry previews. It cannot change a customer repository or execute its code. It never creates Git refs or objects, pushes, opens or merges pull requests. It cannot deploy or remediate. It cannot certify or elevate evidence. Requests for execution fail with `QUALIFIED_SANDBOX_REQUIRED`; mutation requests fail with `CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN`.

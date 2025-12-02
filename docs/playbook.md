# Playbook Ideas

Scenarios to iterate on as you deepen the demo.

- **Alg diversity**: sign SBOMs with RSA/ECDSA and confirm Dependency-Check selects by `alg` + `kid`.
- **JWKS trust**: host a JWKS for the producer key; point Dependency-Check at it (`--scrapiSbomJwksUrl`).
- **Strict vs lenient**: flip `--scrapiStrict` and observe behavior on mismatched `hash_alg`, `log_key_id`, or missing receipt fields.
- **mTLS**: run the server with `-tls-client-ca` and verify client + Dependency-Check connections succeed with client certs.
- **Tampering drills**: alter SBOM bytes or receipt fields and ensure verifiers fail signature/merkle checks.
- **Persistence**: swap the in-memory log for a simple file/DB-backed append-only store and reissue receipts.
- **CI automation**: script the demo steps to run in CI for regression coverage (future GitHub Pages can link to these recipes).

# Playbook Ideas

Scenarios to iterate on as you deepen the demo.

- **Alg diversity**: sign SBOMs with RSA/ECDSA and confirm verifiers honor `alg` + `kid`.
- **JWKS trust**: host a JWKS for the producer key; configure consumers or Dependency-Track extensions to use it.
- **Strict vs lenient**: enforce/relax receipt expectations in your verifier (hash_alg/log_id/version) before uploading to Dependency-Track.
- **mTLS**: run the SCRAPI server with `-tls-client-ca` and upload SBOMs to Dependency-Track with client certs.
- **Tampering drills**: alter SBOM bytes or receipt fields and ensure verification fails before upload.
- **Findings anchoring**: export Dependency-Track findings as JSON, sign them, and register with SCRAPI to bind results back to the log.
- **Persistence**: swap the in-memory log for a simple file/DB-backed append-only store and reissue receipts.
- **CI automation**: script the demo steps to run in CI for regression coverage (future GitHub Pages can link to these recipes).

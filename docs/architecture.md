# Architecture & Data Flow

This page situates the demo against SCITT/SCRAPI and sketches the message shapes.

## Flow at a glance (ASCII)
```
Producer (signs SBOM)          SCRAPI service (Go demo)           Verifier (Dependency-Check)
------------------------       --------------------------         ----------------------------
SBOM bytes --COSE_Sign1-->     POST /entries (COSE)      \
                                -> locator id              \
                                                           -> Signed receipt (COSE_Sign1)
                                   /.well-known/transparency-configuration (log key/id)

Verification:
- SBOM COSE verified with producer key (kid/alg)
- Receipt COSE verified with log key
- Merkle proof checks leaf (0x00||SHA-256(SBOM)) up to root
- log_id/log_key_id, hash_alg, version checked
```

## Components in this repo
- **Server**: `cmd/scrapi-demo-server` + `scrapi/httpserver` (in-memory log, Ed25519 log key).
- **Client**: `cmd/scrapi-demo-client` (registers, polls, fetches config, verifies receipts).
- **SBOM helper**: `cmd/syft-sbom` (generate & sign SBOM into COSE).

## COSE/receipt shapes (demo)
- SBOM signature: COSE_Sign1, `alg` = EdDSA by default (kid optional, recommended).
- Receipt signature: COSE_Sign1, `alg` = EdDSA, payload contains:
  - `log_id`, `scrapi_version`, `size`, `ts`, `leaf`, `root`, `path` (Merkle proof).
- Hashing: leaf = `0x00 || SHA-256(payload)`, node = `0x01 || left || right`.

## Alignment to SCRAPI/SCITT drafts
- Endpoints: `/.well-known/transparency-configuration`, `/entries`, `/entries/{id}`, `/receipts/{id}`.
- Configuration fields: `log_public_key`, `log_key_id`, `hash_alg`, `scrapi_version`, `tree_type`.
- Receipt checks: inclusion proof + log key binding, version/hash checks (strict mode in Dependency-Check enforces).

## Trust model in the demo
- Log key: Ed25519, surfaced via well-known; can be pinned by clients.
- Producer key: supplied by the producer (COSE kid), trusted out-of-band via PEM or JWKS by the verifier.
- No persistence/HSM; in-memory log for educational purposes.

## TODO (to be expanded)
- More detailed sequence diagrams (registration, polling, receipt fetch).
- Variants with RSA/ECDSA SBOM signatures.
- JWKS hosting flow for producer keys.
- Notes on extending the log to persistent storage and async issuance.

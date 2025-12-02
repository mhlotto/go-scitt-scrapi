# Architecture & Data Flow

This page situates the demo against SCITT/SCRAPI and sketches the message shapes.

## Flow at a glance (ASCII)
```
Producer (signs SBOM)          SCRAPI service (Go demo)           Analyzer/Verifier (Dependency-Track)
------------------------       --------------------------         ------------------------------------
SBOM bytes --COSE_Sign1-->     POST /entries (COSE)      \
                                -> locator id              \
                                                           -> Signed receipt (COSE_Sign1)
                                   /.well-known/transparency-configuration (log key/id)

Verification (or ingest):
- SBOM COSE verified with producer key (kid/alg) before using it.
- Receipt COSE verified with log key; Merkle proof checks leaf (0x00||SHA-256(SBOM)) up to root.
- log_id/log_key_id, hash_alg, version checked.
- Dependency-Track ingests the same SBOM while the SCRAPI receipt proves its integrity.
```

## Sequence (registration → polling → receipt fetch)
```
Client                Server                 Log
------                ------                 ---
POST /entries (COSE)  --> validate COSE
                        compute leaf hash
                        append to merkle tree
                        sign receipt (COSE, EdDSA)
<-- 200 {locator, receipt?}
                          [in-memory audit trail]

# If receipt omitted or delayed:
GET /entries/{id} --> return status {locator, receipt?}
<-- 200 {receipt?}

# Dedicated receipt endpoint:
GET /receipts/{id} --> return receipt if available
<-- 200 receipt.cose
    (404/405 -> not supported; 202 -> pending)

Well-known:
GET /.well-known/transparency-configuration
<-- 200 {log_public_key, log_key_id, hash_alg, scrapi_version, tree_type}

Verifier steps:
- Fetch config (or pin log key/id).
- Verify receipt signature with log key.
- Verify SBOM signature with producer key (kid/alg).
- Recompute leaf: 0x00 || SHA-256(SBOM bytes).
- Verify Merkle proof to root; check tree size/timestamp; check log_id/version/hash_alg (strict mode).
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

### COSE header crib (SBOM)
- Protected:
  - `alg`: one of EdDSA / ES256 / ES384 / ES512 / RS256 / RS384 / RS512 / PS256 / PS384 / PS512
- Unprotected (optional):
  - `kid`: recommended when multiple trusted keys exist

### Receipt payload fields (demo)
- `log_id`: string (matches `log_key_id` from config)
- `scrapi_version`: string (e.g., draft hint)
- `size`: int64 (tree size)
- `ts`: int64 (epoch seconds)
- `leaf`: byte string (0x00 || SHA-256(SBOM))
- `root`: byte string (Merkle root)
- `path`: array of nodes { pos: "left"|"right", hash: bytes }

### Merkle hash prefixes
- Leaf: `0x00 || SHA-256(payload)`
- Node: `0x01 || left || right`

## Timeline (high level)
- t0: Producer generates SBOM (CycloneDX/SPDX) and signs it (COSE_Sign1 with alg/kid).
- t1: Producer registers the signed SBOM with SCRAPI `/entries`; receives locator and (ideally) a signed receipt.
- t2: If receipt not returned immediately, producer polls `/entries/{id}` or `/receipts/{id}` until available.
- t3: Producer (or pipeline) publishes SBOM + receipt + locator to consumers.
- t4: Consumer/verifier fetches transparency configuration (or uses pinned log key/id).
- t5: Consumer/verifier validates SBOM signature (producer key), receipt signature (log key), and Merkle proof.
- t6: Security auditor or CI pipeline scans using the verified SBOM, checks receipts for provenance/timeliness.
- t7: Auditor (or pipeline) produces a scan report that references the SBOM/locator, signs it (COSE) to assert authorship, and prepares it for registration. This binds “who found these findings” to “which SBOM was examined.”
- t8: Auditor registers the signed scan report with SCRAPI `/entries`, receives a scan locator and receipt. Now the findings themselves are transparency-backed and cannot be silently swapped without detection.
- t9: Auditor delivers scan report + scan receipt + scan locator back to the producer (or downstream stakeholders). This lets the producer prove “these are exactly the findings the auditor logged.”
- t10: Producer (or any verifier) validates the scan report and receipt exactly like the SBOM: check report signature (auditor identity), receipt signature (log key), Merkle proof, and log key/id pins. This ensures the report is authentic and anchored.
- t11: Optional: Producer re-publishes SBOM + scan + both receipts as a bundle for downstream consumers, enabling end-to-end traceability (origin SBOM and subsequent audit findings both anchored in the log).

## Alignment to SCRAPI/SCITT drafts
- Endpoints: `/.well-known/transparency-configuration`, `/entries`, `/entries/{id}`, `/receipts/{id}`.
- Configuration fields: `log_public_key`, `log_key_id`, `hash_alg`, `scrapi_version`, `tree_type`.
- Receipt checks: inclusion proof + log key binding, version/hash checks (the demo client enforces these before upload to Dependency-Track).

## Trust model in the demo
- Log key: Ed25519, surfaced via well-known; can be pinned by clients.
- Producer key: supplied by the producer (COSE kid), trusted out-of-band via PEM or JWKS by the verifier.
- No persistence/HSM; in-memory log for educational purposes.

## TODO (to be expanded)
- More detailed sequence diagrams (registration, polling, receipt fetch).
- Variants with RSA/ECDSA SBOM signatures.
- JWKS hosting flow for producer keys.
- Notes on extending the log to persistent storage and async issuance.

# Dependency-Check Integration

This page explains how Dependency-Check consumes SCRAPI artifacts produced by the Go demo.

## Inputs the verifier expects
- **Signed SBOM**: COSE_Sign1 with `alg` and optional `kid`. (Default demo uses Ed25519.)
- **Receipt**: COSE_Sign1 signed by the log key, with Merkle proof, `log_id`, `size`, `ts`, `leaf`, `root`.
- **Transparency config**: `log_public_key`, `log_key_id`, `hash_alg`, `scrapi_version`, `tree_type`.
- **Trust material**:
  - Producer key: `--scrapiSbomKey`/`--scrapiSbomTrustedKeys` (PEM) or `--scrapiSbomJwksUrl`.
  - Log key/id pinning: `--scrapiLogKeyPin`, `--scrapiLogKeyIdPin`.
  - (Optional) Trust store/SAN/issuer regex for producer certs if you use X.509-based identity.

## Core flags to remember
- `--scrapiSbom` `<path>` (COSE)
- `--scrapiSbomReceipt` `<path>` **or** `--scrapiSbomLocator` `<id|url>`
- `--scrapiUrl` `<base>` (used for locator fetch/config)
- `--scrapiSbomKey` / `--scrapiSbomJwksUrl`
- `--scrapiLogKeyPin` / `--scrapiLogKeyIdPin`
- `--scrapiStrict` (default true; enforces alg/kid/hash/log_id expectations)
- TLS/auth: `--scrapiToken`, `--scrapiCaCert`, `--scrapiClientCert/Key`

## Receipt verification expectations
- Receipt `alg`: EdDSA (-8).
- `log_id` (if present) must match pinned/configured `log_key_id`.
- Merkle leaf: `0x00 || SHA-256(SBOM-bytes)`.
- Tree size > 0; timestamp within skew; Merkle proof recomputes root.

## SBOM signature verification expectations
- COSE `alg` drives signature verification (EdDSA/ES*/RS*/PS* supported).
- If multiple trusted keys are configured, a `kid` is required.
- JWKS accepted for Ed25519/RSA/EC keys with `alg` hints; non-`sig` uses are skipped.

## Outputs surfaced by Dependency-Check
- Receipt verification status and details (tree size, timestamp, locator) appear in JSON/HTML/XML/SARIF/JUnit reports.
- SBOM leaf hash is recorded (hex).

## Common flows
- **Inline receipt**: supply both `--scrapiSbom` and `--scrapiSbomReceipt`; no network fetch needed.
- **Fetch receipt**: supply `--scrapiSbomLocator` and `--scrapiUrl`; tool polls `/receipts/{id}` then `/entries/{id}`.
- **Pinned log key**: use `--scrapiLogKeyPin` to avoid trusting the well-known fetch.

## TODO (to be expanded)
- Example JWKS hosting for the producer key.
- Example RSA/ECDSA signed SBOM and verifier selection.
- Mapping to SCRAPI draft sections (alg values, receipt fields).
- Troubleshooting table for alg/kid/strict-mode failures.

# Demo Walkthroughs

This page collects runnable flows. Each section is intended to be copy/paste friendly and references the commands shipped in this repo.

## Quickstart: HTTP, no auth
1. **Start server**  
   Purpose: launch the SCRAPI demo log that issues signed inclusion receipts and exposes its log key/id. The receipt is the tamper-evident proof that the exact SBOM bytes were recorded at a point in time, solving “prove this SBOM matches what was registered and hasn’t been swapped.”
   ```bash
   cd ../go-scitt-scrapi
   go run ./cmd/scrapi-demo-server
   ```
2. **Generate + sign SBOM**  
   Purpose: create a canonical SBOM and wrap it in COSE_Sign1 with your producer key/kid so verifiers can authenticate the author. This proves “who said this” and binds your identity to the SBOM content before it goes into the log.
   ```bash
   go run ./cmd/syft-sbom \
     -source . \
     -out /tmp/demo-sbom.json \
     -sign \
     -sign-kid demo-sbom-kid \
     -cose-out /tmp/demo-sbom.cose \
     -pub-out /tmp/demo-sbom-signer-pub.pem
   ```
3. **Register SBOM, get receipt, fetch config/log key**  
   Purpose: anchor the signed SBOM in the transparency log, obtain the signed inclusion receipt, and capture the log key/id so verifiers can pin the log’s identity. This answers “is this SBOM the one in the log?” (receipt + Merkle proof) and “am I trusting the right log?” (pinned log key/id).
   ```bash
   go run ./cmd/scrapi-demo-client \
     -addr http://localhost:8080 \
     -file /tmp/demo-sbom.cose \
     -wrap-sbom=false \
     -out /tmp/demo-receipt.cose \
     -print-receipt-json \
     -config-out /tmp/transparency.cbor \
     -log-key-pem /tmp/log-public-key.pem
   ```
4. **Verify with Dependency-Check** (adjust path to your binary):  
   Purpose: independently validate SBOM signature (producer key/kid), receipt signature (log key), and Merkle inclusion proof to ensure the SBOM matches what was logged. This closes the loop: “is this SBOM from the claimed producer, and does it exactly match what the transparency log recorded at that time?”
   ```bash
   cd /path/to/DependencyCheck
   ./dependency-check.sh --project scrapi-demo \
     --scrapiSbom /tmp/demo-sbom.cose \
     --scrapiSbomReceipt /tmp/demo-receipt.cose \
     --scrapiUrl http://localhost:8080 \
     --scrapiSbomKey /tmp/demo-sbom-signer-pub.pem \
     --scrapiLogKeyPin "$(cat /tmp/log-public-key.pem)"
   ```
   - Use `--scrapiSbomLocator <locator>` instead of `--scrapiSbomReceipt` to fetch.
   - Add `--scrapiLogKeyIdPin <id>` if you captured `log_key_id`.

## TLS + bearer auth variant (fill paths if you enable TLS)
- Start server with `-auth-token`, `-tls-cert`, `-tls-key`, `-tls-client-ca` as needed.
- Client adds: `-token`, `-tls-ca`, `-tls-cert`, `-tls-key`.
- Dependency-Check adds: `--scrapiToken`, `--scrapiCaCert`, `--scrapiClientCert/Key`.
- Remainder of flow matches the quickstart.

## Reuse an existing signing key
If you already have an Ed25519 private key (PKCS#8 PEM):
```bash
go run ./cmd/syft-sbom \
  -source . \
  -out /tmp/demo-sbom.json \
  -sign \
  -sign-priv /path/to/ed25519-key.pem \
  -sign-kid your-kid \
  -cose-out /tmp/demo-sbom.cose \
  -pub-out /tmp/demo-sbom-signer-pub.pem
```

## Next additions (placeholders)
- Multiple alg demo (RSA/ECDSA SBOM signatures) → Dependency-Check selection.
- JWKS-hosted signer key → `--scrapiSbomJwksUrl`.
- Strict vs non-strict receipt/hash/kid handling examples.
- mTLS end-to-end script.

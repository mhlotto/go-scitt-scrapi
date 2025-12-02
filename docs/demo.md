# Demo Walkthroughs

This page collects runnable flows. Each section is intended to be copy/paste friendly and references the commands shipped in this repo.

## Quickstart: HTTP, no auth
1. **Start server**
   ```bash
   cd ../go-scitt-scrapi
   go run ./cmd/scrapi-demo-server
   ```
2. **Generate + sign SBOM**
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

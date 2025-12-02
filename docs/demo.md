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

## Variant: RSA/ECDSA SBOM signatures
Goal: exercise Dependency-Check alg selection (non-EdDSA).

1) Generate keys (examples):
- RSA:
  ```bash
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /tmp/sbom-rsa.key
  openssl rsa -in /tmp/sbom-rsa.key -pubout -out /tmp/sbom-rsa.pub.pem
  ```
- ECDSA P-256:
  ```bash
  openssl ecparam -name prime256v1 -genkey -noout -out /tmp/sbom-ec.key
  openssl ec -in /tmp/sbom-ec.key -pubout -out /tmp/sbom-ec.pub.pem
  ```

2) Produce a COSE_Sign1 with matching alg:
- Use a small helper (Go or python) to sign SBOM bytes with `alg` = RS256/ES256 and embed `kid` (for multiple keys). Keep the COSE output at `/tmp/demo-sbom.cose`.
- Keep the public key for Dependency-Check: `/tmp/sbom-rsa.pub.pem` or `/tmp/sbom-ec.pub.pem`.

3) Register and verify:
- Register with `scrapi-demo-client -file /tmp/demo-sbom.cose -wrap-sbom=false ...` (as in the quickstart).
- Verify with Dependency-Check:
  ```bash
  ./dependency-check.sh ... \
    --scrapiSbom /tmp/demo-sbom.cose \
    --scrapiSbomKey /tmp/sbom-rsa.pub.pem \
    --scrapiSbomReceipt /tmp/demo-receipt.cose
  ```
Expected: the verifier selects RS256/ES256 based on COSE `alg`; fails if the key does not match the alg or `kid` mismatch in a multi-key setup.

## Variant: JWKS-hosted signer key
Goal: trust the producer key via JWKS instead of local PEM.

1) Build a JWKS from your signer key:
```bash
cat > /tmp/jwks.json <<'EOF'
{ "keys": [
  {
    "kty": "OKP",
    "crv": "Ed25519",
    "use": "sig",
    "kid": "demo-sbom-kid",
    "x": "<base64url-raw-ed25519-pubkey>"
  }
] }
EOF
```
For RSA/EC keys, use standard JWK fields (`kty` RSA/EC, `n`/`e` or `x`/`y`/`crv`, plus `alg` if you want to pin).

2) Host the JWKS (simple file server):
```bash
python3 -m http.server 8000 --directory /tmp
# JWKS URL: http://localhost:8000/jwks.json
```

3) Verify with Dependency-Check:
```bash
./dependency-check.sh ... \
  --scrapiSbom /tmp/demo-sbom.cose \
  --scrapiSbomReceipt /tmp/demo-receipt.cose \
  --scrapiSbomJwksUrl http://localhost:8000/jwks.json
```
Expected: the verifier downloads the JWKS, filters for `use=sig`, matches `kid`/`alg`, and verifies the SBOM signature.

## Strict vs non-strict runs
Goal: see enforcement differences for log_id/hash/version.

- Strict (default true):
  ```bash
  ./dependency-check.sh ... --scrapiStrict true
  ```
  Fails on:
  - Receipt `log_id` not matching pinned/configured `log_key_id`
  - Unsupported `hash_alg`
  - Missing kid when `log_key_id` is configured
  - Receipt version mismatch

- Non-strict:
  ```bash
  ./dependency-check.sh ... --scrapiStrict false
  ```
  Warnings instead of hard fails for the above; signature and Merkle proof remain fatal on mismatch.

## mTLS end-to-end
Goal: require client certs on the SCRAPI server and verify with both the demo client and Dependency-Check.

1) Generate demo CA/server/client certs (use `scripts/gen_certs.sh` or your own):
```bash
./scripts/gen_certs.sh
```

2) Start server with mTLS:
```bash
go run ./cmd/scrapi-demo-server \
  -addr :8443 \
  -tls-cert certs/server.crt.pem \
  -tls-key certs/server.key.pem \
  -tls-client-ca certs/ca.crt.pem
```

3) Register with client over mTLS:
```bash
go run ./cmd/scrapi-demo-client \
  -addr https://localhost:8443 \
  -tls-ca certs/ca.crt.pem \
  -tls-cert certs/client.crt.pem \
  -tls-key certs/client.key.pem \
  -file /tmp/demo-sbom.cose \
  -wrap-sbom=false \
  -out /tmp/demo-receipt.cose \
  -config-out /tmp/transparency.cbor \
  -log-key-pem /tmp/log-public-key.pem
```

4) Verify with Dependency-Check over mTLS:
```bash
./dependency-check.sh ... \
  --scrapiUrl https://localhost:8443 \
  --scrapiCaCert certs/ca.crt.pem \
  --scrapiClientCert certs/client.crt.pem \
  --scrapiClientKey certs/client.key.pem \
  --scrapiSbom /tmp/demo-sbom.cose \
  --scrapiSbomReceipt /tmp/demo-receipt.cose \
  --scrapiSbomKey /tmp/demo-sbom-signer-pub.pem \
  --scrapiLogKeyPin "$(cat /tmp/log-public-key.pem)"
```

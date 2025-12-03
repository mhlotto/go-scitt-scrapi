# Demo Walkthroughs

This page collects runnable flows. Each section is intended to be copy/paste friendly and references the commands shipped in this repo.

## Walkthrough: SCRAPI + Dependency-Track (HTTP, no auth)

### 0. Prepare Dependency-Track (backend + frontend + API key)
1. Build and start the apiserver (default port 8080):
   ```bash
   cd dependency-track
   mvn -DskipTests clean package
   java -jar target/dependency-track-apiserver*.jar
   ```
   Wait until you see “Started DependencyTrackApplication” in logs.
2. Start the UI (dev serve on port 8081):
   ```bash
   cd ../frontend
   npm install
   npm run serve -- --port 8081
   ```
3. Open the UI at http://localhost:8081, log in (default admin/password if unchanged), and create an API key (Profile → API Keys). Keep it handy for the upload step.

### 1. Start SCRAPI demo server
   Purpose: launch the transparency log that issues signed inclusion receipts and exposes its log key/id.
   ```bash
   cd ../go-scitt-scrapi
   go run ./cmd/scrapi-demo-server
   ```

### 2. Generate + sign SBOM
   Purpose: create a canonical SBOM and wrap it in COSE_Sign1 with your producer key/kid so verifiers can authenticate the author.
   ```bash
   go run ./cmd/syft-sbom \
     -source . \
     -out /tmp/demo-sbom.json \
     -sign \
     -sign-kid demo-sbom-kid \
     -cose-out /tmp/demo-sbom.cose \
     -pub-out /tmp/demo-sbom-signer-pub.pem
   ```

### 3. Register SBOM with SCRAPI, get receipt + log key
   Purpose: anchor the signed SBOM in the transparency log, obtain the signed inclusion receipt, and capture the log key/id so verifiers can pin the log’s identity.
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

### 4. Upload the same SBOM to Dependency-Track
Purpose: let Dependency-Track ingest/analyze the SBOM while retaining SCRAPI evidence.
   ```bash
   go run ./cmd/scrapi-demo-client \
     -addr http://localhost:8080 \
     -sbom /tmp/demo-sbom.json \
     -wrap-sbom=true \
     -dtrack-url http://localhost:8081 \
     -dtrack-api-key <your-api-key> \
     -dtrack-project "scrapi-demo" \
     -dtrack-version "1.0.0" \
     -dtrack-auto-create \
     -dtrack-scrapi-receipt /tmp/demo-receipt.cose \
     -dtrack-sbom-cose /tmp/demo-sbom.cose \
     -dtrack-scrapi-base http://localhost:8080 \
     -dtrack-scrapi-log-key-pin "$(cat /tmp/log-public-key.pem)" \
     -dtrack-scrapi-trusted-sbom-key /tmp/demo-sbom-signer-pub.pem \
     -dtrack-scrapi-trusted-sbom-jwks http://localhost:8000/jwks.json \ # optional JWKS demo
     -dtrack-scrapi-strict \
     -dtrack-poll -dtrack-poll-attempts 10 -dtrack-poll-interval 2s
   ```
   - The client uploads the SBOM via `/api/v1/bom` and prints the processing token/project reference. Dependency-Track will call `/verify/{locator}` on the SCRAPI server, validate the receipt/consistency/subject, and cache freshness info.
   - In the Dependency-Track UI, check:
     - **Project dashboard**: SCRAPI verification badge + freshness (if latest BOM exists).
     - **Project details modal**: SCRAPI status/locator/reason/strict + freshness (STH size/timestamp).  
       Note: UI is read-only for SCRAPI info; failures/degraded freshness still allow ingest unless `artifact.scrapi.verification.required=true`.

5. **(Optional) Sign and register findings**  
   After Dependency-Track reports findings (UI/API), export a JSON summary, sign it (auditor key/kid) into COSE_Sign1, and register it with SCRAPI to anchor the scan results. Downstream verifiers can chain SBOM receipt + findings receipt.

## TLS + bearer auth variant (fill paths if you enable TLS)
- Start server with `-auth-token`, `-tls-cert`, `-tls-key`, `-tls-client-ca` as needed.
- Client adds: `-token`, `-tls-ca`, `-tls-cert`, `-tls-key`.
- Dependency-Track upload flags stay the same; add `-tls-ca`/`-tls-cert`/`-tls-key` if your Dependency-Track instance is mTLS-protected.

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
Goal: exercise alg selection (non-EdDSA).

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
- Keep the public key for verification: `/tmp/sbom-rsa.pub.pem` or `/tmp/sbom-ec.pub.pem`.

3) Register and verify:
- Register with `scrapi-demo-client -file /tmp/demo-sbom.cose -wrap-sbom=false ...` (as in the quickstart).
- Verify receipt + SBOM signature with your own verifier, or hand them to Dependency-Track as a provenance record alongside the BOM upload.

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

3) Configure verifiers or downstream services to use the JWKS for SBOM signature validation; the SCRAPI receipt verification is unchanged.

## mTLS end-to-end
Goal: require client certs on the SCRAPI server and verify with both the demo client and Dependency-Track upload.

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

4) Upload to Dependency-Track over TLS/mTLS:
```bash
go run ./cmd/scrapi-demo-client \
  -addr https://localhost:8443 \
  -tls-ca certs/ca.crt.pem \
  -tls-cert certs/client.crt.pem \
  -tls-key certs/client.key.pem \
  -sbom /tmp/demo-sbom.json \
  -wrap-sbom=true \
  -dtrack-url https://localhost:8081 \
  -dtrack-api-key <your-api-key> \
  -dtrack-project "scrapi-demo" \
  -dtrack-version "1.0.0" \
  -dtrack-auto-create
```

## Scan report loopback (auditor returns findings anchored in the log)
Goal: show that not just SBOMs, but also scan results can be signed, registered, and verified with receipts.

1) Let Dependency-Track analyze the SBOM you uploaded. Export findings (JSON) that reference the SBOM locator or hash.
2) Sign the findings JSON into COSE_Sign1 (auditor key/kid). Keep the public key for downstream verifiers.
3) Register the signed findings with SCRAPI:
```bash
go run ./cmd/scrapi-demo-client \
  -addr http://localhost:8080 \
  -file /tmp/demo-findings.cose \
  -wrap-sbom=false \
  -out /tmp/demo-findings-receipt.cose \
  -print-receipt-json \
  -config-out /tmp/transparency.cbor \
  -log-key-pem /tmp/log-public-key.pem
```
4) Deliver scan findings + receipt + locator. Verifiers check the auditor signature, log signature, and Merkle proof just like the SBOM.

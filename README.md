# go-scitt-scrapi

This repository is a compact Go module that demonstrates what a SCITT-style transparency service can look like in practice. It includes minimal domain types, an in-memory `TransparencyService`, SCRAPI-flavored HTTP handlers, a tiny client, and a runnable demo server. The goal is to provide a teaching aid and a starting point for experiments, not a full SCITT reference implementation.

## What SCITT is for

SCITT (Secure Component Integrity, Transparency, and Trust) is an emerging IETF architecture for creating tamper-evident, verifiable logs of software or supply chain statements. The model is:

- A producer signs a statement, such as an SBOM, attestation, advisory, version metadata, or provenance.
- The producer registers that signed statement with a transparency service.
- The service logs it and returns a receipt showing inclusion.
- Verifiers use the receipt to ensure the statement they see matches what was registered.

Goals include universal auditability, cross-vendor traceability, and a common cryptographic foundation for supply chain metadata. If you know Sigstore or Rekor, SCITT aims to standardize and generalize those ideas.

## Where SCRAPI fits in

SCRAPI (SCITT Reference API) is the HTTP interface for SCITT services: the wire protocol for publishing signed statements, polling registration status, fetching receipts, and discovering service configuration. It defines endpoints such as:

- `/.well-known/transparency-configuration`
- `POST /entries`
- `GET /entries/{id}`
- `GET /receipts/{id}`

This repository implements lightweight, Go-friendly versions of these endpoints based on draft-ietf-scitt-scrapi-05. The demo issues receipts synchronously; real deployments may defer issuance until after log inclusion.

## What this code does

- Defines core SCITT-like types under `scrapi/`: `SignedStatement`, `Receipt`, `Locator`, `RegistrationStatus`, and helpers.
- Provides an in-memory `TransparencyService` that hashes submitted COSE payloads to form locator IDs and returns a signed COSE receipt containing a Merkle inclusion proof, root hash, and tree size.
- Implements SCRAPI-style HTTP handlers in `scrapi/httpserver`.
- Supplies a minimal client helper in `scrapi/client`.
- Includes a runnable demo server under `cmd/scrapi-demo-server`.
- Captures an in-memory audit trail of registrations, status checks, and receipt lookups.
- Exposes the log public key and key ID via the well-known configuration endpoint for verification tooling.
- Accepts SBOM submissions (CycloneDX/SPDX JSON) and can wrap them into COSE for registration.
- Includes a Syft-powered SBOM generator under `cmd/syft-sbom`.

## Running the demo

Goal: show the end-to-end SCRAPI flow in three quick moves:

1. Start the server.
2. Post a signed statement.
3. See the returned locator and receipt.

### 1) Start the server

```bash
go run ./cmd/scrapi-demo-server
```

Default listen address: `:8080`.

### 2) Register with the bundled client (auto-generates a COSE_Sign1)

```bash
go run ./cmd/scrapi-demo-client -addr http://localhost:8080
```

Flags:

- `-file path/to/payload.cose` to send your own COSE_Sign1 instead of a generated one.
- `-message "text"` to change the payload used for the generated COSE_Sign1.
- `-out receipt.cose` to write the returned receipt to a file.
- `-sbom fixtures/sbom/sample-cyclonedx.json` to send an SBOM; `-wrap-sbom=false` sends raw SBOM (server wraps), `-wrap-sbom=true` signs locally and sends COSE.

### 2b) Register with curl (if you already have a COSE_Sign1 blob)

```bash
curl -X POST \
  -H "Content-Type: application/cose" \
  --data-binary @signed_statement.cose \
  http://localhost:8080/entries
```

### 3) Observe the response

Both methods return a locator ID (used to query `/entries/{id}`) and a signed receipt. The receipt payload carries a Merkle inclusion proof, root hash, and tree size; the COSE envelope is signed with the demo log key (Ed25519).

### Audit logging

- The server prints audit-friendly log lines for registrations, status queries, and receipt fetches.
- The in-memory service retains an audit trail in memory; `(*scrapi.InMemoryTransparencyService).AuditTrail()` returns a copy for inspection in tests or additional tooling.

## SBOM helpers

- Generate an SBOM with Syft (CycloneDX JSON by default):
  ```bash
  go run ./cmd/syft-sbom -source . -out sbom.json
  ```
- Register that SBOM via the demo client:
  ```bash
  go run ./cmd/scrapi-demo-client -addr http://localhost:8080 -sbom sbom.json -wrap-sbom=true
  ```
- A sample CycloneDX SBOM is available at `fixtures/sbom/sample-cyclonedx.json`.
- Bigger picture: SCITT receipts make SBOM sharing tamper-evident and time-bound. A producer can publish an SBOM with a receipt, and consumers can verify the receipt (signature and Merkle proof) to ensure the SBOM is exactly what was registered, when it was registered, and anchored to a log root. Pairing SBOMs with receipts helps downstream scanners, auditors, and deploy pipelines trust that the SBOM they ingest hasn’t been swapped or modified in transit.

## End-to-end SBOM + dependency-check demo

1) Generate an SBOM for a target:
   ```bash
   go run ./cmd/syft-sbom -source . -out sbom.json
   ```
2) Register the SBOM and get a receipt (signed COSE with Merkle proof):
   ```bash
   go run ./cmd/scrapi-demo-client -addr http://localhost:8080 -sbom sbom.json -wrap-sbom=true
   ```
   The client verifies the receipt signature, proof, and leaf hash against the SBOM bytes.
3) Run a vulnerability scan with OWASP Dependency-Check against the same project or SBOM (example):
   ```bash
   dependency-check --project demo --scan . --format JSON --out dc-report.json
   ```
   (If your dependency-check setup differs, adjust paths/flags accordingly.)
4) Register the scan result as a second statement (raw JSON or wrap it into COSE similarly):
   ```bash
   go run ./cmd/scrapi-demo-client -addr http://localhost:8080 -file dc-report.cose
   ```
   or:
   ```bash
   go run ./cmd/scrapi-demo-client -addr http://localhost:8080 -file dc-report.json -wrap-sbom=false
   ```
   Include metadata in your scan payload (e.g., the SBOM digest or locator) so consumers can link scan → SBOM.
5) Consumers retrieve receipts for both SBOM and scan, verify signatures and Merkle proofs, and check that the scan references the expected SBOM digest/locator. This creates an auditable chain: SBOM → scan result, both anchored in a transparency log.

## Other ways to build a SCITT service

- Use a Merkle-tree-backed append-only log so receipts carry inclusion proofs.
- Add a production-grade signer or HSM for receipts.
- Persist statements and receipts in a database or object store for durability and scale.
- Introduce background workers for asynchronous registration and policy evaluation before issuing receipts.
- Integrate SBOM or attestation producers upstream in CI or release pipelines.
- Implement full cryptographic inclusion proofs according to the SCITT architecture.

## Related ecosystems

- Sigstore and Rekor: existing public transparency logs.
- in-toto: signed supply chain step metadata.
- SLSA: provenance levels and guidance.
- Cosign: artifact signing tools.

SCITT aims to bring standardization and interoperability to ideas already present in these ecosystems.

## What this is not

- A production SCITT implementation.
- A conformance suite for SCRAPI.
- A real inclusion-proof log.
- A secure receipt-signing system.
- Persistent or fault-tolerant.

Use this module to explore the flow and data shapes, then replace pieces with hardened components when you build a real service.

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
- Provides an in-memory `TransparencyService` that hashes submitted COSE payloads to form locator IDs and returns a simple dummy COSE receipt.
- Implements SCRAPI-style HTTP handlers in `scrapi/httpserver`.
- Supplies a minimal client helper in `scrapi/client`.
- Includes a runnable demo server under `cmd/scrapi-demo`.

## Running the demo

Goal: show the end-to-end SCRAPI flow in three quick moves:

1. Start the server.
2. Post a signed statement.
3. See the returned locator and receipt.

### 1) Start the server

```bash
go run ./cmd/scrapi-demo
```

Default listen address: `:8080`.

### 2) Register with the bundled client (auto-generates a COSE_Sign1)

```bash
go run ./cmd/scrapi-client -addr http://localhost:8080
```

Flags:

- `-file path/to/payload.cose` to send your own COSE_Sign1 instead of a generated one.
- `-message "text"` to change the payload used for the generated COSE_Sign1.
- `-out receipt.cose` to write the returned receipt to a file.

### 2b) Register with curl (if you already have a COSE_Sign1 blob)

```bash
curl -X POST \
  -H "Content-Type: application/cose" \
  --data-binary @signed_statement.cose \
  http://localhost:8080/entries
```

### 3) Observe the response

Both methods return a locator ID (used to query `/entries/{id}`) and a dummy receipt. The demo issues receipts synchronously for simplicity.

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

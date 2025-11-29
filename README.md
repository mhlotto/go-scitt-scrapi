# go-scitt-scrapi

This repository is a compact Go module that showcases how a SCITT-style transparency service can look in code. It focuses on the minimal domain types, a small in-memory `TransparencyService`, HTTP handlers that speak SCRAPI-shaped endpoints, a simple client helper, and a demo server you can run locally to experiment.

## What SCITT is for

SCITT (Secure Component Integrity Transparency and Trust) provides an auditable log of signed software or supply chain statements. Producers register signed statements, transparency services return receipts, and verifiers later use those receipts plus log proofs to check that what they see matches what was registered. The goal is accountability and traceability for signed artifacts.

## What SCRAPI adds

SCRAPI is the HTTP-facing API for SCITT services. It defines well-known endpoints for publishing signed statements and retrieving receipts or configuration. The handlers here model the shapes and status flows from draft-ietf-scitt-scrapi-05 so that clients can post COSE_Sign1 payloads and immediately receive a receipt.

## What this code does

- Defines core types such as `SignedStatement`, `Receipt`, `Locator`, and `RegistrationStatus` in `scrapi/`.
- Implements an in-memory `TransparencyService` that hashes the submitted COSE payload to form an ID and emits a dummy COSE receipt.
- Exposes HTTP handlers in `scrapi/httpserver` for:
  - `/.well-known/transparency-configuration`
  - `POST /entries`
  - `GET /entries/{id}`
  - `GET /receipts/{id}`
- Includes a tiny client helper in `scrapi/client` to post entries, plus a demo server in `cmd/scrapi-demo` you can run directly.

## Running the demo

```bash
go run ./cmd/scrapi-demo
```

By default the server listens on `:8080`. POST a COSE_Sign1 blob with content type `application/cose` to `/entries` and you should receive a receipt and a locator ID.

## Other ways to build a SCITT service

- Replace the in-memory implementation with a Merkle-tree backed append-only log so receipts carry inclusion proofs.
- Plug in a real signer and key management for receipts, or delegate signing to an HSM.
- Store statements and receipts in a database or object store for durability and horizontal scaling.
- Add background workers to handle asynchronous registration and policy evaluation before receipts are issued.
- Integrate attestation formats or SBOM producers upstream so registration is part of a secure build pipeline.

## What this is not

- It is not a full SCITT reference implementation or production-grade transparency log.
- It is not a complete SCRAPI conformance suite. Error handling and status transitions are simplified.
- It does not verify signatures, manage keys, or provide inclusion proofs.
- It does not persist data beyond process lifetime.

Use this module as a learning aid and a starting point for experiments before moving to a hardened, audited service.

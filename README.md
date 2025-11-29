# go-scitt-scrapi

A minimal Go helper library for SCITT / SCRAPI-style transparency services. It includes core types, an in-memory `TransparencyService`, HTTP handlers that mimic draft SCRAPI endpoints, a tiny client helper, and a demo server.

## HTTP endpoints

- `/.well-known/transparency-configuration`
- `/entries` (POST to register)
- `/entries/{id}` (GET status/receipt)
- `/receipts/{id}` (GET receipt by ID)

## Running the demo

```bash
go run ./cmd/scrapi-demo
```

The demo starts an HTTP server (default `:8080`) backed by the in-memory service.

## Notes

- The handlers implement a simplified SCRAPI flow suitable for experiments and prototypes.
- The included `TransparencyService` is an in-memory implementation meant for demos; swap it out for a real backend as needed.

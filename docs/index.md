# go-scitt-scrapi + Dependency-Track Demo

This documentation explains how to run an end-to-end transparency demo using the Go SCRAPI server/client and OWASP Dependency-Track as the SBOM ingest/analyzer. It is organized so you can skim the flow, drill into details, or copy/paste commands when you are ready to run it locally.

## What’s here
- [Demo walkthrough](demo.md): step-by-step runs (HTTP, TLS/auth variants) with commands.
- [Story & roles](story.md): short narrative of the parties and why SCRAPI + Dependency-Track helps.
- [Dependency-Track integration](dependency-track.md): how the analyzer consumes SBOMs and how we tie its results back into SCRAPI.
- [Architecture & data flow](architecture.md): SCITT/SCRAPI context, COSE shapes, Merkle proofs, ASCII flow sketches.
- [Playbook ideas](playbook.md): scenarios to iterate on (multiple algs, JWKS, policy checks).

## Prerequisites (quick)
- Go toolchain and Syft helper (bundled via `cmd/syft-sbom`).
- Dependency-Track running locally (API key in hand).
- Basic command-line familiarity; no external services required.

## Status
- Initial docs scaffold with commands and placeholders for deeper dives.
- GitHub Pages workflow to be added separately.

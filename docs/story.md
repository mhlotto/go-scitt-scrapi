# Story: Who Does What and Why It Helps

This demo is about making SBOM sharing tamper-evident and auditable. Three human parties play:

- **Producer** (builder/vendor): creates an SBOM, signs it, and registers it with SCRAPI (the transparency log). Receives a receipt (locator + Merkle proof) that says “this exact SBOM was logged at this time.”
- **Analyzer/Operator** (Dependency-Track user): ingests the SBOM plus the SCRAPI receipt. Dependency-Track verifies the SBOM signature, validates the receipt against the log’s Signed Tree Head, and shows the result. It can later sign/register scan findings.
- **Consumer/Auditor** (downstream team, regulator, or customer): trusts that the SBOM being analyzed is the one the producer logged, and that findings can be anchored the same way.

## Flow at a glance
1) Producer builds SBOM → signs it → registers with SCRAPI → gets receipt + log key/ID.  
2) Producer (or operator) uploads SBOM + receipt to Dependency-Track with trusted signer key.  
3) Dependency-Track verifies: SBOM signature, receipt inclusion + freshness (STH/consistency), and records status.  
4) Operator reviews results; optional: sign and register findings back to SCRAPI (future step).  
5) Consumer/Auditor can independently verify the SBOM receipt and, later, a findings receipt to prove provenance.

## Security benefits the demo highlights
- **Tamper-evidence**: The SBOM you analyze is the one the producer logged (receipt + Merkle proof + log signature).
- **Identity & authenticity**: SBOM signatures prove who authored the SBOM; log key/ID proves which log anchored it.
- **Freshness**: Dependency-Track checks the receipt against the current Signed Tree Head (and consistency proofs) to detect stale or fabricated proofs.
- **Auditability**: Receipts/locators and freshness status travel with the BOM; downstream parties can re-verify with the log.
- **Extensible trust**: (Planned) findings anchoring lets scan results be proven and chained to the original SBOM.

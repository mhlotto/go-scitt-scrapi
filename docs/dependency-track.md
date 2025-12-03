# Dependency-Track Integration

How we hand the SCRAPI-anchored SBOM to Dependency-Track and keep the chain of custody intact.

## What the helper does
- Uploads a CycloneDX SBOM to Dependency-Track via `/api/v1/bom` (multipart form).
- Accepts project name/version (or UUID) and can `autoCreate` the project.
- Prints the processing token from Dependency-Track so you can watch the UI/API for analysis results.
- Keeps the SCRAPI locator/receipt alongside the upload so you can prove “this is the exact SBOM we ingested.”

## Flags in `scrapi-demo-client`
- `-dtrack-url` `<base>`: Dependency-Track API base (e.g., `http://localhost:8081`).
- `-dtrack-api-key` `<key>`: API key with `BOM_UPLOAD` permission.
- `-dtrack-project` `<name>`: Project name (used with `-dtrack-version`).
- `-dtrack-version` `<version>`: Project version.
- `-dtrack-project-uuid` `<uuid>`: Optional direct UUID if you already know the project.
- `-dtrack-auto-create`: Auto-create project when name/version do not exist.
- `-sbom` must be set so the client can upload the raw CycloneDX JSON (it does not send the COSE envelope to Dependency-Track).
- SCRAPI verification extras (optional, sent with the upload):
  - `-dtrack-scrapi-receipt` `<path>`: COSE receipt.
  - `-dtrack-sbom-cose` `<path>`: COSE_Sign1 of the SBOM (producer signature).
- `-dtrack-scrapi-base` `<url>`: SCRAPI base URL for fetching well-known config.
- `-dtrack-scrapi-log-key-pin` `<pem>` / `-dtrack-scrapi-log-key-id-pin` `<id>`: pin the log key/key id.
- `-dtrack-scrapi-trusted-sbom-key` `<pem>`: trusted producer key (PEM).
- `-dtrack-scrapi-trusted-sbom-jwks` `<url>`: trusted producer JWKS (Ed25519, `use=sig`).
- `-dtrack-scrapi-strict`: enable strict receipt checks (log_id/hash_alg, etc.).
- `-dtrack-scrapi-locator` `<id>`: optional locator string for logging/notification context.
- `-dtrack-poll`: poll Dependency-Track for processing status using the returned token (with `-dtrack-poll-attempts` / `-dtrack-poll-interval`).

## Typical flow
1) Generate/sign SBOM and register with SCRAPI to get `locator` and `receipt`.  
   Keep the locator handy; include it inside the SBOM metadata (e.g., CycloneDX `properties` or `externalReferences`) if you want Dependency-Track to persist the link.
2) Upload the SBOM to Dependency-Track with the flags above. The client prints:
   - Project reference (name/version or UUID used).
   - Upload token returned by Dependency-Track.
3) Watch Dependency-Track for analysis to complete (UI), or poll the `/api/v1/bom/token/{token}`/project APIs yourself to harvest findings.
4) Export findings as JSON (or VEX) that include the SCRAPI SBOM locator/hash, sign them into COSE_Sign1, and register with SCRAPI. Now both SBOM and findings are anchored.

## Notes and expectations
- Content type: SBOM is sent as multipart form (`bom=@...`) exactly as documented in Dependency-Track’s CICD guide.
- Permissions: API key must allow BOM uploads; auto-create requires portfolio/project-create perms.
- TLS/mTLS: reuse `-tls-ca`/`-tls-cert`/`-tls-key` flags to talk to Dependency-Track over HTTPS if needed.
- Token handling: the helper only prints the upload token; it does not poll analysis status yet. Use the UI or API to check progress and export findings.
- JWKS: SBOM signature verification now supports a JWKS URL via `-dtrack-scrapi-trusted-sbom-jwks` (Ed25519 keys, `use=sig`, optional `alg=EdDSA`).

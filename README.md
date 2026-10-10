# EmberCheckouts

EmberCheckouts is a ten-minute encrypted checkout handoff service. EmberAIO uploads a payload using a short-lived EmberAuth token. Possession of the UUID v4 is the intentionally shareable capability for public, reusable retrieval until the server-owned expiry.

Sensitive payload data is encrypted with AES-256-GCM before storage. The AAD binds the envelope version, EmberAuth subject, and checkout UUID. Cleanup irreversibly nulls ciphertext, nonce, encryption key ID, and envelope version after expiry while preserving non-secret analytics and allowlisted import outcomes.

## Local bootstrap

Requirements: Docker with Compose, OpenSSL, and Go 1.24 for host-side tests.

```sh
cp .env.example .env
KEY="$(openssl rand -base64 32)"
perl -i -pe "s|REPLACE_WITH_BASE64_32_BYTE_KEY|$KEY|" .env
docker compose up --build -d
curl -fsS http://localhost:8080/readyz
```

EmberAuth must be available at `EMBER_AUTH_URL` and publish `/.well-known/jwks.json`. Stop the stack with `docker compose down`; add `-v` only to intentionally erase PostgreSQL data.

Without Docker, point `DATABASE_URL` at any PostgreSQL 16+, apply the migrations in order, and run the binary directly:

```sh
for m in migrations/*.sql; do psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$m"; done
set -a; . ./.env; set +a
go run ./cmd/api
```

## Configuration

The service configuration is:

- `DATABASE_URL` — PostgreSQL connection string; required.
- `PUBLIC_BASE_URL` — origin used in returned open links; defaults to `http://localhost:8080`.
- `ENCRYPTION_KEY` — standard-base64 encoded, exactly 32-byte AES key; required. New payloads are sealed with it.
- `ENCRYPTION_KEY_ID` — ID stored with each envelope for `ENCRYPTION_KEY`; defaults to `primary`.
- `ENCRYPTION_KEYS` — optional `id:base64,...` list of previous keys that can still open existing payloads. IDs must be unique.
- `TRUSTED_PROXIES` — comma-separated CIDRs of the reverse proxy. Rate limits key on the right-most untrusted `X-Forwarded-For` hop only when the direct peer is in this list; empty ignores forwarded headers.
- `EMBER_AUTH_URL` — exact expected JWT issuer and base URL for JWKS; defaults to `http://localhost:8081`.
- `EMBER_AUTH_JWKS_URL` — optional JWKS discovery override for container networking; keep the public issuer in `EMBER_AUTH_URL`. Production should normally leave this unset.

The listen address, ten-minute lifetime, one-minute cleanup interval, 1 MiB body cap, and in-process rate limit have safe code defaults rather than deployment settings. Plain HTTP target/storage URLs are accepted only for loopback development when `PUBLIC_BASE_URL` itself uses loopback HTTP.

## EmberAuth token contract

`POST /v1/checkouts` requires an Ed25519 JWT bearer token. Verification is behind the `auth.Verifier` interface while EmberAuth is developed concurrently.

Expected token:

- JOSE `alg` exactly `EdDSA`, a non-empty `kid`, and optional `typ` exactly `JWT`.
- `iss` exactly equal to `EMBER_AUTH_URL` after trimming its trailing slash.
- `aud` exactly `ember-services`; additional audiences are rejected.
- A future numeric `exp`; an optional numeric `nbf` must not be in the future.
- A numeric `iat` no more than 90 seconds old and no more than 60 seconds in the future, so a leaked token with a long `exp` is still short-lived here.
- Non-empty `sub`, `membership_id`, `installation_id`, and `session_id`.
- `checkouts:write` in either the space-separated `scope` claim or string-array `scopes` claim.

The verifier caches valid Ed25519 JWKS keys for five minutes, refreshes after the cache lifetime, and immediately refetches once for an unknown `kid` to support signing-key rotation. Other key types and algorithms are ignored; the JWT header cannot select a non-Ed25519 verification path.

## API

- `GET /healthz`
- `GET /readyz`
- `GET /open` — static no-referrer page. Links use `/open#checkout=<uuid>`, so the capability does not enter access logs or referrers.
- `POST /v1/checkouts` — EmberAuth bearer token required.
- `GET /v1/checkouts/{uuid}` — public and reusable until exactly ten minutes after creation; then returns `410`.
- `POST /v1/checkouts/{uuid}/events` — public capability endpoint accepting only one allowlisted `outcome`.

Upload body:

```json
{
  "module": "skiddle",
  "site": "skiddle",
  "title": "Final Release",
  "targetUrl": "https://www.skiddle.com/basket/default.php",
  "proxyUrl": "http://user:pass@host:port",
  "cookies": [],
  "storage": {"local": [], "session": []},
  "display": {"quantity": 2, "price": "109.12", "currency": "GBP"},
  "producerVersion": "1.2.3"
}
```

The producer cannot provide `expiresAt`. A successful response includes checkout metadata and `openUrl`. Retrieval returns `handoff` and the server-owned `expiresAt`.

No endpoint sends CORS headers: the `/open` page is same-origin and EmberAIO is not a browser, so cross-origin scripts cannot read handoffs. Request logs record the route pattern (for example `GET /v1/checkouts/{checkoutID}`), status, and duration, never the concrete path, because the path carries the capability.

Allowed event outcomes are `import_succeeded`, `import_partial`, `invalid_payload`, `permissions_denied`, `cookies_failed`, `local_storage_failed`, `session_storage_failed`, `proxy_failed`, `navigation_failed`, and `unsupported_browser_state`. Arbitrary text, error messages, and extra fields are rejected.

## Data policy

Durable analytics contain only EmberAuth subject/membership/installation/session IDs, module/site, sanitized title, quantity, price/currency, producer version, target host, proxy-used boolean, timestamps, retrieval count, and allowlisted outcome codes. Cookies, storage values, proxy URL/credentials, full target URL, tokens, and raw errors exist only inside the encrypted ten-minute payload and are never logged.

## Development checks

```sh
make fmt
go test ./...
go test -race ./...
go vet ./...
```

Terminate TLS at a trusted reverse proxy, apply edge rate limits, and restrict PostgreSQL access. Losing `ENCRYPTION_KEY` makes live payloads unrecoverable.

## Key rotation

Payloads live for ten minutes, so rotation needs only a short overlap:

1. Generate a new key and give it a new ID, for example `ENCRYPTION_KEY_ID=2026-10`.
2. Move the old key into `ENCRYPTION_KEYS=primary:<old-base64>` and deploy.
3. After at least ten minutes (one payload lifetime plus cleanup), remove the old entry from `ENCRYPTION_KEYS` and redeploy.

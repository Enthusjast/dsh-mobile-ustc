# Remote service foundation

This Go service provides a strict resource-token authentication foundation, PostgreSQL-backed device registration/revocation, and grant-filtered host/runtime/session directory reads. Host installation proofs, grant management, enrollment, relay, file handoff, and reliable command journals remain unimplemented.

The service requires `REMOTE_ISSUER`, `REMOTE_AUDIENCE`, `REMOTE_JWKS_URL`, `REMOTE_CLIENT_IDS`, `REMOTE_REQUIRED_SCOPES`, `REMOTE_PUBLIC_ORIGIN`, and `REMOTE_DATABASE_URL`. A development listener can use `REMOTE_LISTEN_ADDR=127.0.0.1:8080`. Start it with `go run ./cmd/remote` from this directory. `GET /healthz` is liveness-only; `GET /readyz` checks PostgreSQL. `GET /v1/me` requires a JWT access token and a DPoP proof. `POST /v1/devices` registers separate approval and DPoP public keys, with the DPoP key bound to the access token; host, runtime, session, command-status, and revocation routes also require that key to belong to a non-revoked device. Apply `deploy/sql/001_remote_control.up.sql` before starting the service. Bind it to loopback during development. Production must place it behind a TLS ingress configured to the same external origin and use a PostgreSQL DSN with `sslmode=verify-full`.

Implemented routes are `POST /v1/devices`, `DELETE /v1/devices/{id}`, `GET /v1/hosts`, `GET /v1/runtimes`, `GET /v1/runtimes/{id}/sessions`, `PUT /v1/runtimes/{id}/grants/{user_id}`, `DELETE /v1/runtimes/{id}/grants/{user_id}`, and `GET /v1/commands/{request_id}?device_id=...`. Device registration requires an ES256 approval-key signature bound to the current DPoP proof JTI, verified identity, both key thumbprints, and normalized device-name digest. Runtime owners can delegate only actions and resources within their existing grant; owner grants must include `grant.manage`, and organization admins can assign them. Grant changes increment the version and write audit and outbox records in the same transaction. Directory and command-status data are filtered by the active user, organization membership, runtime grant, action scope, and session or workspace scope. An empty scope array grants no access. The OpenAPI contract is in `../../contracts/openapi/remote.yaml`.

Access tokens must be signed with RS256 or ES256, typed as `at+jwt`, issued by the configured issuer, intended for the configured audience, minted to an allowed OAuth client, contain every configured scope, and bind a P-256 proof key through `cnf.jkt`. No caller may choose the JWKS URL, algorithm, audience, client allowlist, or public origin through a request.

Resource requests must use `Authorization: DPoP <access-token>` and a separate `DPoP` proof JWT. The resource service challenges for a one-time `DPoP-Nonce`, verifies the method, public URI, `ath`, proof-key thumbprint, timestamp and `jti`, and rejects replay. Its in-memory nonce store supports a single service process only; multi-node deployment needs a shared atomic replay store before it can pass M1.

Development verification uses Go 1.26.8. PostgreSQL connections use the `pgx` database/sql driver pinned in `go.mod`:

```sh
go test -race ./...
go build -o /tmp/dsh-remote ./cmd/remote
```

The migration is a schema baseline only; this repository does not yet apply it automatically. Repository SQL has not been exercised against a live PostgreSQL server. User/org provisioning, enrollment, installation proofs, the OIDC/PKCE client flow, and a shared replay store remain outstanding. The authentication contract and its remaining gates are recorded in [M1 authentication notes](../../docs/m1-authentication.md).

# Remote service foundation

This Go service currently provides a strict resource-token authentication foundation and a single introspection route. It does not yet implement device registration, host grants, PostgreSQL metadata, relay, or command journals.

The access-token verifier requires configuration. Set `REMOTE_ISSUER`, `REMOTE_AUDIENCE`, `REMOTE_JWKS_URL`, `REMOTE_CLIENT_IDS`, `REMOTE_REQUIRED_SCOPES`, and `REMOTE_PUBLIC_ORIGIN`. A development listener can use `REMOTE_LISTEN_ADDR=127.0.0.1:8080`. Start it with `go run ./cmd/remote` from this directory. `GET /healthz` is unauthenticated; `GET /v1/me` requires a JWT access token and a DPoP proof. Bind the service to loopback during development. Production must place it behind a TLS ingress configured to the same external origin.

Access tokens must be signed with RS256 or ES256, typed as `at+jwt`, issued by the configured issuer, intended for the configured audience, minted to an allowed OAuth client, contain every configured scope, and bind a P-256 proof key through `cnf.jkt`. No caller may choose the JWKS URL, algorithm, audience, client allowlist, or public origin through a request.

Resource requests must use `Authorization: DPoP <access-token>` and a separate `DPoP` proof JWT. The resource service challenges for a one-time `DPoP-Nonce`, verifies the method, public URI, `ath`, proof-key thumbprint, timestamp and `jti`, and rejects replay. Its in-memory nonce store supports a single service process only; multi-node deployment needs a shared atomic replay store before it can pass M1.

Development verification uses Go 1.26.8 and no downloaded Go modules:

```sh
go test -race ./...
go build -o /tmp/dsh-remote ./cmd/remote
```

The authentication contract and its remaining gates are recorded in [M1 authentication notes](../../docs/m1-authentication.md).

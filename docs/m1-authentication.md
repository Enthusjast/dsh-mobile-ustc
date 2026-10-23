# M1 Resource authentication foundation

This is an implementation baseline, not evidence that the school identity provider has enabled the remote-control client or resource.

## Implemented

`services/remote/internal/auth` verifies OAuth JWT access tokens against a configured JWKS URL. It pins the issuer, audience, OAuth client allowlist, required scopes and acceptable algorithms; requires `at+jwt`, `iss`, `sub`, `client_id`, `jti`, `iat`, `exp`, and DPoP key binding; rejects duplicate JSON claims and refuses caller-supplied key URLs. Supported access-token signatures are RS256 and ES256; proof keys are P-256.

The middleware requires the DPoP authorization scheme, checks the proof signature, `typ`, method, externally configured URI, access-token hash (`ath`), proof-key thumbprint, timestamp, server nonce and one-use `jti`. It returns a fresh nonce after an authenticated request. Public URL comparison uses only configured origin and request path; `Forwarded` and `X-Forwarded-*` headers are not trusted.

The `GET /v1/me` route shows verified principal claims as a development probe. `GET /healthz` contains no identity detail. The server has bounded headers, idle time and graceful shutdown.

## Verification and remaining M1 work

`go test -race ./...` uses generated RSA and P-256 keys plus a local JWKS test server. Coverage includes issuer, audience, client, scope, expiration, not-before, `cnf.jkt`, JWT type, algorithm, duplicate JSON keys, DPoP method, URI, token hash, private JWK rejection, initial nonce challenge, nonce retry, concurrent replay and proof reuse. The initial PostgreSQL schema is in `deploy/sql/001_remote_control.up.sql`; it has not been applied to PostgreSQL or connected to the service. No live identity provider, token endpoint, Android client, production TLS ingress or data store is involved.

Configuration still needs the organization’s actual issuer, resource audience, Android public-client ID and allowed scopes. The provider must issue access tokens with the configured audience, acceptable `at+jwt` signing, and DPoP key binding. This must be confirmed against the provider rather than relaxed in code.

Before M1 can pass its exit gate, remaining work includes Authorization Code + PKCE mobile integration, device and installation registration, authorization checks backed by PostgreSQL, persistent grants and audit/outbox, a shared multi-node replay store, Host installation proofs and short-lived tickets, command journals, revoke propagation, durable `host_accepted` / `agent_queued` reconciliation, and failure testing.

The verifier follows [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html) for JWT access tokens, [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) for algorithm and token-type checks, [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) for DPoP proof binding, and [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html) for JWK thumbprints.

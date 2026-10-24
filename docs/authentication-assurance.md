# Authentication assurance for remote approvals

JWT verification retains optional `auth_time`, `acr` and `amr` claims from the signed access token. Malformed present claims reject that token; absent claims do not prevent ordinary remote access. Neither `iat`, token refresh, DPoP possession nor local device biometrics supplies a missing authentication event.

`auth.NewAssuranceVerifier` takes trusted deployment mappings of an exact issuer, OAuth client and local profile to an exact ACR plus required AMR values. ACR values have no implied ordering. AMR order is irrelevant, but names are case sensitive and every configured method must be present. The constructor copies its configuration and rejects duplicate issuer/client/profile rules. No mapping, including an empty configuration, supplies implicit approval authority.

Sensitive admission additionally requires a strictly unexpired access token, nonfuture issuance and authentication, authentication no later than token issuance, and an authentication age within the request's bound (0–900 seconds). There is no expiry or future-authentication grace period on this path. A refreshed token retains its original authentication age. A failed requirement needs an actual issuer-supported reauthentication flow; it cannot be fixed by adding fields to a phone request.

The verifier is an internal policy primitive. Callers must pass the principal established by JWT/DPoP middleware, and independently check the current device, approval key, owner grant, action, resource scope and pending execution. Production identity mappings and a real school IdP step-up/PKCE flow are not configured or demonstrated by local test fixtures.

References: OpenID Connect Core 1.0 §2 defines these authentication claims; RFC 9068 §2.2.1 describes their use in JWT access tokens. Deployment mappings must be verified against the actual issuer and client configuration before enabling approvals.

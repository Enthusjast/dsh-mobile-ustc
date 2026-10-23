# Go / DSH integration evidence

On 2026-10-24, `npm run test:remote-dsh` passed with the real Go `cmd/remote` entrypoint, an isolated PostgreSQL 18.6 cluster, and the installed npm DSH 0.2.1-rc.2. The plugin uses the same DSH session controller and Agent for local IPC and outbound Relay traffic. No TokenWorks process is involved.

Run from the repository root:

```sh
npm run test:remote-dsh
```

The Python runner creates a temporary private directory, initializes an unprivileged PostgreSQL cluster with no TCP listener, applies the migrations, builds the Go executable and host plugin, and runs the TypeScript integration. It always stops that cluster and removes its directory. It does not accept a database URL or use the existing PostgreSQL service. Go and PostgreSQL binaries must already be installed; use `REMOTE_TEST_GO` and `REMOTE_TEST_PG_BIN` when their paths differ from the local defaults. Run under an unprivileged account with Node/npm, Python 3 and the repository dependencies installed. The ordinary `npm run verify` remains independent of PostgreSQL.

The test seeds only three identities and organization membership through SQL. All subsequent device registration, enrollment and credential/ticket operations use the HTTP API with locally generated ES256 access tokens, DPoP nonce retries and registered-key proofs. Host and phone confirmations are separate calls. A third user with membership but no runtime grant cannot obtain a ticket or list that runtime.

The test opens the real host and mobile WebSocket connections, waits for the DSH catalog to appear through the PostgreSQL-backed directory, creates a session through Relay using an authorized workspace UUID and configured preset, then checks a snapshot, native events, assistant chunks, persisted command receipts, a replacement sync and fixed-cursor pagination. Repeating the creation request UUID returns one native session; unknown workspaces/presets are denied and changed creation content conflicts. Repeating the message request UUID produces one native user message; changing its body conflicts. Wrong pagination cuts require resynchronization. [Remote cancellation](session-cancel-protocol.md) interrupts a held model call, preserves interrupted partial output, rejects stale epochs and returns a durable settled status on retry. Unsubscribe releases the follower. Revoking an idle sibling device closes only that device; the primary phone can still page history. Revoking the primary phone user's grant while idle sends `access.revoked` and closes the socket within five seconds, prevents new tickets, and acknowledges the supported control outbox events.

A database dump is checked for absence of the unique prompt, model reply, local workspace path, enrollment code, raw host credential and mobile ticket. PostgreSQL still contains the intended command IDs, states and canonical digests. The test also exercises graceful service shutdown with upgraded sockets.

The identity issuer, model adapter and host credential/key provider are local fixtures. The test does not validate school IdP registration, PKCE, real model access, OS key storage, Android merging/cache or a production TLS ingress. Single-process outbox propagation and periodic authoritative connection checks are implemented; see [revocation evidence and deployment limits](revocation-propagation.md). Mobile lease renewal, durable multi-node fanout and target-load/failure-window measurements remain separate gates. This is combined Go/PostgreSQL/DSH evidence, not a production readiness or Android acceptance claim.

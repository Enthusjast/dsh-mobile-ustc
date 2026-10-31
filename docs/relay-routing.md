# Inter-node relay routing

The production service registers its host connections through the fenced
[PostgreSQL directory](relay-directory.md). A phone entering another node is
proxied to the current host owner over a private, mutually authenticated TLS 1.3
WebSocket. The owner runs the existing ticket consumption, installation/device
proof, narrower ticket scope, per-operation authorization, subscriptions,
approval and file protocol handlers. The ingress does not invent a second
business acknowledgement. Message bodies remain transient.

Enable the private transport with a unique stable `REMOTE_RELAY_NODE_ID` and
`REMOTE_RELAY_CONFIG_FILE`, after applying migrations through `021`:

```json
{
  "listen_addr": "10.0.0.11:8444",
  "origin": "https://relay-a.internal:8444",
  "ca_file": "relay-ca.pem",
  "certificate_file": "relay-a.pem",
  "key_file": "relay-a.key",
  "max_proxy_connections": 4096
}
```

Configuration and credential files must be regular owner-only files. Relative
paths resolve beside the configuration. Use a dedicated cluster CA. Each node
leaf certificate must have the origin hostname/IP SAN, both client/server EKUs
and exactly one URI SAN: `spiffe://dsh-remote/relay/<node UUID>`. Startup verifies
the certificate chain, hostname, lifetime, usages and node identity. The listener
binds an explicit literal private or loopback IP. Configure network access so
only relay nodes can reach it; the public HTTP router has no private RPC route.

The same private endpoint routes an explicit HTTP allowlist: approval decision
POSTs, host-file content GETs and file-status GETs. The ingress checks JWT/DPoP
cryptographic possession and current metadata only to select the owner. It does
not consume the nonce/JTI or attach an authenticated handler context. The owner
reconstructs the original allowlisted public path and runs the complete normal
middleware, consuming the original proof once. Caller-supplied principal claims
are never forwarded as authority. Host-file routing inspects the unconsumed
ticket and verifies its installation proof; the owner alone redeems the ticket,
binds the stream to the live host, and checks ongoing file authority.

HTTP forwarding has a separate 128-request budget, a 16 KiB approval body limit,
an eight-second approval deadline and 64 KiB file-copy buffer. It uses the same
certificate/node/generation checks, with redirects, ambient HTTP proxies and
application retries disabled. Drain cancels forwards. Partial upstream files
abort the response; no successful complete-file result is manufactured.
File registration/commit can temporarily return a conservative `waiting` hint;
subsequent file-status requests resolve the owner's current staged-ack hint.

Both sides verify certificate chains and node URI identity. The receiver checks
the caller's current database generation and lease, its own exact target
identity, and the committed runtime epoch/connection. The device still proves
its registered key against the owner's fresh challenge before its one-use
ticket is consumed. A route change during the handshake rejects admission.
Public caller headers cannot select another node or generation.

The optional transport is disabled by default. A single production node still
publishes its directory; a different node without a private endpoint cannot
silently service that owner's live operations. Older binaries that do not
publish fenced routes must be drained before enabling this transport.

Each ingress tunnel copies at most one 64 KiB message per direction, with no
additional user-space backlog. Each write has a five-second deadline; the
per-node ingress connection budget defaults to 4096 and is limited to 12000.
The existing owner's 16-message socket queue remains independently bounded.
No automatic reconnect, resubscribe or command replay occurs inside a tunnel.
Failure closes both transports; the client reconnects, obtains a fresh ticket,
reconciles stable request IDs and replaces its subscription snapshot.

Runtime replacement invalidates routed device connections during the normal
one-second batch authority checks. Node ownership loss or drain closes its
owner sockets and ingress tunnels. Cleanup from old host/node incarnations
cannot remove replacement routes. Directory resolution and business authority
checks retain their existing independent fail-closed deadlines.

Metrics distinguish `dsh_remote_relay_proxy_tunnels` and directional
`dsh_remote_relay_proxy_inflight_bytes` from owner sockets. The directional
`dsh_remote_relay_tunnel_transit_duration_seconds` measures one proxy leg.
`dsh_remote_relay_owner_http_forwards` reports the separate active HTTP budget.
The existing session route histogram measures the owner handler; it excludes
the added ingress leg. Quantiles must not be added or presented as complete
cross-node end-to-end latency. No resource identity or body appears in labels.

Validated October 27, 2026:

- Actual two-process production tests cover snapshots/assistant content,
  cross-resource denial, revoke, host migration and old cleanup, ingress drain,
  missing/forged node identities, stale generations/connections, wrong owner TLS
  identity, admission budgets and nonconsumption of rejected tickets.
- `python3 tools/integration/run_remote_dsh.py --cross-node` ran the full Go
  race/private-PostgreSQL suite and the actual installed npm DSH 0.2.1-rc.2
  composition. Host entered A; every phone WebSocket entered B. Native session
  creation, chat, history, cancel/archive, questions, signed approval decisions,
  grant invalidation and the database body boundary passed. The final fixture
  sends every phone HTTP/WebSocket to B, including approval submissions.
  Identity/model were local fixtures; no TokenWorks was attempted.
- Separate file tests run two independent production API/relay instances with
  private mutual TLS, a shared private PostgreSQL database and explicit local
  object/scanner/issuer peers. Host WSS enters A; phone HTTP/WSS and Host file
  downloads enter B. Real npm DSH stages the attachment, creates its native
  receipt and admits the file message once. Wrong-key and repeated file reads
  are denied; revoke cancels the source both before headers and during its body.
  These file cases run as two API instances in one test process, distinct from
  the two-production-process native chat/approval composition.

Final evidence: `.local/relay-routing-full-final.log` passed the complete Go
race/private-PostgreSQL suite and the cross-node production/native composition
(about 11.509 seconds for native); `.local/relay-owner-files-first.log` records
the focused native-file/read/revoke scenarios. `go vet ./...` and TypeScript
check passed. These fixtures do not establish physical Android, school SSO,
OEM push, 12000 connections or 2000 active sessions × 20 Hz capacity.

The bounded owner-crash scenario uses two production children, one Host
protocol fixture and one phone. It kills only the owned Relay child with
SIGKILL, preserves its stale database route, and verifies that admission through
the survivor fails until the Host explicitly reconnects there. The failed
transport does not consume the phone ticket. Recovery rejects the old sync and
requires new subscription/sync/epoch identities. A command remains `received`
until an explicit retry and a Host receipt; neither reconnect nor an accepted
retry replays its body. The Host receipt is a protocol fixture in this test;
native durable acceptance has separate DSH evidence above. The focused record
is `.local/relay-routing-owner-crash-second.log`.

The separate [native DSH owner-crash drill](native-relay-crash-drill.md) now
SIGKILLs only the real Host's owned Relay child while PostgreSQL and the ingress
survivor remain online. After natural consumer-lease expiry, explicit restart
and normal plugin reconnection preserve the native epoch/session, reject the
old sync, retain one original message across reconciliation, and accept a new
native message. It restarts the same node identity; production supervision and
automatic migration through another ingress remain deployment gates.

Before the subsequent test-scope change, clean revision `dcb4c83` also passed
the existing single-node 3000-connection profile: 200 active streams × 20 Hz for
30 seconds, 120000/120000 deliveries, admission 7.009 seconds, end-to-end p95
37.630 ms / p99 78.216 ms and revoke sample 189.571 ms. Evidence is
`.local/relay-capacity/relay-routing-3000/`. It remains a single-node result.

Per the October 27 development instruction, further large-load and physical
device tests are deferred, and OEM push-channel configuration is skipped.
Continue functional development with bounded local fixtures and simple emulator
checks when Android changes require them. The unrun acceptance gates remain
open rather than being treated as successful.

Restoring the shared database requires the separate [recovery isolation
procedure](database-recovery.md). Node generation alone cannot detect a database
and deployment configuration both rolled back to an old backup. The current
production entrypoint also fences its externally configured database epoch.

The separate [leaf certificate/key renewal drill](relay-certificate-renewal-drill.md)
restarts the owned ingress and owner one at a time under the same fixture CA,
checks fresh TLS peer fingerprints and reconciles the same installed DSH session.
It does not provide hot reload, CA replacement or certificate revocation evidence.

# Inter-node relay routing

The production service registers its host connections through the fenced
[PostgreSQL directory](relay-directory.md). A phone entering another node is
proxied to the current host owner over a private, mutually authenticated TLS 1.3
WebSocket. The owner runs the existing ticket consumption, installation/device
proof, narrower ticket scope, per-operation authorization, subscriptions,
approval and file protocol handlers. The ingress does not invent a second
business acknowledgement. Message bodies remain transient.

Enable the private transport with a unique stable `REMOTE_RELAY_NODE_ID` and
`REMOTE_RELAY_CONFIG_FILE`, after applying migrations through `020`:

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
  grant invalidation and the database body boundary passed. REST entered A in
  this fixture. Identity/model were local fixtures; no TokenWorks was attempted.

This stage provides WebSocket affinity. REST approval decisions and host-file
downloads still require their owner process; generic REST load balancing is not
yet accepted. The native fixture does not exercise cross-node file transfers,
physical Android devices, school SSO, OEM push, 12000 connections or the target
2000 active sessions × 20 Hz workload.

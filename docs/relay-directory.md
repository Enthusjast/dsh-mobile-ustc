# Relay connection directory

Migration `020` adds a rebuildable PostgreSQL directory. It contains runtime,
node, node generation, runtime epoch and connection UUIDs, with an optional
private HTTPS origin on the node registry. It stores no message bodies,
credentials or command acknowledgements.

`ControlConsumer.NewRelayDirectory` produces a repository that atomically
publishes the directory entry in the same transaction as host attachment.
Attachment holds a shared lock on its current node incarnation; registry
takeover cannot race through that transaction. The normal whole-transaction
serializable retry rules still apply. Library fixtures can continue to use the
unwrapped repository.

Resolution checks the current committed runtime connection, installation key,
host/enrollment state, 45-second host presence and the exact live node generation.
Every lookup has a two-second deadline. Directory presence grants no business
authority: tickets, device possession and every resource operation retain their
existing checks.

Renewal compares all ownership fields. Cleanup compares epoch, connection, node
and generation before removing a route. A late close from a replaced socket or
node cannot remove its successor. Registry takeover clears the previous private
origin; retained routes from an old generation immediately become unusable.
Routes are bounded by the runtime table and replaced on reconnect. An expired
node needs a new incarnation; host heartbeats cannot resurrect it.

Validated on October 27, 2026 with private PostgreSQL and Go race instrumentation:
`TestRelayDirectoryFencesConnectionAndNodeReplacement` and
`TestRelayDirectoryExpiryAndFailedAttachDoNotPublishOwnership` cover cross-node
resolution, old-close protection, generation fencing, expired leases, endpoint
reset and rollback under a blocked registry lock. The production entrypoint now
uses this repository for every host attachment; [private relay transport and
owner HTTP routing](relay-routing.md) have separate integration evidence.
Directory tests alone do not demonstrate cluster capacity.

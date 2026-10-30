# Approval details access and host results

Registered phones can also [read known status over HTTP](approval-http-status.md)
without a live socket or online Host. This uses the same current-owner read policy
as WSS status, returns metadata only, and does not issue execution authority.

The [bounded database outage drill](database-outage-drill.md) also runs two real
npm DSH Bash approvals. An approved, unspent invocation becomes invalidated before
its ordinary permit expires; a separately consumed invocation completes once while
disconnected and retains its durable succeeded fact. After relay restart, both facts
reconcile through the new Host connection with one matching resource audit each,
their original allow decisions, and fingerprinted acknowledgements. Current phone
status reads succeed, while old-connection details remain unavailable.

Approval details and result metadata now have explicit current-owner read checks. `ApprovalControl.AuthorizeView` requires both `approval.decide` and `session.read` in the admitted ticket and current owner grant, matching device/proof key/grant versions, active user/membership/host/installation/runtime and the exact original live connection/session/workspace. A read-only socket cannot inherit approval access from another socket's wider grant. `ListPending` returns at most 64 live, unexpired references and independently authorizes each item; it returns no parameters. `AuthorizeStatus` applies the same current owner/action/resource checks to stored metadata, including after host disconnection. Full details still require the original online host. Moving a session does not transfer an old workspace's approval body to a newly scoped reader.

Migration 007 adds a host journal state, fixed execution-outcome enum and service receipt time. These are metadata facts, not callbacks or executable permissions. Host `approved` leaves the service at `decision_received`. Host `consumed` marks an already spent permission as `allowed`, without claiming native tool success, and prevents further lease issuance. Only host `settled` carries `succeeded`, `failed` or `cancelled`. Both successful and failed tool results retain the signed approval's allow decision; a failed native tool is not relabeled as a user rejection.

`RecordResult` verifies the currently authenticated installation/runtime/connection/key, registered approval/session/epoch/execution/binding and the accepted decision digest where relevant. An unsigned pending request cannot become consumed/settled, a signed rejection cannot become an allow, conflicting final outcomes cannot replace each other, and late approved/consumed/unknown messages cannot downgrade a settled result. Actual host cancellation/expiry/invalidation is terminal. Matching retries write no duplicate audit/outbox event. State compare-and-set, audit and outbox commit together; failed/ignored updates or failed audit/outbox return no durable acknowledgement. Failure to record a result says nothing about whether the already-running tool executed; the host must retain and reconcile its durable fact.

Connection loss turns an unobserved accepted decision or consumed permit into service `outcome_unknown`. The last actual host state is retained separately; the service does not pretend it observed a host callback. A replacement connection from the same registered installation/runtime can reconcile a known final result for the old epoch, even after the phone/grant was revoked. This records history and grants no authority. The old connection is fenced. Recovered approvals never regain a native callback, a pending state or a lease. Current phone authorization still controls disclosure of reconciled results.

Active-limit accounting includes consumed permits until settlement, deadline or disconnection. A long-running tool whose result has not been observed can therefore become unknown and later reconcile a trustworthy result. No result is automatically replayed. Downgrading migration 007 retains audit/outbox facts and maps spent but unsettled work to unknown; re-upgrade cannot revive execution.

`npm run test:remote-dsh` runs these PostgreSQL tests with race detection in disposable databases: narrowed sockets and operator denial, offline metadata/full-detail distinction, exact result bindings, retries and out-of-order receipts, incompatible final outcomes, takeover with historical settlement, revocation, storage failures and rollback/re-upgrade. The existing real npm DSH chain runs afterward. The [server HTTPS/WSS transport](approval-protocol.md) now exposes these operations and consumes durable metadata references. The [normal plugin sender](approval-native.md) now delivers durable host facts with fingerprinted acknowledgements; production identity and the remaining platform/capability gates remain open.

Private [approval transition metrics](approval-observability.md) count confirmed
commits, separating control state from Host journal state/outcome. In particular,
allowed/consumed is not settled execution, duplicate result reports do not count
again, and a historical correction cannot issue a new execution lease.

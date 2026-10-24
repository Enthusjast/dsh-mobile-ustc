# Signed approval server transport

The configured Go service now exposes `approval.signed.v1` and `POST /v1/approvals/{id}/decisions`. The [wire schema](../contracts/ws/v1/approval.schema.json) is a separately negotiated extension to the base Relay contract. The [normal plugin integration](approval-native.md) now offers this capability when explicitly provisioned and connects native ownership, actual-body constraints and durable result delivery. Go fixture-peer tests remain separate component evidence; the CLI suite also exercises the normal plugin against the real service.

Enable the server only through `REMOTE_APPROVAL_POLICY_FILE`. Omission leaves both the capability and HTTP decision endpoint unavailable. The file supplies a fixed policy/version/profile/maximum authentication age, explicit issuer/client/ACR/required-AMR mappings, and a dedicated P-256 service signing identity. Mapping issuers and clients must already be trusted by the JWT verifier, and at least one mapping must match the configured profile. There is no default mapping or automatic MFA inference. A deployment template is:

```json
{
  "policy": { "version": 7, "assurance_profile": "school/step-up", "max_auth_age_seconds": 60 },
  "mappings": [{
    "profile": "school/step-up", "issuer": "https://id.example.edu", "client_id": "android",
    "acr": "urn:example:verified", "required_amr": ["otp"]
  }],
  "signing": {
    "issuer": "https://remote.example.edu", "key_id": "dsh-approval-authority/current",
    "private_key_file": "/run/secrets/approval-key.pem",
    "valid_from": "<UTC millisecond timestamp>", "valid_until": "<UTC millisecond timestamp>"
  }
}
```

Replace all example identity/method values with the issuer's verified configuration; the example establishes no school MFA capability. Key validity must include startup time. The server accepts a single unencrypted PKCS8 or SEC1 EC private-key PEM, at most 16 KiB, from a regular file with no group/other permission bits. Symlinks and multiple PEM blocks are rejected. A relative key path resolves against the policy file. The key is cloned into the signer and never printed; this is an explicit server secret-file loader, not an OS/HSM provider. Install the public authority anchor independently on the host. No anchor supplied by a phone or JWS header is trusted automatically. Apply migrations through 007 before starting the new service.

Host flow:

1. Durably register the native execution locally, publish its session catalog, then send `approval.request` with the exact context on the authenticated current host connection. The service verifies policy/ownership/catalog facts and commits metadata/audit/outbox before `approval.registered`.
2. Respond to `approval.details.get` with the original context in `approval.details`, or `approval.error` for an unavailable/stale request. The request ID is a fresh service RPC ID, separate from the phone's routing ID. The service verifies identity and canonical binding before using or disclosing the response.
3. Receive `approval.decision` containing the phone JWS and separately signed control-plane authorization JWS. The host must independently verify both, use its synchronous verified lease cache, and persist one-use consumption in the final guard. A transport write is not a native result.
4. Send journal facts using `approval.result`; include its exact context/decision digests and a canonical `payload_sha256`. The hash covers JCS `{type,runtime_id,runtime_epoch,session_id,payload}` and excludes v/request_id/hash. `approval.result.ack` echoes that fingerprint only after result/audit/outbox commit. Historical result epochs may differ from the current reporting connection; this reconciles facts and never restores callbacks or authority.

The normal host adapter retains durable result facts until their matching acknowledgement and closes/invalidates pending authority when its connection or policy lifecycle ends. The current server does not interpret a service audit or an outbox publication as acknowledgement of host execution.

Phone flow:

1. Negotiate the capability on a scoped, key-proved WSS connection. `approval.subscribe` returns at most 64 current pending references in `approval.snapshot`; subsequent `approval.reference` frames carry status metadata only. `approval.unsubscribe` releases the watch. Owner, `session.read` and `approval.decide` must all remain authorized on that exact socket and current grant.
2. Use `approval.details.get` for an online current context. Details are never reconstructed from server metadata. Each outgoing body fragment rechecks current owner/resource authority. Display and hash the full context, then sign allow_once/reject using the registered approval key.
3. POST `{connection_id,decision_jws}` to `/v1/approvals/{id}/decisions` using a fresh resource JWT and DPoP proof. The connection must be the same active device/proof key and its ticket scope is still enforced. JWT auth_time/acr/amr are validated by the real HTTP middleware and explicit assurance mapping; arbitrary phone assurance or caller public keys are not accepted. There is no custom OAuth proof inside a WSS business frame.
4. The response carries durable status and `delivery: pending|forwarded|recorded`. A failure after decision commit can leave delivery pending; retry the same canonical proof while valid or reconcile status. It does not mean the tool did not execute. `approval.status.get` retrieves authorized status metadata even after the host goes offline, so a missed final notification need not leave a cached pending view unresolved.

The service keeps full context only during registration/reassembly or one details RPC; it retains no approval body cache. Each context is at most 128 KiB. Large contexts use at most four ordered 40 KiB parts in `approval.fragment`, with canonical standard base64 and visible routing on every part. Reassembly has a three-second deadline, at most four transfers per host, 64 globally and 8 MiB total. Unsolicited details fragments, changed routing/transfer identity, duplicate/out-of-order parts, malformed JSON and size overruns are rejected; disconnection releases assemblies.

Details RPCs have a three-second deadline, with at most four per requesting socket, eight per host and 64 globally. Approval operations have a separate 20-per-second per-socket admission budget. There is one approval watch per mobile socket, at most 64 per runtime and 16,000 globally. A watch queues at most 64 changed IDs, not contexts. Snapshot delivery precedes its reference worker; each queued ID is re-read under current authority, so a racing/delayed event cannot overwrite a terminal fact with an older pending payload. A slow/failed watcher closes for resynchronization. Disconnect/drain cancel pending lookups and wait for delivery workers.

Committed approval pending/decision/end/result events are consumed through the existing single-process control outbox worker as metadata references. Authorization-prepared events are acknowledged without sending an execution claim. Replaying an old event reads the current authoritative state. Durable multi-node fanout and background push remain later gates.

Validation includes strict TypeScript/schema frames, Unicode fragmentation and cross-language result digests; Go capability, scope, snapshot-race, cancellation, cleanup and failure-path tests; secret/configuration checks; and real PostgreSQL + JWT/DPoP + signed WSS peers exercising weak-assurance/altered-signature denial, valid lease forwarding, native-result metadata, offline reconciliation and stale-grant denial. The Go composition test uses fixture peers; the separate CLI test now uses the normal signed plugin with a real Bash tool. Neither is Android. `npm run test:remote-dsh` runs these Go/PostgreSQL tests before the existing production Go + real npm DSH 0.2.1-rc.2 session/question chain. Normal callback/body/guard wiring and durable host result delivery have local real-DSH evidence; production school identity, host key provisioning, Android and the remaining capability/OS/load gates remain incomplete.

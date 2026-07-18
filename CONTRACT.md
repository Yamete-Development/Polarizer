# Polarizer v2 Integration Contract

The Protobuf files are the executable source of truth. This document records transport and ownership rules that are not expressible in `.proto` files.

## Canonical schema

- `proto/trust_and_safety/v2/models.proto`: actions, scopes, subjects, effects, decisions, moderation resources, safety assessments, and review items.
- `proto/trust_and_safety/v2/policy.proto`: policy bundles, immutable versions, manifests, fixtures, diagnostics, provider health, and traces.
- `proto/trust_and_safety/v2/events.proto`: Kafka envelopes, commands, results, delivery callbacks, and cache invalidations.
- `proto/trust_and_safety/v2/api.proto`: gRPC service.
- `proto/prism/prism_jobs.proto`: binary Prism payload retained end to end.

Do not introduce JSON mirrors, JSON report blobs, alternate copies of these schemas, or client-supplied reviewer/moderator identities.

## Kafka

| Topic | Key | Binary value |
|---|---|---|
| `events.trust-safety.action.requested.v2` | `scope-type:scope-id` | `ActionRequested` |
| `events.trust-safety.decision.v2` | action ID | `DecisionPublished` |
| `events.trust-safety.commands.v2` | command ID | `CommandEnvelope` |
| `events.trust-safety.command-results.v2` | command ID | `CommandResult` |
| `events.trust-safety.policy.invalidated.v2` | bundle ID | `PolicyCacheInvalidated` |
| `events.prism.delivery.v2` | action ID | `PrismDeliveryCallback` |
| `prism.stream.jobs` | scope key | `prism.PrismStreamPayload` |

Every record carries these Kafka headers:

- `ce_specversion=1.0`
- `ce_type`
- `ce_source=/polarizer` for Polarizer-produced records
- `ce_id`
- `ce_time`
- `ce_datacontenttype=application/protobuf`
- `content-type=application/protobuf`

Missing or malformed event types go to the restricted corresponding `.dlq` topic. Consumers acknowledge only after the state change or external side effect succeeds. A failed record rewinds its partition to the earliest uncommitted offset.

### Durable command delivery

Polarizer writes every `NOTIFY`, `DELETE`, or `KICK` command to `trust_safety.processed_command` in the same transaction that persists the decision and outbox record. Bot consumers must use `ClaimCommand` before a side effect and `CompleteCommand` afterward:

- Claims use a claimant ID and expiring lease token.
- The claim returns Polarizer's stored canonical `CommandEnvelope`; consumers never execute a potentially altered Kafka body.
- Completed commands return their stored result on duplicate claims.
- An active lease owned by another claimant returns busy without executing the command.
- An expired retry-safe lease may be claimed again.
- An expired non-retry-safe lease becomes `RECOVERY_REQUIRED`; it is never executed automatically again.
- Completion requires the current lease token and stores success, result code, and typed result metadata durably.

The Polarizer ledger and RPCs and the bot claim/complete consumer are implemented. Kafka acknowledgment happens only after `CompleteCommand` durably stores the outcome and enqueues its result event; a transient failure is deferred without being converted into a poison-message DLQ acknowledgment.

## Message state

```text
PENDING_MODERATION
    ├── BLOCKED
    ├── HELD
    ├── EXPIRED
    └── APPROVED_PENDING_DELIVERY
              ├── ACTIVE
              └── DELIVERY_FAILED
```

Only a successful Prism delivery callback may transition approved content to `ACTIVE`.

`HELD` actions retain an encrypted Prism payload and a maximum hold deadline. `AdjudicateHeldAction` accepts an action ID or linked review-item ID, an expected resource version, a required reason, and one of:

- `APPROVE`: atomically publishes the stored Prism payload, moves the action to `APPROVED_PENDING_DELIVERY`, and resolves pending review items.
- `REJECT`: moves the action to `BLOCKED` and resolves pending review items without publishing content.
- `EXPIRE`: moves the action to `EXPIRED` and resolves pending review items without publishing content.

The expiry worker automatically applies `EXPIRE` after the stored hold deadline. Every manual or automatic resolution increments the action version and writes an audit event. The server RPC and bot client are implemented; reviewer UI wiring remains in progress.

## gRPC authentication and authorization

The server listens on port `50051` with a server certificate and requires a client certificate signed by `GRPC_TLS_CLIENT_CA`.

Every request includes `RequestContext`:

- `request_id`: UUIDv7 generated per logical request.
- `actor_id`: authenticated human ID for human operations, or the service identity for service-only operations.
- `actor_type`: `HUMAN` for moderation/control-plane changes and `SERVICE` only for explicitly service-only APIs.
- `service_principal`: caller deployment identity, allowlisted per method by `SERVICE_PRINCIPAL_ALLOWLIST_JSON`.
- `idempotency_key`: required for every mutation and reused across transport retries.
- `trace_id`: optional distributed trace correlation.

Human permissions are checked with Iris. Iris timeout or unavailability returns `UNAVAILABLE` and no mutation occurs. Service actors cannot call methods that require a human permission.

The claimed principal must also match the SHA-256 fingerprint of the actual mTLS client certificate through `SERVICE_PRINCIPAL_CERT_SHA256_JSON`. A certificate fingerprint may be assigned to only one principal.

NSFW exact/perceptual hash overrides are administered through the typed
`CreateNsfwOverride`, `GetNsfwOverride`, `ListNsfwOverrides`,
`UpdateNsfwOverride`, and `DeleteNsfwOverride` RPCs. Every operation requires
the global `ADMINISTRATOR` permission. Mutations require idempotency keys;
updates and deletes require optimistic versions and produce before/after audit
records. An exact SHA-256 override takes precedence over a perceptual-hash
override, and both take precedence over cached or freshly computed model
classification.
Wildcard method grants are rejected at startup; every service principal must have an explicit non-empty method set and at least one certificate fingerprint.

Permission mapping:

| Permission | Operations |
|---|---|
| `VIEW_LOGS` | reports, moderation history, traces, assessments, flags |
| `MODERATE_HUB_MESSAGES` | warnings, mutes, message actions, Hub cases |
| `MANAGE_BANS` | Hub bans and unbans |
| `MANAGE_RULES` | Hub policy drafts, fixtures, tests, shadow mode |
| `MANAGE_GLOBAL_BLACKLISTS` | platform restrictions |
| `HANDLE_LOBBY_REPORTS` | Lobby cases |
| `ADMINISTRATOR` | global policies, providers, and NSFW overrides |

`GetRestriction` authorizes against the stored restriction scope. `UpdateRestriction` first loads that stored scope and restriction type, then applies the corresponding permission (`MANAGE_BANS` for bans, moderation permissions for other Hub restrictions, and the mapped platform/Lobby permission). A caller cannot move a restriction to another scope or subject through an update.

## Mutation semantics

- Resource versions are optimistic concurrency tokens.
- Update/revoke/resolve operations must include the expected version.
- `UpdateRestriction` accepts a `FieldMask`; only `reason` and `expires_at` are mutable. An explicit `expires_at` mask with no timestamp clears the expiry.
- Idempotency is scoped by service principal and key. Repeating the same mutation returns its original resource.
- Mute and ban infraction creation includes its enforcement restriction in the same request. Polarizer creates both in one transaction and stores the linked restriction ID on the infraction.
- Revoking a linked infraction revokes its enforcement restriction in the same transaction.
- Scripts never execute effects directly. Polarizer validates, merges, persists, and applies accepted effects transactionally.
- Stored fixtures are versioned resources. Any fixture change increments the policy version's fixture revision, so a stale passing test run cannot satisfy publication.
- Mandatory platform versions require two explicit `ApprovePolicyVersion` calls from distinct administrators before activation. Publishing does not implicitly approve.

## Policy runtime contract

Feature invocations are isolated by provider name plus a fingerprint of configuration, deadline, and maximum data-handling class. Policies may therefore request the same provider with different controls without overwriting or reusing one another's values. Runtime snapshots project the appropriate value back to the provider name for each policy. Trace snapshots retain the invocation fingerprint and call each provider's `redact_for_trace` hook. Providers that handle content persist only approved metadata; normalized text is available to policy evaluation but replaced by length and normalization metadata in traces.

`luau-v1` compiles immutable bytecode before publication and evaluates it in `polarizer-policy-worker`, never in the API/Kafka process. Each evaluation receives a fresh sandbox with frozen `action` and `features`. The worker exposes only typed constructors for:

- `allow`, `block`, `hold`, `censor`
- `flag`, `notify`, `route_review`
- `create_infraction`, `create_restriction`
- `label_entity`, `increment_counter`
- `delete`, `kick`

The sandbox clears its environment, has no stdin other than the bounded worker protocol, emits no stderr, and exposes no filesystem, network, process, dynamic-loading, `os`, `io`, `package`, `debug`, or `require` facilities. Source size, heap, VM interrupts, CPU time, wall time, protocol frames, and returned output are bounded. Timeout/protocol failure kills the worker process; Polarizer validates every returned effect again before persistence. The production Docker image packages both binaries and configures the API to execute the packaged worker as a non-root user.

## Data handling

Webhook credentials remain inside the encrypted Prism payload and are not emitted in decisions, traces, errors, or logs. Content submitted to external providers is the minimum permitted by the action's data-handling class.

OpenAI image moderation requires two independent approvals: `OPENAI_EXTERNAL_IMAGES=true` at deployment and `external_images: true` in that policy's provider configuration. If either is absent, attachment URLs are not sent externally; local media classification remains the default.

Local attachment fetching enforces all of the following on every redirect hop:

- HTTPS, no URL credentials, approved exact/subdomain host, and port 443.
- Fresh DNS lookup whose complete answer contains no private, loopback, link-local, multicast, documentation, benchmark, reserved, or private-embedded transition address.
- A direct connection pinned to the validated address with system proxies disabled, preventing proxy DNS re-resolution and DNS-rebinding races.
- At most three redirects, bounded connection/total deadlines, declared and streamed byte limits, approved image MIME types, and agreement between MIME, magic bytes, and decoded format.
- Header-level pixel checks before decode plus decoder width, height, allocation, and total-pixel limits to reject oversized or highly compressed image bombs.

## Integration status

The Protobuf and Polarizer server implementations for restriction updates, held-action adjudication, and durable command claims are landed. Bot restriction editing and command-consumer claim/complete wiring are landed. Bot reviewer adjudication UI remains in progress and must not be represented as enabled until its end-to-end tests pass.

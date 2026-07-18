# Polarizer

Polarizer is InterChat's authoritative trust-and-safety service and dynamic policy engine. Hub and Lobby actions are evaluated here before user content can reach Prism.

## Architecture

```text
Bot action (binary Protobuf)
        │
        ▼
Kafka action inbox ──► feature dependency plan ──► policy-ir-v1 / luau-v1
        │                                                │
        │                                                ▼
        │                                      typed effects + trace
        │                                                │
        └──────── PostgreSQL transaction ◄───────────────┘
                         │
                         ├── decision event
                         ├── durable command ledger + bot commands
                         └── approved Prism job
```

PostgreSQL 18 is authoritative for policies, decisions, restrictions, infractions, counters, safety assessments, review items, inbox state, and outbox state. Redis is not an authority. Kafka payloads are binary Protobuf; CloudEvents metadata is carried in Kafka headers.

## Safety properties

- Content is `PENDING_MODERATION` until Polarizer commits a decision.
- Blocked or held content is never published to Prism.
- Held actions have a bounded deadline and can be approved, rejected, or expired through an audited, version-checked adjudication transaction. Approval alone releases the encrypted Prism payload.
- Approved content remains `APPROVED_PENDING_DELIVERY` until a Prism callback marks it active.
- Global mandatory policy cannot be weakened by product, Hub, Lobby, or overlay policy.
- Policy scripts return typed effects and cannot access databases, networks, files, processes, secrets, or environment variables.
- Luau executes in isolated worker processes with instruction, heap, wall-time, source, and output limits.
- Luau receives only frozen action/features and typed constructors for allow, block, hold, censor, flag, notify, infraction, restriction, review, label, counter, delete, and kick effects. Returned effects are validated again in Polarizer.
- OpenAI moderation is an optional typed feature provider. Policies choose categories, thresholds, and explicit outage behavior.
- External images reach OpenAI only when both the deployment and the individual policy invocation opt in; local image classification is the default.
- Attachment downloads require an approved HTTPS host on every redirect, pinned public DNS answers, no proxy re-resolution, bounded streaming, matching MIME/decoded formats, and byte, pixel, and decoder-allocation limits.
- Mutations require an authenticated human actor, an allowlisted service principal, and an idempotency key.
- gRPC and Iris connections require mutual TLS.
- Full Prism payloads are encrypted at rest in the action inbox and are never logged.
- Feature invocations are isolated by provider configuration, deadline, and data-handling class. Runtime values remain available to policy evaluation while providers control the redacted representation persisted in traces.
- Bot side effects are registered transactionally in PostgreSQL before publication. Claim/complete leases make retry-safe commands recoverable and route ambiguous non-retry-safe outcomes to manual recovery.

## Contracts

The canonical schemas live in [`../proto/trust_and_safety/v2`](../proto/trust_and_safety/v2) and [`../proto/prism/prism_jobs.proto`](../proto/prism/prism_jobs.proto). Generated Rust code is committed under `src/generated`; production builds do not depend on sibling repositories or a locally installed Protobuf compiler.

See [CONTRACT.md](CONTRACT.md) for the topic, header, authentication, state, and API contract.

## Running locally

Requirements:

- PostgreSQL 18
- Kafka
- a Polarizer server certificate and trusted client CA
- an Iris client certificate and trusted Iris CA
- the `polarizer-policy-worker` binary on `PATH` or configured explicitly

```bash
cp .env.example .env
# Fill all required credentials and endpoints.
cargo run -- migrate
cargo run --bin polarizer
```

The service exposes:

| Address | Purpose |
|---|---|
| `:50051` | mutually authenticated gRPC |
| `:9090/live` | liveness |
| `:9090/ready` | readiness |
| `:9090/metrics` | Prometheus text metrics |

`POLARIZER_AUTO_MIGRATE=true` is the safe default for a simple deployment: migrations finish before any health server, gRPC server, or Kafka consumer starts. SQLx uses a PostgreSQL advisory lock, and `POLARIZER_MIGRATION_TIMEOUT_SECONDS` bounds lock acquisition plus execution. Any migration error terminates the process before readiness.

For replicated deployments, prefer a one-shot `polarizer migrate` init/pre-deployment job and set `POLARIZER_AUTO_MIGRATE=false` on service replicas. The migration-only command needs only `DATABASE_URL`, `DATABASE_MAX_CONNECTIONS`, `POLARIZER_MIGRATION_TIMEOUT_SECONDS`, and optional `LOG_LEVEL`; it does not require runtime TLS, Kafka, Iris, or policy-worker configuration.

## Policy runtimes and features

Initial runtimes:

- `policy-ir-v1`: typed declarative rule trees used by built-in policy and visual editors.
- `luau-v1`: isolated advanced scripting for custom control flow.

Registered feature providers include normalized text, deterministic automod matching, restrictions, durable counters, safety assessments, entity labels, local NSFW classification, and OpenAI moderation. The compiler resolves dependencies so providers only run when an applicable rule requests them.

Classifier-style providers live in the `policy::features::checks` catalog. OpenAI moderation is one optional external check beside deterministic automod and local NSFW classification; the policy engine has no OpenAI-specific branch. Every provider implements the same read-only lifecycle (`resolve`, deadline enforcement, health, trace redaction) and publishes typed category, cache, and external-I/O metadata. Adding another local model or external classifier consists of implementing `FeatureProvider` and adding its factory to `checks::configured`; it does not change `main.rs`, policy runtimes, or effect enforcement. Duplicate provider names fail startup instead of silently replacing an existing check.

Each distinct provider invocation is keyed by its configuration, deadline, and maximum data-handling class. This prevents two policies that request the same provider with different controls from sharing a result accidentally. Trace snapshots use provider-owned redaction; normalized message content, credentials, and submitted external-provider inputs are not persisted as trace values.

## Integration status

| Capability | Status |
|---|---|
| `GetRestriction` / `UpdateRestriction` with field masks and optimistic versions | Implemented in Polarizer and wired into the bot moderation UI |
| Held-action lookup/adjudication and automatic expiry | Implemented in Polarizer; bot client exists, reviewer UI wiring is in progress |
| Durable command claim/complete ledger | Implemented in Polarizer and wired into the bot command consumer |
| Policy authoring, fixtures, approval, shadow, activation, and rollback APIs | Implemented server-side; broader Winter control-plane UI remains in progress |

## Verification

```bash
cargo fmt --all -- --check
cargo check --offline
cargo test --offline --all-targets
```

## Source layout

```text
src/
├── auth.rs                    # Iris authorization and service allowlists
├── eventbus.rs                # Kafka inbox, outbox, decisions, commands, callbacks
├── command.rs                 # durable command claim/complete leases and recovery
├── grpc/                      # v2 control-plane and moderation API
├── moderation/                # authoritative resources and transactional mutations
├── policy/
│   ├── engine.rs              # dependency planning and evaluation
│   ├── merge.rs               # scope precedence and effect merge
│   ├── ir.rs                  # policy-ir-v1 runtime
│   ├── luau.rs                # isolated luau-v1 runtime client
│   ├── worker_protocol.rs     # bounded worker protocol
│   └── features/              # registered read-only providers
│       └── checks/            # declarative classifier catalog (OpenAI is one check)
├── bin/polarizer-policy-worker.rs
└── generated/                 # committed Protobuf output
```

The clean PostgreSQL 18 baseline is [`migrations/20260714000001_trust_safety_v2_baseline.sql`](migrations/20260714000001_trust_safety_v2_baseline.sql).

The production Docker image builds and packages both `polarizer` and `polarizer-policy-worker`, sets `POLARIZER_POLICY_WORKER_BIN` to the packaged worker, and runs the service as a non-root user. A deployment is not ready without the worker binary.

The image does not download or bake in a third-party NSFW model. To enable the
local media check, mount an approved ONNX model read-only and set
`NSFW_MODEL_PATH` to that container path. Without it, the check is simply not
registered and policies requiring it follow their declared provider-failure
behavior.

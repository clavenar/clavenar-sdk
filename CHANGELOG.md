# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/);
versions track `Cargo.toml`. The crate is a path-dep (not published),
so "released" here means "consumed by clavenar-console / clavenar-ctl
at that version".

## [Unreleased]

## [0.3.0]

- Embed the exact `clavenar.client-migration/v1` fixture and schema, document
  the client-first explicit-selector rollout, and retain side-effect-free
  decision selection with a canonical pre-network request ID.

### Added

- `reconciling_tool_executor` registers both an idempotent executor and its
  non-executing effect lookup. `ExecutionUncertain` carries a serializable,
  exact-identity handle, and `reconcile_uncertain_effect` can complete it only
  from a lookup-confirmed result/effect ID.
- `DurableExecutionStore::begin_effect_attempt` atomically persists the exact
  intent, authorization use, and in-flight marker before executor invocation;
  `load_uncertain_intent` restores that exact state for reconciliation.
- Serializable `PendingAuthorization` handles and begin/resume APIs for
  prepared single-tool and atomic-batch requests. Human-review polling replays
  the retained request, and approval is atomically claimed once before the
  registered executor.
- `DurableExecutionStore::claim_intent_once` opt-in support for a durable
  single-use authorization boundary; unsupported stores fail closed.
- `DurableExecutionStore` makes pre-effect intent and post-effect completion
  persistence mandatory for SDK-governed execution. The completion store
  atomically enqueues the workload-signed receipt, and
  `flush_execution_receipt_outbox` redelivers receipts without re-executing a
  tool.
- `idempotent_tool_executor` supplies capable tools with the retained
  idempotency ID, exact signed payload, authorization ID, and stable executor
  identity.
- `PreparedToolRequest` and `PreparedToolBatch` allocate a stable UUID before
  network access, serialize for durable retention, and restore without
  replacing that identity. Prepared authorization and execution APIs reuse it
  unchanged for exact decision retries.
- `execute_tool_batch` and `authorize_tool_batch` commit a bounded ordered set
  of uniquely identified model tool calls in one side-effect-free decision.
  The registered executor sees the complete signed batch exactly once only
  after whole-batch approval; partial sibling release is not exposed.
- Attributed `SimClient` mutation variants that forward a bounded
  `X-Clavenar-Operator` audit value, plus a configurable positive request
  deadline (twenty seconds by default) on simulator reads and writes.

### Changed

- SDK-governed `execute_tool` now invokes one clone-shared executor registered
  through `ClavenarClientBuilder::tool_executor`. Per-call executor injection
  was removed, and `ExecutionOutcome` returns the actual result, effect ID, and
  terminal receipt metadata without executable authorization bytes.
- Side-effect-free authorization now selects `clavenar.decision/v1`
  independently from `clavenar.execution/v1` receipt evidence. The governed
  path never falls back to unselected server-executed `/mcp`.

### Security

- Once an effect crosses the durable in-flight boundary, executor errors,
  restarts, retries, and concurrent duplicates cannot invoke it again.
  Not-found, unavailable, ambiguous, invalid, or unregistered effect lookups
  remain explicitly uncertain; only receipt outbox delivery may retry.
- Pending handles are bound to the verified workload, stable idempotency and
  correlation IDs, deterministic pending ID, and exact canonical payload
  digest. Polling, denial, expiry, substitution, and repeated claims release
  zero additional effects.
- Missing or unavailable durable intent storage fails closed before an
  executor effect. An effect is never reported successful until its actual
  result/effect ID and signed receipt are durably committed and the outbox
  delivery is confirmed.
- Prepared requests are revalidated before HTTP construction. Invalid restored
  values fail locally with zero network attempts, and no governed network path
  creates or replaces a request identity.
- Deny, review, expiry, cancellation, policy change, invalid structure, and
  call-identity drift release zero batch siblings. Modified batches must retain
  call identity/order and arrive as one complete re-gated signed payload.
- Missing executor configuration fails before authorization. Denied or invalid
  authorization never reaches the executor, and receipt persistence failure
  cannot report successful governed execution.
- Lite rejects decision and legacy execution selectors before upstream access
  until its compatible durable governed-execution path is available.

## [0.2.0]

### Added

- `hil` module: `HilClient` + the HIL wire types (pending queue reads,
  `/decide/{id}` via `HilDecideCredential`, decision-link verify,
  assign/incident patches, notifications, approvals stats,
  `/pending/stream` SSE, identities link/unlink). Hoisted from
  clavenar-console once clavenar-ctl became the second consumer.

### Removed

- Unreachable `LedgerClient` base variants superseded by their
  `_for_tenant` / `_scoped` / `_filtered` forms:
  `audit_agent_paged_before_since`, `audit_agent_paged_after_since`,
  `fleet_behavioral_diff`, `model_upgrade_canary`,
  `compliance_evidence`.

## [0.1.0]

Initial version: typed async clients for the proxy (`ClavenarClient`),
ledger, agents/identity, policies, brain, and simulator surfaces.

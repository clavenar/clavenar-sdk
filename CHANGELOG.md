# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/);
versions track `Cargo.toml`. The crate is a path-dep (not published),
so "released" here means "consumed by clavenar-console / clavenar-ctl
at that version".

## [Unreleased]

### Added

- Attributed `SimClient` mutation variants that forward a bounded
  `X-Clavenar-Operator` audit value, plus a configurable positive request
  deadline (twenty seconds by default) on simulator reads and writes.

### Changed

- SDK-governed `execute_tool` now invokes one clone-shared executor registered
  through `ClavenarClientBuilder::tool_executor`. Per-call executor injection
  was removed, and `ExecutionOutcome` returns the actual result, effect ID, and
  terminal receipt metadata without executable authorization bytes.

### Security

- Missing executor configuration fails before authorization. Denied or invalid
  authorization never reaches the executor, and receipt persistence failure
  cannot report successful governed execution.

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

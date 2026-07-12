# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/);
versions track `Cargo.toml`. The crate is a path-dep (not published),
so "released" here means "consumed by clavenar-console / clavenar-ctl
at that version".

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

<!-- public repo — do not add internal topology, secrets, deploy/runbook, strategy, or absolute host paths -->
# clavenar-sdk — typed async Rust client for the Clavenar proxy + control plane

Wraps the proxy `POST /mcp` surface and the ledger / identity / policy /
simulator HTTP APIs with typed verdicts so an integrator doesn't relearn the
wire contract per service. A legacy Brain explain client remains for loopback
fixtures but is not a production external surface. Consumed by
clavenar-console, clavenar-ctl, and external integrators. Library crate — no
binary.

## Build, test, lint
```bash
cargo build
cargo test                                   # unit tests + tests/ (axum 0.8 mock servers)
cargo clippy --all-targets -- -D warnings
cargo deny check all                         # advisories / licenses / bans / sources
cargo cyclonedx --format json --describe crate
cargo package --locked                       # protected release preflight
```
`cargo package --locked` writes generated output under `target/package/`; use
it only for package/release changes and do not treat that tree as source.
Host-build caveat: `target/` may be root-owned from prior docker builds —
pass `CARGO_TARGET_DIR=/tmp/clavenar-sdk-target` when building on the host.

Run: no binary. Public-API entry is the per-service client constructors,
each taking a base URL (path prefix preserved, trailing slash optional):
- `ClavenarClient::builder(base_url)?.auth(Auth::Bearer(..)).build()?` → `call_tool` / `send_jsonrpc` against `POST /mcp` (proxy / clavenar-lite, e.g. `:8088`).
- `LedgerClient::new(base_url)?` → `audit_correlation` / `audit_agent*` / `verify` / `regulatory_export` (ledger, e.g. `:8083`).
- `AgentsClient::new(base_url)?.with_bearer(tok)` → `/agents` lifecycle CRUD (identity, e.g. `:8086`).
- `PoliciesClient`, `SimClient` → policy-engine and simulator admin. `BrainClient`
  retains a typed `POST /explain-pattern` compatibility client for loopback
  fixtures only; production Brain accepts the exact policy-engine workload
  identity, not a generic SDK caller or bearer token.
- `verify_pack(..)` (`pack` module) → Ed25519 signed-policy-pack verification.

## Layout
- `src/lib.rs` — crate root; module decls + the full public re-export surface. Edition 2024.
- `src/client.rs` — `ClavenarClient`, `ClavenarClientBuilder`, `Auth`. `send_raw` is the proxy client's status-dispatch site (200→JSON, 403→`Veto`, 401→`Unauthorized`, 400→`BadRequest`, else `Server`). 403→`Veto` is proxy-specific — the other clients map 403 to `Server` (agents/policies/brain/sim via `http.rs::decode_response`, ledger via its own `get_json`/`post_json`).
- `src/ledger.rs` — `LedgerClient` + the large set of typed row/report mirrors (audit, lifecycle, exports, regulatory bundle, hunt/canary/baseline analytics), plus a write path `log` (`POST /log` — append a forensic row; the server computes the chain) and durable tenant lifecycle final-export/tombstone effects. The audit/verify surface is no longer strictly read-only.
- `src/agents.rs` — `AgentsClient`: identity enrollment + state-machine transitions, certification, grant/envelope types, and durable tenant lifecycle start/status/claim/complete/retry receipts.
- `src/policies.rs` — `PoliciesClient`: list/get/create/update/activate/deactivate/delete/rollback/diff + Lab/Miner batch surfaces, typed conflict/error parsers, and the durable tenant lifecycle owner effect.
- `src/brain.rs` — `BrainClient`: aggregated-metrics `explain-pattern` local/test
  compatibility client; not a production external integration surface.
- `src/sim.rs` — `SimClient`: simulator dev admin (`/status`, `/multiplier`, `/running`, `/auto-decide`, `/agents`).
- `src/hil.rs` — `HilClient`: pending queue reads (plain + demo-session-scoped), `/decide/{id}` (via `HilDecideCredential`: session cookie / Console bearer plus typed session claim / demo-session cookie), decision-link verify, assign/incident patches, notifications, approvals stats, `/pending/stream` SSE (raw `reqwest::Response`), identities link/unlink, and the tenant-scoped lifecycle owner effect. Non-2xx → `Server{status,body}` so consumers keep per-status mappings (console relies on this).
- `src/execution.rs` — exact SDK-governed authorization, durable
  intent/effect/completion state, signed receipts, outbox delivery, and
  uncertain-effect recovery.
- `contracts/` — public execution and client-migration contract mirrors
  from `clavenar-specs`; keep implementing code and these files in lockstep.
- `src/secure_transport.rs` — atomic reload of a complete mTLS/token/deadline/
  proxy client snapshot; implements `HttpProvider`.
- `src/pack.rs` — Policy-Exchange signed-pack manifest + Ed25519 verify (`verify_pack`, JWKS / SPKI-PEM key loaders).
- `src/http.rs` — `HttpProvider`, `StaticHttpClient`, crate-internal
  `default_provider`/`parse_base_url`/`decode_response`. Public injection is
  `install_process_http_provider` (once, process-wide) plus each client's
  `with_http_provider` for timeouts / TLS roots / hot-reloaded creds.
- `src/error.rs` — `ClavenarError`. `tests/` — integration tests against axum mock servers. `docs/SEQUENCES.md` — five primary client-path diagrams. `docs/ENDPOINTS.md` — per-client method → HTTP route → return-type table (the route reference).

## Conventions & invariants

- **Formatting is an owning-CI gate.** Run `cargo fmt --all -- --check`
  before pushing Rust changes; CI runs it before check, test, and clippy.

- **`rustls-tls`, not native-tls** (reqwest `default-features = false`), so a downstream `cargo install` on a fresh box needs no system OpenSSL. Same combo as clavenar-lite — keep it.
- **Base-URL prefix is preserved** across every client: `http://gw/clavenar` lands `/clavenar/mcp`, `/clavenar/audit/...`, etc. Trailing slash optional; `parse_base_url` normalizes. Don't strip or re-root the path.
- **Proxy 403 is `Veto`; other clients keep 403 as `Server`.** `ClavenarClient`
  maps structured or non-JSON 403 to `ClavenarError::Veto` (non-JSON → structured
  fields empty, body on `raw`) and never `Decode`. Agents/policies/brain/sim
  (`http.rs::decode_response`) and ledger (`get_json`/`post_json`) map 403 to
  `Server{status,body}` so consumers keep per-status mappings.
- **`ClavenarError` and `Auth` are `#[non_exhaustive]`** — new variants (mTLS / OIDC / SPIFFE auth) are non-breaking; consumer match arms need `_ => ...`.
- **`correlation_id` is `#[serde(default)]`** on `LedgerEntry` — pre-correlation-id rows deserialize cleanly to `None`. Don't make it required.
- **Clients are cheap to clone** (inner `Arc<dyn HttpProvider>`). Add new shared state behind the `Arc`, not by value.
- **Decision selection never grants effect retries.** SDK-governed execution
  persists exact intent and single-use authorization before the effect, records
  completion and signed receipt durably, and surfaces uncertain state instead
  of automatically re-executing.
- **Public client changes require consumer checks.** Validate affected call
  sites in `clavenar-console` and `clavenar-ctl` as well as this crate before
  changing a constructor, error mapping, or shared wire type.
- **`SimClient` requires an authenticated transport outside local fixtures.** Inject an
  mTLS-capable [`HttpProvider`] whose workload identity is authorized by the simulator;
  network placement alone is not authorization and the control listener must never be
  public.
- **`pack.rs` reuses the regulatory-export manifest signature primitive** (Ed25519 via `ed25519-dalek`) — not new crypto. Keep verification aligned with the manifest path.

Rust house rules:
- clippy `-D warnings` is the floor; never `#[allow]` to silence a lint unless it's a documented false positive (note the reason in the attribute).
- `cargo deny check all` gates CI (advisories / licenses / bans / sources). `deny.toml` is synced verbatim from `clavenar-specs` — edit it there first, then mirror the exact bytes.
- `[lints.rust] unreachable_pub = "warn"` — keep module-internal items non-`pub`; only the lib.rs re-export surface is public.
- A type in a `pub` fn signature must itself be `pub` (clippy `private_interfaces`).
- Tests live at the bottom of the file in `#[cfg(test)] mod tests` (`items_after_test_module`).
- `writeln!` over `write!(.., "\n")`; let-chains over nested `if let`. Doc comments: prose continuations, no leading `+ ` (clippy `doc_lazy_continuation`).
- One logical area per commit; use imperative mood.
- Commit subjects must start with a lowercase letter.

## Pointers

[README](README.md) · [security policy](SECURITY.md) ·
[sequence diagrams](docs/SEQUENCES.md) · [endpoint reference](docs/ENDPOINTS.md).

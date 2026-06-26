<!-- public repo — do not add internal topology, secrets, deploy/runbook, strategy, or absolute host paths -->
# clavenar-sdk — typed async Rust client for the Clavenar proxy + control plane

Wraps the proxy `POST /mcp` surface and the ledger / identity / policy /
brain / simulator HTTP APIs with typed verdicts so an integrator doesn't
relearn the wire contract per service. Consumed by clavenar-console,
clavenar-ctl, and external integrators. Library crate — no binary.

## Build, test, lint
```bash
cargo build
cargo test                                   # unit tests + tests/ (axum 0.8 mock servers)
cargo clippy --all-targets -- -D warnings
cargo deny check all                         # advisories / licenses / bans / sources
```
Run: no binary. Public-API entry is the per-service client constructors,
each taking a base URL (path prefix preserved, trailing slash optional):
- `ClavenarClient::builder(base_url)?.auth(Auth::Bearer(..)).build()?` → `call_tool` / `send_jsonrpc` against `POST /mcp` (proxy / clavenar-lite, e.g. `:8088`).
- `LedgerClient::new(base_url)?` → `audit_correlation` / `audit_agent*` / `verify` / `regulatory_export` (ledger, e.g. `:8083`).
- `AgentsClient::new(base_url)?.with_bearer(tok)` → `/agents` lifecycle CRUD (identity, e.g. `:8086`).
- `PoliciesClient`, `BrainClient`, `SimClient` → policy-engine, brain `POST /explain-pattern`, simulator admin.
- `verify_pack(..)` (`pack` module) → Ed25519 signed-policy-pack verification.

## Layout
- `src/lib.rs` — crate root; module decls + the full public re-export surface. Edition 2024.
- `src/client.rs` — `ClavenarClient`, `ClavenarClientBuilder`, `Auth`. `send_raw` is the single status-dispatch site (200→JSON, 403→`Veto`, 401→`Unauthorized`, 400→`BadRequest`, else `Server`).
- `src/ledger.rs` — `LedgerClient` + the large set of typed row/report mirrors (audit, lifecycle, exports, regulatory bundle, hunt/canary/baseline analytics).
- `src/agents.rs` — `AgentsClient`: identity enrollment + state-machine transitions, certification, grant/envelope types.
- `src/policies.rs` — `PoliciesClient`: list/get/create/update/activate/deactivate/delete/rollback/diff + Lab/Miner batch surfaces, typed conflict/error parsers.
- `src/brain.rs` — `BrainClient`: aggregated-metrics `explain-pattern` only.
- `src/sim.rs` — `SimClient`: simulator dev admin (`/status`, `/multiplier`, `/running`, `/auto-decide`, `/agents`).
- `src/pack.rs` — Policy-Exchange signed-pack manifest + Ed25519 verify (`verify_pack`, JWKS / SPKI-PEM key loaders).
- `src/http.rs` — `HttpProvider` trait, `StaticHttpClient`, `default_provider`, `parse_base_url`. Injection point for custom timeouts / TLS roots / hot-reloaded creds.
- `src/error.rs` — `ClavenarError`. `tests/` — integration tests against axum mock servers. `docs/SEQUENCES.md` — five primary client-path diagrams.

## Conventions & invariants
- **`rustls-tls`, not native-tls** (reqwest `default-features = false`), so a downstream `cargo install` on a fresh box needs no system OpenSSL. Same combo as clavenar-lite — keep it.
- **Base-URL prefix is preserved** across every client: `http://gw/clavenar` lands `/clavenar/mcp`, `/clavenar/audit/...`, etc. Trailing slash optional; `parse_base_url` normalizes. Don't strip or re-root the path.
- **One 403 envelope, one error variant.** A structured or non-JSON 403 both surface as `ClavenarError::Veto` (non-JSON → structured fields empty, body on `raw`). Never return `Decode` for a 403 — callers must not special-case the server edition.
- **`ClavenarError` and `Auth` are `#[non_exhaustive]`** — new variants (mTLS / OIDC / SPIFFE auth) are non-breaking; consumer match arms need `_ => ...`.
- **`correlation_id` is `#[serde(default)]`** on `LedgerEntry` — pre-correlation-id rows deserialize cleanly to `None`. Don't make it required.
- **Clients are cheap to clone** (inner `Arc<dyn HttpProvider>`). Add new shared state behind the `Arc`, not by value.
- **`SimClient` is dev-only, unauthenticated** — its admin port is meant to live on an internal compose network, never public. Don't add prod auth assumptions to it.
- **`pack.rs` reuses the regulatory-export manifest signature primitive** (Ed25519 via `ed25519-dalek`) — not new crypto. Keep verification aligned with the manifest path.

Rust standards that bind here:
- clippy `-D warnings` is the floor; never `#[allow]` to silence a lint unless it's a documented false positive (note the reason in the attribute).
- `cargo deny check all` gates CI (advisories / licenses / bans / sources). `deny.toml` is synced verbatim across the Rust repos from the public clavenar-specs source — mirror, don't fork.
- `[lints.rust] unreachable_pub = "warn"` — keep module-internal items non-`pub`; only the lib.rs re-export surface is public.
- A type in a `pub` fn signature must itself be `pub` (clippy `private_interfaces`).
- Tests live at the bottom of the file in `#[cfg(test)] mod tests` (`items_after_test_module`).
- `writeln!` over `write!(.., "\n")`; let-chains over nested `if let`. Doc comments: prose continuations, no leading `+ ` (clippy `doc_lazy_continuation`).
- One logical area per commit; commit subjects start lowercase, imperative mood.

## Pointers
README.md · SECURITY.md · docs/SEQUENCES.md

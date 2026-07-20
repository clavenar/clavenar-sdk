# clavenar-sdk

Async Rust client for [Clavenar](https://github.com/clavenar).
Wraps the proxy `POST /mcp` surface and the ledger audit/verify
endpoints with typed verdicts so an external app doesn't have to
relearn the wire contract on every integration.

```bash
cargo add clavenar-sdk
```

Pairs with [`clavenar-lite`](https://github.com/clavenar/clavenar-lite)
for the dev-onboarding story (lite is the OSS proxy you put in front
of an agent, this SDK is what your app calls), and with the
full Clavenar control plane for production.

Sequence diagrams for the five primary client paths — `ClavenarClient::call_tool`
with veto parse, `LedgerClient` audit + verify, `AgentsClient`
lifecycle, `PoliciesClient` update with optimistic concurrency, and
Lab + Miner with typed-error lift — live in
[`docs/SEQUENCES.md`](docs/SEQUENCES.md).

## What's in the box

| Type                    | Wraps                                      | Returns                                                                  |
|-------------------------|--------------------------------------------|--------------------------------------------------------------------------|
| `ClavenarClient`          | `POST /mcp` on clavenar-lite or clavenar-proxy | upstream JSON on 200, `ClavenarError::Veto` on 403                         |
| `LedgerClient`          | clavenar-ledger HTTP API                     | typed `LedgerEntry`, `LifecycleRow`, `VerifyResult`, `ExportRecord`, regulatory bundle bytes |
| `AgentsClient`          | clavenar-identity `/agents` lifecycle surface | typed `AgentRecord`, `AgentCreated`, `LifecycleResponse`; full CRUD + state-machine transitions |
| `PoliciesClient`        | clavenar-policy-engine console-policy mgmt   | typed `PolicyRow` / `PolicyVersionRow` / `PolicyDetail` / `MutationResponse` |
| `BrainClient`           | loopback compatibility for clavenar-brain `POST /explain-pattern` | typed `ExplainPatternResponse` (`one_liner`, `rationale`); production calls belong to policy-engine's exact mTLS identity |
| `SimClient`             | clavenar-simulator authenticated control API | typed `SimStatus`, `SimAgentRecord`, `SimStats`                           |
| `ClavenarError::Veto`     | structured 403 envelope (or non-JSON fallback) | `intent_category`, `reasons`, `review_reasons`, `correlation_id`, `raw` (`layer` etc. via `raw`) |
| `Auth`                  | `ClavenarClient` construction                | `None` (open access) or `Bearer(String)`. mTLS / OIDC / SPIFFE: see roadmap |

A path prefix on the base URL is preserved across every client — pass
`http://gateway/clavenar` and requests land at `http://gateway/clavenar/mcp`
etc. Trailing slash optional; the SDK normalizes either form.

`BrainClient` is retained for local/test compatibility, not as an external
production API. In TLS deployments, Brain serves `/explain-pattern` on its
mTLS application port and accepts only
`spiffe://clavenar.local/service/policy-engine`; bearer auth does not satisfy
that boundary. The policy-engine uses its own workload-identity-aware internal
client. This SDK does not mint or impersonate that service identity.

## Quick start

```rust
use serde_json::json;
use clavenar_sdk::{Auth, ClavenarClient, ClavenarError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ClavenarClient::builder("http://localhost:8088")?
        .auth(Auth::Bearer("dev-token".into()))
        .build()?;

    match client.call_tool("search", json!({"q": "rust async"})).await {
        Ok(reply) => println!("upstream said: {reply}"),
        Err(ClavenarError::Veto { intent_category, reasons, .. }) => {
            eprintln!("blocked ({intent_category}): {reasons:?}");
        }
        Err(ClavenarError::Unauthorized(body)) => {
            eprintln!("auth failed: {body}");
        }
        Err(other) => return Err(other.into()),
    }
    Ok(())
}
```

## Exact SDK-governed execution

`execute_tool` selects `clavenar.execution/v1`: Proxy runs its complete
security/HIL pipeline and signs the exact canonical payload, but performs no
upstream effect. The SDK passes that signed payload to your executor, signs a
terminal receipt, and waits for the receipt's synchronous Ledger commit.

Build the injected `reqwest::Client` with the current workload SVID, and pass
the matching P-256 private key through `execution_signing_key`. Proxy verifies
the receipt signature against the TLS leaf used on that same request.

```rust,no_run
use clavenar_sdk::{ClavenarClient, ExecutionEffect};
use serde_json::json;
use uuid::Uuid;

# async fn run(mtls_client: reqwest::Client, svid_key: p256::ecdsa::SigningKey)
# -> Result<(), clavenar_sdk::ClavenarError> {
let client = ClavenarClient::builder("https://proxy:8443")?
    .http_client(mtls_client)
    .execution_signing_key(svid_key)
    .build()?;
let outcome = client.execute_tool(
    Uuid::new_v4(),
    "payments.transfer",
    json!({"amount": 100}),
    |signed_jsonrpc| async move {
        // Invoke the tool using exactly signed_jsonrpc; this is the sole
        // side-effecting step in the v1 SDK-governed path.
        let _ = signed_jsonrpc;
        Ok(ExecutionEffect {
            result: json!({"ok": true}),
            effect_id: "provider-operation-123".into(),
        })
    },
).await?;
assert_eq!(outcome.receipt.stage, "execution.completed");
# Ok(()) }
```

An exact retry may reuse its UUID; changed bytes under the same UUID are a
conflict. Automatic retries after an uncertain external effect, batching,
intent capture, other language SDKs, and migration of the legacy
Proxy-executed default remain WP-06 scope.

## Audit reconstruction

The full edition writes two ledger rows per successful request (proxy
+ policy) and stitches them with a UUIDv4 `correlation_id`. The SDK
exposes the same join:

```rust
use clavenar_sdk::LedgerClient;

let ledger = LedgerClient::new("http://localhost:8083")?;
let rows = ledger
    .audit_correlation("3f4b8c2a-9e1d-47fa-8a6c-c0a8d8888c8c")
    .await?;
for row in &rows {
    println!(
        "[{}] seq={} method={} intent={} authorized={}",
        row.timestamp, row.seq, row.method, row.intent_category, row.authorized
    );
}

let v = ledger.verify().await?;
assert!(v.valid, "chain corrupted at seq {:?}", v.first_invalid_seq);
```

`LedgerClient` covers the full audit surface — beyond the
`audit_correlation` / `verify` shown above:

- `audit_agent` / `audit_agent_paged` / `audit_agent_count` — per-CN
  rows, ASC-full or newest-first paged.
- `lifecycle_for_agent(tenant, agent_id)` — chain-v3 lifecycle rows
  for a registered agent, joined with the per-event payload bytes.
- `list_agents` — distinct CNs that have ever logged a verdict.
- `list_exports` — cold-tier Parquet snapshot bookkeeping.
- `regulatory_export(from, to, opts)` — produce a regulatory `.tar.gz`
  bundle for a half-open time window with optional operator markdown
  and Parquet pointers.

## Agents, policies, simulator

The same crate ships typed clients for the rest of the clavenar control
plane so an integrator doesn't have to roll a fresh client per service:

```rust
use clavenar_sdk::{AgentsClient, AgentListFilter, AgentState, CreateAgentRequest};

let agents = AgentsClient::new("http://identity:8086")?
    .with_bearer(oidc_id_token);
let rows = agents
    .list("acme", AgentListFilter { state: Some(AgentState::Active), owner_team: None })
    .await?;

let created = agents.create(&CreateAgentRequest {
    tenant: "acme",
    agent_name: "support-bot-3",
    owner_team: "payments",
    scope_envelope: vec!["mcp:read:tickets".into()],
    yellow_envelope: vec![],
    attestation_kinds: vec!["dev-mock".into()],
    description: Some("triage queue"),
    actor_sub: None,
}).await?;

agents.suspend(&created.record.id, "acme", Some("incident #4172")).await?;
```

`AgentsClient` also carries the per-tenant operator surface:
`get_budget` / `set_budget` read and set a tenant's monthly micro-USD
spend ceiling (`TenantBudget`), and `offboard_tenant(tenant, confirm,
reason)` decommissions every agent in a tenant (`confirm` must equal the
tenant name). The matching audit-row erase is a separate
`LedgerClient::tombstone_tenant(tenant, reason)` call the console makes
after the identity offboard — ledger reads need no change, tombstone
filtering is server-side and transparent. `LedgerClient::finops_spend`
takes a `tenant` argument to scope the spend rollup to one operator
tenant (`None` keeps the deployment-wide rollup).

`PoliciesClient` wraps `clavenar-policy-engine`'s
console-policy-management surface (list / get / create / update /
activate / deactivate / delete / rollback / diff). 409s on mutations
carry a typed `ConflictResponse` — recover the up-to-date row via
`PoliciesClient::parse_conflict(&body)`.

`SimClient` wraps the simulator's control surface (`/status`,
`/multiplier`, `/running`, `/auto-decide`, `/agents`). Outside local
fixtures, inject an mTLS-capable `HttpProvider` whose workload identity
the simulator authorizes. Network placement is not authorization and the
control listener must never be public. Mutating callers should use the
`*_as(operator, ...)` variants so the simulator can attribute accepted
controls; the operator header is audit context, never authorization. All
simulator calls have a twenty-second deadline by default, configurable with
`with_request_timeout`.

## Error model

`ClavenarError` distinguishes the four wire outcomes a caller actually
has to branch on, plus transport / decode / config arms:

```rust
pub enum ClavenarError {
    Veto { intent_category: String, reasons: Vec<String>,
           review_reasons: Vec<String>, raw: String },
    Unauthorized(String),
    BadRequest(String),
    Server { status: reqwest::StatusCode, body: String },
    Transport(reqwest::Error),
    Decode(serde_json::Error),
    InvalidConfig(String),
}
```

`#[non_exhaustive]` reserves the right to add variants in a future
minor — match arms must include `_ => ...`.

### One 403 envelope, one error variant

Both **clavenar-lite** and full-edition **clavenar-proxy** emit the same
structured JSON 403 envelope (`verdict`, `layer`, `error`, `reasons`,
`review_reasons`, `intent_category`, `correlation_id`). The SDK projects
the commonly-needed fields onto the `Veto` arm — including
`correlation_id` (the join key for the audit row); the full envelope
(e.g. `layer`, the deny stage) is always available verbatim on `raw`.

An older server that returns a non-JSON 403 still surfaces as `Veto`,
but the structured fields are empty/`None` and only `raw` carries the
body. Either way you don't special-case the server edition: branch on
`ClavenarError::Veto`, read `correlation_id` / `reasons` if you need
them, and always log `raw`.

## Wire shapes the SDK mirrors

| SDK type               | Server-side source                                   |
|------------------------|------------------------------------------------------|
| `LedgerEntry`          | `clavenar_ledger::LedgerEntry`                         |
| `LifecycleRow`         | `clavenar_ledger::LifecycleRow` (chain v3 + payload)   |
| `VerifyResult`         | `clavenar_ledger::VerifyResult`                        |
| `ExportRecord`         | `clavenar_ledger::export::ExportRecord`                |
| `AgentRecord`          | `clavenar_identity::agents::AgentRecord`               |
| `AgentCreated`         | `clavenar_identity::agents::CreateAgentResponse`       |
| `PolicyRow` / `PolicyVersionRow`             | `clavenar_policy_engine::storage::*`         |
| `PolicyDetail`                               | `clavenar_policy_engine::read_api::PolicyDetailResponse` |
| `MutationResponse`                           | `clavenar_policy_engine::write_api::MutationResponse`    |
| `SimStatus` / `SimStats` / `SimAgentRecord`  | `clavenar_simulator::admin::{StatusResponse, StatsView, AgentRecord}` |
| `ClavenarError::Veto`    | `clavenar_lite::proxy::DenyResponse` (JSON 403)        |
| Request body shape     | JSON-RPC 2.0; `tools/call` with `params.{name,arguments}` |

The `correlation_id` field on `LedgerEntry` is `#[serde(default)]`,
matching the server: rows produced by older publishers (pre-correlation-id)
deserialize cleanly with `correlation_id = None`.

## Custom HTTP client

For non-default timeouts, custom TLS roots, or HTTP proxies, inject
your own `reqwest::Client`:

```rust
let http = reqwest::Client::builder()
    .timeout(std::time::Duration::from_secs(2))
    .build()?;
let client = ClavenarClient::builder("http://localhost:8088")?
    .http_client(http)
    .build()?;
```

## Roadmap

- `Auth::Mtls { cert, key }` — first-class identity for the full edition's
  mTLS proxy. Open question: shipping a default rustls config vs. handing
  callers a `reqwest::ClientBuilder` and letting them attach an `Identity`.
- `Auth::Oidc(TokenSource)` and `Auth::Spiffe(WorkloadApi)` — paired with
  short-lived bearer tokens and SPIFFE workload identities respectively.
  Per the GTM plan these are the "Clavenar-Ready" identity story.
- TS / Python bindings — out of scope for the Rust crate. Likely
  separate `@clavenar/sdk` and `clavenar-sdk` (PyPI) packages built on top
  of the same wire contract once it's stable. These are distinct from the
  existing agent-wrapper SDK `@clavenar/agent-sdk` (repo
  `clavenar-typescript-sdk`), which guards an Anthropic/OpenAI client
  rather than calling this control-plane surface.

## License

Apache-2.0. See `LICENSE`.

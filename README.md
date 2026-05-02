# warden-sdk

Async Rust client for [Agent Warden](https://github.com/vanteguardlabs).
Wraps the proxy `POST /mcp` surface and the ledger audit/verify
endpoints with typed verdicts so an external app doesn't have to
relearn the wire contract on every integration.

```bash
cargo add warden-sdk
```

Pairs with [`warden-lite`](https://github.com/vanteguardlabs/warden-lite)
for the dev-onboarding story (lite is the OSS proxy you put in front
of an agent, this SDK is what your app calls), and with the
full Agent Warden control plane for production.

## What's in the box

| Type                    | Wraps                                      | Returns                                                                  |
|-------------------------|--------------------------------------------|--------------------------------------------------------------------------|
| `WardenClient`          | `POST /mcp` on warden-lite or warden-proxy | upstream JSON on 200, `WardenError::Veto` on 403                         |
| `LedgerClient`          | ledger HTTP API                            | `Vec<LedgerEntry>` from `/audit/...`, `VerifyResult` from `/verify`      |
| `WardenError::Veto`     | structured 403 body (or plain-text fallback) | `intent_category`, `reasons`, `review_reasons`, `raw`                    |
| `Auth`                  | client construction                        | `None` (open access) or `Bearer(String)`. mTLS / OIDC / SPIFFE: see roadmap |

## Quick start

```rust
use serde_json::json;
use warden_sdk::{Auth, WardenClient, WardenError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WardenClient::builder("http://localhost:8088")?
        .auth(Auth::Bearer("dev-token".into()))
        .build()?;

    match client.call_tool("search", json!({"q": "rust async"})).await {
        Ok(reply) => println!("upstream said: {reply}"),
        Err(WardenError::Veto { intent_category, reasons, .. }) => {
            eprintln!("blocked ({intent_category}): {reasons:?}");
        }
        Err(WardenError::Unauthorized(body)) => {
            eprintln!("auth failed: {body}");
        }
        Err(other) => return Err(other.into()),
    }
    Ok(())
}
```

## Audit reconstruction

The full edition writes two ledger rows per successful request (proxy
+ policy) and stitches them with a UUIDv4 `correlation_id`. The SDK
exposes the same join:

```rust
use warden_sdk::LedgerClient;

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

## Error model

`WardenError` distinguishes the four wire outcomes a caller actually
has to branch on, plus transport / decode / config arms:

```rust
pub enum WardenError {
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

### Two 403 shapes, one error variant

- **warden-lite** emits a structured JSON 403 (`error`, `reasons`,
  `review_reasons`, `intent_category`). The SDK parses it into the
  `Veto` arm's named fields.
- **full-edition warden-proxy** today emits a plain-text 403
  (`Security Violation: <reason>`). The SDK still surfaces this as
  `Veto`, but the structured fields are empty defaults — only `raw`
  carries the body.

Either way you don't special-case the proxy edition: branch on
`WardenError::Veto`, read `intent_category` if you need it (skip
otherwise), and always log `raw`.

## Wire shapes the SDK mirrors

| SDK type               | Server-side source                                   |
|------------------------|------------------------------------------------------|
| `LedgerEntry`          | `warden_ledger::LedgerEntry`                         |
| `VerifyResult`         | `warden_ledger::VerifyResult`                        |
| `WardenError::Veto`    | `warden_lite::proxy::DenyResponse` (JSON 403)        |
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
let client = WardenClient::builder("http://localhost:8088")?
    .http_client(http)
    .build()?;
```

## Roadmap

- `Auth::Mtls { cert, key }` — first-class identity for the full edition's
  mTLS proxy. Open question: shipping a default rustls config vs. handing
  callers a `reqwest::ClientBuilder` and letting them attach an `Identity`.
- `Auth::Oidc(TokenSource)` and `Auth::Spiffe(WorkloadApi)` — paired with
  short-lived bearer tokens and SPIFFE workload identities respectively.
  Per the GTM plan these are the "Warden-Ready" identity story.
- TS / Python bindings — out of scope for the Rust crate. Likely
  separate `@warden/sdk` and `warden-sdk` (PyPI) packages built on top
  of the same wire contract once it's stable.

## License

Apache-2.0. See `LICENSE`.

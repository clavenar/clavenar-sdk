//! Async client for the proxy `POST /mcp` surface.
//!
//! Two ergonomic call sites:
//!
//! * [`ClavenarClient::call_tool`] — the common case. Builds a
//!   JSON-RPC `tools/call` body around `name` + `arguments` and posts
//!   it. Returns the upstream JSON on 200, a [`ClavenarError::Veto`] on
//!   403, or one of the other [`ClavenarError`] arms.
//! * [`ClavenarClient::send_jsonrpc`] — escape hatch for non-tool
//!   methods (`tools/list`, etc.). Same return semantics.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::ClavenarError;
use crate::http::{default_provider, parse_base_url, HttpProvider, StaticHttpClient};

/// Authentication mode for the proxy.
///
/// `None` is the clavenar-lite "open access" default. `Bearer` is the
/// token shape both clavenar-lite and the full edition's proxy use for
/// HTTP-only deployments. mTLS / OIDC / SPIFFE will land as new
/// variants in a future minor — `#[non_exhaustive]` reserves the
/// right to add them without it being a breaking change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Auth {
    /// Send no auth headers. Matches a clavenar-lite started without
    /// `--token` / `CLAVENAR_LITE_TOKEN`.
    None,
    /// Send `Authorization: Bearer <token>`.
    Bearer(String),
}

/// Async client for the proxy `POST /mcp` surface.
///
/// Cheap to clone — the inner `Arc<dyn HttpProvider>` is `Arc`-based.
#[derive(Debug, Clone)]
pub struct ClavenarClient {
    base_url: Url,
    auth: Auth,
    http: Arc<dyn HttpProvider>,
    next_id: Arc<AtomicU64>,
}

/// Two-step builder: validate the URL once, then attach optional
/// settings, then build. Surfaces caller misuse (a typo in the base
/// URL, an unsupported auth combo) before any network call.
#[derive(Debug)]
pub struct ClavenarClientBuilder {
    base_url: Url,
    auth: Auth,
    http: Option<Arc<dyn HttpProvider>>,
}

impl ClavenarClient {
    /// Start building a client. Returns `Err(InvalidConfig)` if
    /// `base_url` doesn't parse as a URL.
    ///
    /// `base_url` should be the proxy's origin — the SDK appends
    /// `/mcp` itself.
    pub fn builder(base_url: impl AsRef<str>) -> Result<ClavenarClientBuilder, ClavenarError> {
        let url = parse_base_url(base_url.as_ref())?;
        Ok(ClavenarClientBuilder {
            base_url: url,
            auth: Auth::None,
            http: None,
        })
    }

    /// `POST /mcp` with a JSON-RPC `tools/call` body.
    ///
    /// Wire shape:
    /// ```json
    /// { "jsonrpc": "2.0", "id": <auto>, "method": "tools/call",
    ///   "params": { "name": "<name>", "arguments": <arguments> } }
    /// ```
    /// Returns the upstream JSON on 200, [`ClavenarError::Veto`] on a
    /// structured 403, [`ClavenarError::Unauthorized`] on 401,
    /// [`ClavenarError::BadRequest`] on 400, or one of the other
    /// [`ClavenarError`] arms.
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<Value, ClavenarError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        });
        self.send_raw(body).await
    }

    /// `POST /mcp` with an arbitrary JSON-RPC body. Use this for
    /// methods other than `tools/call` (`tools/list`, custom RPCs,
    /// etc.).
    pub async fn send_jsonrpc(
        &self,
        method: &str,
        params: Value,
    ) -> Result<Value, ClavenarError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        self.send_raw(body).await
    }

    /// Internal: post `body` to `<base_url>/mcp` and dispatch on
    /// status. Public methods build `body` and delegate here so the
    /// status-handling logic lives in one place.
    async fn send_raw(&self, body: Value) -> Result<Value, ClavenarError> {
        let endpoint = self
            .base_url
            .join("mcp")
            .map_err(|e| ClavenarError::InvalidConfig(format!("join /mcp: {e}")))?;

        let mut req = self.http.client().post(endpoint).json(&body);
        if let Auth::Bearer(token) = &self.auth {
            req = req.bearer_auth(token);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let raw = resp.text().await?;

        match status {
            StatusCode::OK => decode_json_body(&raw),
            StatusCode::FORBIDDEN => Err(parse_veto(&raw)),
            StatusCode::UNAUTHORIZED => Err(ClavenarError::Unauthorized(raw)),
            StatusCode::BAD_REQUEST => Err(ClavenarError::BadRequest(raw)),
            other => Err(ClavenarError::Server { status: other, body: raw }),
        }
    }
}

impl ClavenarClientBuilder {
    /// Attach an [`Auth`] mode. Defaults to [`Auth::None`].
    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = auth;
        self
    }

    /// Inject a pre-configured `reqwest::Client`. Useful when callers
    /// want to set custom timeouts, proxies, or TLS roots; otherwise a
    /// default client is constructed at build time.
    pub fn http_client(mut self, client: Client) -> Self {
        self.http = Some(Arc::new(StaticHttpClient::new(client)));
        self
    }

    /// Inject a custom [`HttpProvider`] for hot-reloading credentials.
    /// See [`crate::LedgerClient::with_http_provider`] for the
    /// trade-offs against `http_client`.
    pub fn http_provider(mut self, provider: Arc<dyn HttpProvider>) -> Self {
        self.http = Some(provider);
        self
    }

    /// Construct the client. Builds a default `reqwest::Client` if
    /// neither `http_client(...)` nor `http_provider(...)` was called.
    pub fn build(self) -> Result<ClavenarClient, ClavenarError> {
        let http = match self.http {
            Some(p) => p,
            None => default_provider()?,
        };
        Ok(ClavenarClient {
            base_url: self.base_url,
            auth: self.auth,
            http,
            next_id: Arc::new(AtomicU64::new(1)),
        })
    }
}

/// Mirror of the shared 403 envelope emitted by both `clavenar-lite`
/// and full-edition `clavenar-proxy`. Used only inside `parse_veto`; we
/// project into [`ClavenarError::Veto`] before handing the value back.
#[derive(Debug, Deserialize)]
struct DenyResponse {
    #[serde(default)]
    reasons: Vec<String>,
    #[serde(default)]
    review_reasons: Vec<String>,
    #[serde(default)]
    intent_category: String,
    #[serde(default)]
    correlation_id: Option<String>,
}

/// Parse a 403 body into a `ClavenarError::Veto`. Both editions now emit
/// the JSON envelope, so the structured fields populate; an older server
/// that returns plain text falls back to `raw` only. Either way we
/// return `ClavenarError::Veto`, never `Decode` — callers shouldn't have
/// to special-case the server edition.
fn parse_veto(raw: &str) -> ClavenarError {
    match serde_json::from_str::<DenyResponse>(raw) {
        Ok(d) => ClavenarError::Veto {
            intent_category: d.intent_category,
            reasons: d.reasons,
            review_reasons: d.review_reasons,
            correlation_id: d.correlation_id,
            raw: raw.to_owned(),
        },
        Err(_) => ClavenarError::Veto {
            intent_category: String::new(),
            reasons: Vec::new(),
            review_reasons: Vec::new(),
            correlation_id: None,
            raw: raw.to_owned(),
        },
    }
}

/// Decode a 200 body. Surfaces a `Decode` error if the body isn't
/// JSON — not expected from a real proxy, but keeps us from panicking
/// on a misconfigured upstream.
fn decode_json_body(raw: &str) -> Result<Value, ClavenarError> {
    serde_json::from_str(raw).map_err(ClavenarError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_veto_with_structured_body() {
        let body = r#"{
            "verdict": "denied",
            "layer": "policy",
            "error": "security_violation",
            "reasons": ["Direct execution of SQL queries is prohibited."],
            "review_reasons": [],
            "intent_category": "DangerousTool",
            "correlation_id": "a1b2c3d4-0000-4000-8000-000000000001"
        }"#;
        match parse_veto(body) {
            ClavenarError::Veto {
                intent_category,
                reasons,
                review_reasons,
                correlation_id,
                raw,
            } => {
                assert_eq!(intent_category, "DangerousTool");
                assert_eq!(reasons.len(), 1);
                assert!(review_reasons.is_empty());
                assert_eq!(
                    correlation_id.as_deref(),
                    Some("a1b2c3d4-0000-4000-8000-000000000001")
                );
                assert_eq!(raw, body);
            }
            other => panic!("expected Veto, got {other:?}"),
        }
    }

    #[test]
    fn parse_veto_with_plain_text_body() {
        // Mirrors what an older / non-JSON server returns.
        let body = "Security Violation: shell_exec is denied for this agent";
        match parse_veto(body) {
            ClavenarError::Veto {
                intent_category,
                reasons,
                review_reasons,
                correlation_id,
                raw,
            } => {
                // Structured fields stay empty; raw carries the full body.
                assert!(intent_category.is_empty());
                assert!(reasons.is_empty());
                assert!(review_reasons.is_empty());
                assert!(correlation_id.is_none());
                assert_eq!(raw, body);
            }
            other => panic!("expected Veto, got {other:?}"),
        }
    }

    #[test]
    fn parse_veto_with_partial_body_keeps_present_fields() {
        // Body has `intent_category` but is missing `reasons`. The
        // `#[serde(default)]` attributes mean the missing field
        // becomes an empty Vec, not a parse error.
        let body = r#"{ "intent_category": "Velocity" }"#;
        match parse_veto(body) {
            ClavenarError::Veto { intent_category, reasons, .. } => {
                assert_eq!(intent_category, "Velocity");
                assert!(reasons.is_empty());
            }
            other => panic!("expected Veto, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn builder_rejects_invalid_url() {
        let err = ClavenarClient::builder("not a url").unwrap_err();
        match err {
            ClavenarError::InvalidConfig(msg) => assert!(msg.contains("base_url")),
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }
}

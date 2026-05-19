//! Typed client for `warden-brain`.
//!
//! Currently exposes a single endpoint: `POST /explain-pattern`,
//! consumed by the policy-engine miner (Phase 7 Self-Learn) and by
//! any external tooling that wants a human-readable explanation of
//! a pattern detected in their own traffic.
//!
//! The brain's `/inspect` surface is *not* exposed here — that's the
//! proxy's hot-path contract, not something the SDK should encourage
//! external callers to drive directly. If you want to ask brain "is
//! this MCP call shaped like an injection?", call the proxy, which
//! enforces auth + correlation + ledger emission.

use std::sync::Arc;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::http::{decode_response, default_provider, parse_base_url, HttpProvider, StaticHttpClient};
use crate::WardenError;

/// Wire shape for `POST /explain-pattern`. The PII contract here is
/// enforced by the struct itself: only aggregated thresholds, the
/// pattern kind, the tool name (or a placeholder), and an evidence
/// count. Callers must construct this from aggregated metrics — never
/// raw arguments / agent IDs / correlation IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainPatternRequest {
    pub kind: String,
    pub tool_type: String,
    pub threshold: serde_json::Value,
    pub evidence_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExplainPatternResponse {
    pub one_liner: String,
    pub rationale: String,
}

/// Cheap to clone — the inner `reqwest::Client` is `Arc`-based, same
/// pattern as the other per-service clients.
#[derive(Debug, Clone)]
pub struct BrainClient {
    base_url: Url,
    http: Arc<dyn HttpProvider>,
    bearer: Option<String>,
}

impl BrainClient {
    /// Build a client against `base_url` (e.g.
    /// `http://localhost:8081`). The path is appended verbatim — pass
    /// the brain's root, not `/explain-pattern`.
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, WardenError> {
        let url = parse_base_url(base_url.as_ref())?;
        let http = default_provider()?;
        Ok(Self {
            base_url: url,
            http,
            bearer: None,
        })
    }

    pub fn with_http_client(self, client: Client) -> Self {
        self.with_http_provider(Arc::new(StaticHttpClient::new(client)))
    }

    pub fn with_http_provider(mut self, provider: Arc<dyn HttpProvider>) -> Self {
        self.http = provider;
        self
    }

    pub fn with_bearer(mut self, token: impl Into<String>) -> Self {
        self.bearer = Some(token.into());
        self
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub async fn explain_pattern(
        &self,
        req: &ExplainPatternRequest,
    ) -> Result<ExplainPatternResponse, WardenError> {
        let url = self
            .base_url
            .join("explain-pattern")
            .map_err(|e| WardenError::InvalidConfig(format!("join explain-pattern: {e}")))?;
        let mut request = self.http.client().post(url).json(req);
        if let Some(t) = self.bearer.as_ref() {
            request = request.bearer_auth(t);
        }
        let resp = request.send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        decode_response(status, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_base_url() {
        match BrainClient::new("not a url") {
            Ok(_) => panic!("expected InvalidConfig"),
            Err(WardenError::InvalidConfig(_)) => {}
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn pii_contract_request_shape_holds_only_aggregates() {
        // Mirror of the test in warden-brain. The SDK type's shape is
        // a separate enforcement boundary — a future PR that adds a
        // free-form payload field to ExplainPatternRequest has to
        // delete this assertion to land.
        let req = ExplainPatternRequest {
            kind: "after_hours".to_string(),
            tool_type: "bulk_export".to_string(),
            threshold: serde_json::json!({"off_hours_pct": 0.12}),
            evidence_count: 142,
        };
        let s = serde_json::to_string(&req).unwrap();
        for forbidden in [
            "arguments",
            "agent_id",
            "correlation_id",
            "payload",
            "raw",
            "input",
        ]
        .iter()
        {
            assert!(
                !s.contains(&format!("\"{}\"", forbidden)),
                "PII-shaped key {} must not appear in request body: {}",
                forbidden,
                s
            );
        }
    }
}

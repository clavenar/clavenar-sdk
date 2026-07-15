//! Async client for the clavenar-simulator admin HTTP surface.
//!
//! Three calls cover the operator surface needed by the
//! `clavenar-console` `/sim` panel:
//!
//! * [`SimClient::status`] — live snapshot: traffic multiplier, agent
//!   roster (cn + persona + λ + transient flag), and the latest stats
//!   summary.
//! * [`SimClient::set_multiplier`] — `POST /multiplier`. The simulator
//!   updates the shared atomic in place; agents pick up the new value
//!   on their next inter-arrival.
//! * [`SimClient::add_agents`] — `POST /agents`. Mints a transient
//!   `<persona>-tN` agent and spawns its traffic loop.
//!
//! The simulator control surface requires a mutually authenticated
//! transport outside local fixtures. Callers inject an [`HttpProvider`]
//! carrying the authorized workload identity; network placement alone is
//! not authorization and the control listener must never be public.

use std::sync::Arc;
use std::time::Duration;

use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};

use crate::ClavenarError;
use crate::http::{
    HttpProvider, StaticHttpClient, decode_response, default_provider, parse_base_url,
};

/// One row in the live agent roster — mirrors the simulator's
/// internal `AgentRecord`. `transient=false` for the boot roster,
/// `true` for agents spawned via `POST /agents`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimAgentRecord {
    pub cn: String,
    pub persona: String,
    pub rate_lambda: f64,
    #[serde(default)]
    pub transient: bool,
}

/// Snapshot of the simulator's `Stats`. `None` for the latency
/// percentiles when no requests have been recorded yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimStats {
    pub sent: u64,
    pub ok: u64,
    pub denied: u64,
    pub error: u64,
    pub success_pct: f64,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
}

/// Response body of `GET /status` on the simulator's admin server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimStatus {
    pub traffic_multiplier: f64,
    /// Whether the simulator is currently firing requests. Older
    /// simulator builds (pre run-flag) didn't emit this field;
    /// `#[serde(default)]` resolves to `false` (paused) for those.
    /// That matches the new boot default and keeps the console safe
    /// against version skew during a rolling upgrade.
    #[serde(default)]
    pub running: bool,
    /// HIL auto-decision sidecar state. `None` means the sidecar
    /// wasn't configured at boot (no `--hil-url` on the simulator) —
    /// the console renders an "off" placeholder and disables the
    /// toggle. `Some(true/false)` is enabled / paused. The simulator
    /// emits this with `serde(skip_serializing_if = is_none)`, so
    /// older simulator payloads omit the field entirely; `serde(default)`
    /// here fills it back in as `None`.
    #[serde(default)]
    pub auto_decide: Option<bool>,
    pub agents: Vec<SimAgentRecord>,
    pub stats: SimStats,
}

/// Async client for the simulator admin HTTP surface.
///
/// Cheap to clone — the inner `reqwest::Client` is `Arc`-based.
#[derive(Debug, Clone)]
pub struct SimClient {
    base_url: Url,
    http: Arc<dyn HttpProvider>,
    request_timeout: Duration,
}

// The simulator bounds transient-agent creation at 15 seconds. Keep the
// client deadline above that server budget so a non-idempotent create cannot
// complete after the caller has already reported a timeout.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_OPERATOR: &str = "sdk:unattributed";
const MAX_OPERATOR_BYTES: usize = 128;

impl SimClient {
    /// Build a client against `base_url` (e.g.
    /// `http://simulator:9100`). Returns `InvalidConfig` if the URL
    /// is malformed.
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, ClavenarError> {
        let url = parse_base_url(base_url.as_ref())?;
        let http = default_provider()?;
        Ok(Self {
            base_url: url,
            http,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        })
    }

    /// Inject a pre-configured `reqwest::Client`. Same use case as
    /// `ClavenarClientBuilder::http_client` — lets callers configure
    /// timeouts / proxy / TLS once and reuse.
    pub fn with_http_client(self, client: Client) -> Self {
        self.with_http_provider(Arc::new(StaticHttpClient::new(client)))
    }

    /// Inject a custom [`HttpProvider`] for hot-reloading credentials.
    /// See [`LedgerClient::with_http_provider`] for the trade-offs.
    pub fn with_http_provider(mut self, provider: Arc<dyn HttpProvider>) -> Self {
        self.http = provider;
        self
    }

    /// Override the per-request deadline. The default is twenty seconds.
    /// Zero is rejected because an unbounded or ambiguous control-plane
    /// request is never a safe fallback.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Result<Self, ClavenarError> {
        if timeout.is_zero() {
            return Err(ClavenarError::InvalidConfig(
                "simulator request timeout must be greater than zero".into(),
            ));
        }
        self.request_timeout = timeout;
        Ok(self)
    }

    /// Read-only access to the configured base URL. Mirrors
    /// `AgentsClient::base_url` so the clavenar-console `/config` page
    /// can surface the simulator's admin URL on its "Backends" card
    /// without having to plumb the raw env var alongside the client.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// `GET /status` — current multiplier + agent roster + stats.
    pub async fn status(&self) -> Result<SimStatus, ClavenarError> {
        self.get_json("status").await
    }

    /// `POST /multiplier` — update the simulator's traffic multiplier
    /// in place. Returns the post-update [`SimStatus`] so the caller
    /// can render the new state without a follow-up `status()` call.
    pub async fn set_multiplier(&self, multiplier: f64) -> Result<SimStatus, ClavenarError> {
        self.set_multiplier_as(DEFAULT_OPERATOR, multiplier).await
    }

    /// Attributed variant of [`Self::set_multiplier`]. `operator` is
    /// audit context only; the simulator still authorizes the caller with
    /// its mutually authenticated workload identity.
    pub async fn set_multiplier_as(
        &self,
        operator: &str,
        multiplier: f64,
    ) -> Result<SimStatus, ClavenarError> {
        self.post_json_as(
            operator,
            "multiplier",
            &serde_json::json!({ "traffic_multiplier": multiplier }),
        )
        .await
    }

    /// `POST /running` — flip the simulator's start/stop flag.
    /// Returns the post-update [`SimStatus`] so the caller can render
    /// the new badge without a follow-up `status()` call.
    pub async fn set_running(&self, running: bool) -> Result<SimStatus, ClavenarError> {
        self.set_running_as(DEFAULT_OPERATOR, running).await
    }

    /// Attributed variant of [`Self::set_running`].
    pub async fn set_running_as(
        &self,
        operator: &str,
        running: bool,
    ) -> Result<SimStatus, ClavenarError> {
        self.post_json_as(
            operator,
            "running",
            &serde_json::json!({ "running": running }),
        )
        .await
    }

    /// `POST /auto-decide` — pause or resume the simulator's HIL
    /// auto-decision sidecar. Returns the post-update [`SimStatus`].
    /// When the simulator wasn't booted with `--hil-url`, the server
    /// answers 409 Conflict and this surfaces as
    /// [`ClavenarError::Server`] with the explanation in the body.
    pub async fn set_auto_decide(&self, enabled: bool) -> Result<SimStatus, ClavenarError> {
        self.set_auto_decide_as(DEFAULT_OPERATOR, enabled).await
    }

    /// Attributed variant of [`Self::set_auto_decide`].
    pub async fn set_auto_decide_as(
        &self,
        operator: &str,
        enabled: bool,
    ) -> Result<SimStatus, ClavenarError> {
        self.post_json_as(
            operator,
            "auto-decide",
            &serde_json::json!({ "enabled": enabled }),
        )
        .await
    }

    /// `POST /agents` — mint and spawn `count` transient agents of
    /// the named persona. Returns the CNs of the spawned agents on
    /// success.
    pub async fn add_agents(
        &self,
        persona: &str,
        count: usize,
    ) -> Result<Vec<String>, ClavenarError> {
        self.add_agents_as(DEFAULT_OPERATOR, persona, count).await
    }

    /// Attributed variant of [`Self::add_agents`].
    pub async fn add_agents_as(
        &self,
        operator: &str,
        persona: &str,
        count: usize,
    ) -> Result<Vec<String>, ClavenarError> {
        // The simulator returns `{ spawned: [...] }`; project to the
        // inner Vec so callers don't carry the wrapper.
        #[derive(Deserialize)]
        struct Wrap {
            spawned: Vec<String>,
        }
        let w: Wrap = self
            .post_json_as(
                operator,
                "agents",
                &serde_json::json!({ "persona": persona, "count": count }),
            )
            .await?;
        Ok(w.spawned)
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, ClavenarError> {
        let endpoint = self
            .base_url
            .join(path)
            .map_err(|e| ClavenarError::InvalidConfig(format!("join {path}: {e}")))?;
        let resp = self
            .http
            .client()
            .get(endpoint)
            .timeout(self.request_timeout)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        decode_response(status, body)
    }

    async fn post_json_as<B: Serialize, T: serde::de::DeserializeOwned>(
        &self,
        operator: &str,
        path: &str,
        body: &B,
    ) -> Result<T, ClavenarError> {
        validate_operator(operator)?;
        let endpoint = self
            .base_url
            .join(path)
            .map_err(|e| ClavenarError::InvalidConfig(format!("join {path}: {e}")))?;
        let resp = self
            .http
            .client()
            .post(endpoint)
            .header("x-clavenar-operator", operator)
            .json(body)
            .timeout(self.request_timeout)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        decode_response(status, body)
    }
}

fn validate_operator(operator: &str) -> Result<(), ClavenarError> {
    if operator.is_empty()
        || operator.len() > MAX_OPERATOR_BYTES
        || !operator.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ClavenarError::InvalidConfig(format!(
            "simulator operator must be 1..={MAX_OPERATOR_BYTES} visible ASCII bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::routing::{get, post};
    use axum::{Json, Router};

    use super::*;

    fn status_payload() -> serde_json::Value {
        serde_json::json!({
            "traffic_multiplier": 1.0,
            "running": false,
            "agents": [],
            "stats": {
                "sent": 0,
                "ok": 0,
                "denied": 0,
                "error": 0,
                "success_pct": 0.0,
                "p50_ms": null,
                "p95_ms": null
            }
        })
    }

    async fn spawn_test_server(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/"), task)
    }

    #[test]
    fn sim_status_decodes_canonical_payload() {
        let raw = r#"{
            "traffic_multiplier": 2.5,
            "running": true,
            "auto_decide": true,
            "agents": [
                {"cn": "cs-bot-1", "persona": "cs-bot", "rate_lambda": 0.3, "transient": false},
                {"cn": "cs-bot-t1", "persona": "cs-bot", "rate_lambda": 0.3, "transient": true}
            ],
            "stats": {
                "sent": 100, "ok": 95, "denied": 4, "error": 1,
                "success_pct": 95.0,
                "p50_ms": 18.0, "p95_ms": 3100.0
            }
        }"#;
        let parsed: SimStatus = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.traffic_multiplier, 2.5);
        assert!(parsed.running);
        assert_eq!(parsed.auto_decide, Some(true));
        assert_eq!(parsed.agents.len(), 2);
        assert!(!parsed.agents[0].transient);
        assert!(parsed.agents[1].transient);
        assert_eq!(parsed.stats.sent, 100);
        assert_eq!(parsed.stats.p50_ms, Some(18.0));
    }

    #[test]
    fn sim_status_auto_decide_defaults_none_when_field_missing() {
        // Simulator omits `auto_decide` when the sidecar isn't
        // configured (skip_serializing_if). Older builds didn't emit
        // it at all. Both shapes deserialize to `None` here.
        let raw = r#"{
            "traffic_multiplier": 1.0,
            "running": false,
            "agents": [],
            "stats": {"sent": 0, "ok": 0, "denied": 0, "error": 0, "success_pct": 0.0, "p50_ms": null, "p95_ms": null}
        }"#;
        let parsed: SimStatus = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.auto_decide, None);
    }

    #[test]
    fn sim_status_running_defaults_false_when_field_missing() {
        // Pre run-flag simulator builds don't emit `running`. The
        // `#[serde(default)]` resolves it to `false` so the console's
        // Start/Stop button shows the safe (paused) state until the
        // simulator is actually upgraded.
        let raw = r#"{
            "traffic_multiplier": 1.0,
            "agents": [],
            "stats": {"sent": 0, "ok": 0, "denied": 0, "error": 0, "success_pct": 0.0, "p50_ms": null, "p95_ms": null}
        }"#;
        let parsed: SimStatus = serde_json::from_str(raw).unwrap();
        assert!(!parsed.running);
    }

    #[test]
    fn sim_agent_record_defaults_transient_false_for_legacy_payload() {
        // Older simulator builds (pre-Phase-4) won't emit `transient`.
        // The `#[serde(default)]` should resolve it to `false`.
        let raw = r#"{"cn": "cs-bot-1", "persona": "cs-bot", "rate_lambda": 0.3}"#;
        let parsed: SimAgentRecord = serde_json::from_str(raw).unwrap();
        assert!(!parsed.transient);
    }

    #[test]
    fn sim_client_surfaces_configured_base_url() {
        // The clavenar-console /config page renders the simulator's base
        // URL on its "Backends (optional)" card; this getter is what
        // the handler reads. Round-trip the URL string through the
        // client without losing the trailing slash.
        let client = SimClient::new("http://simulator:9100/").unwrap();
        assert_eq!(client.base_url().as_str(), "http://simulator:9100/");
    }

    #[test]
    fn sim_stats_handles_no_requests_yet() {
        let raw = r#"{"sent": 0, "ok": 0, "denied": 0, "error": 0, "success_pct": 0.0, "p50_ms": null, "p95_ms": null}"#;
        let parsed: SimStats = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.sent, 0);
        assert!(parsed.p50_ms.is_none());
    }

    #[test]
    fn simulator_operator_is_bounded_visible_ascii() {
        assert!(validate_operator("alice@example.test").is_ok());
        assert!(validate_operator("").is_err());
        assert!(validate_operator("contains space").is_err());
        assert!(validate_operator("contains\nnewline").is_err());
        assert!(validate_operator(&"a".repeat(MAX_OPERATOR_BYTES)).is_ok());
        assert!(validate_operator(&"a".repeat(MAX_OPERATOR_BYTES + 1)).is_err());
    }

    #[test]
    fn simulator_request_timeout_rejects_zero() {
        let client = SimClient::new("http://simulator:9100/").unwrap();
        assert!(client.with_request_timeout(Duration::ZERO).is_err());
    }

    #[test]
    fn default_request_deadline_exceeds_server_creation_budget() {
        assert!(DEFAULT_REQUEST_TIMEOUT > Duration::from_secs(15));
    }

    #[tokio::test]
    async fn attributed_mutation_forwards_operator_header() {
        async fn capture(
            State(seen): State<Arc<Mutex<Option<String>>>>,
            headers: HeaderMap,
        ) -> Json<serde_json::Value> {
            *seen.lock().unwrap() = headers
                .get("x-clavenar-operator")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            Json(status_payload())
        }

        let seen = Arc::new(Mutex::new(None));
        let app = Router::new()
            .route("/multiplier", post(capture))
            .with_state(seen.clone());
        let (base_url, server) = spawn_test_server(app).await;
        let client = SimClient::new(base_url).unwrap();

        client
            .set_multiplier_as("test-approver", 2.0)
            .await
            .unwrap();

        assert_eq!(seen.lock().unwrap().as_deref(), Some("test-approver"));
        server.abort();
    }

    #[tokio::test]
    async fn simulator_request_deadline_covers_read_only_calls() {
        async fn slow_status() -> Json<serde_json::Value> {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Json(status_payload())
        }

        let app = Router::new().route("/status", get(slow_status));
        let (base_url, server) = spawn_test_server(app).await;
        let client = SimClient::new(base_url)
            .unwrap()
            .with_request_timeout(Duration::from_millis(10))
            .unwrap();

        let error = client.status().await.unwrap_err();

        assert!(matches!(error, ClavenarError::Transport(ref err) if err.is_timeout()));
        server.abort();
    }
}

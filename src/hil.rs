//! Async client for the `clavenar-hil` HTTP surface (`/pending`,
//! `/decide/{id}`, `/decision-link/verify`, `/auth/*` proxy,
//! `/identities/*`). Server-side types are duplicated here as
//! deliberate wire-contract mirrors.
//!
//! Error mapping differs from the `decode_response` clients on
//! purpose: every non-2xx surfaces as [`ClavenarError::Server`] with
//! the status and verbatim body, so a caller can branch per status
//! (404 "no longer pending" vs 409 "already decided" vs 422 "action
//! invalid in this state") without the SDK collapsing them.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ClavenarError;
use crate::http::{HttpProvider, StaticHttpClient, default_provider, parse_base_url};

/// Cookie name HIL's WebAuthn middleware reads on `/decide/{id}`.
pub const HIL_SESSION_COOKIE: &str = "clavenar_hil_session";

/// Cookie name HIL's demo-session middleware reads. HIL re-verifies
/// the JWT and enforces the prefix-against-correlation-id gate.
pub const DEMO_SESSION_COOKIE: &str = "clavenar_demo_session";

/// Hex-encoded typed principal claim. HIL accepts this header only from the
/// exact Console mTLS workload and supplies the credential fingerprint from
/// the verified peer certificate itself.
pub const DECISION_PRINCIPAL_HEADER: &str = "x-clavenar-decision-principal";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionPrincipalMethod {
    Oidc,
    Saml,
    BasicAdmin,
    OperatorMtls,
}

#[derive(Serialize)]
struct ConsolePrincipalClaim<'a> {
    subject: &'a str,
    tenant: &'a str,
    method: DecisionPrincipalMethod,
}

/// Status of a HIL pending row. Mirror of `clavenar_hil::Status`.
/// Lowercase wire form via `#[serde(rename_all = "lowercase")]` on
/// the server side; we match it here.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PendingStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

impl PendingStatus {
    /// Pretty label for a UI — capitalized, no quotes.
    pub fn label(self) -> &'static str {
        match self {
            PendingStatus::Pending => "Pending",
            PendingStatus::Approved => "Approved",
            PendingStatus::Denied => "Denied",
            PendingStatus::Expired => "Expired",
        }
    }
}

/// One row from `GET /pending`. Mirror of `clavenar_hil::PendingRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRequest {
    pub id: Uuid,
    /// Proxy-stamped UUIDv4 that joins this HIL row to the brain/policy/
    /// proxy/ledger rows for the same agent request — the key for
    /// deep-linking from a pending row to the full forensic timeline.
    pub correlation_id: Uuid,
    pub agent_id: String,
    pub method: String,
    pub request_payload: serde_json::Value,
    pub risk_summary: String,
    pub created_at: DateTime<Utc>,
    pub ttl_seconds: i64,
    pub status: PendingStatus,
    #[serde(default)]
    pub decided_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub decided_by: Option<String>,
    #[serde(default)]
    pub decision_reason: Option<String>,
    /// Present when an admin chose `Decision::Modify` and supplied a
    /// rewrite, so HIL responses round-trip cleanly through
    /// [`HilClient::decide`].
    #[serde(default)]
    pub modified_payload: Option<serde_json::Value>,
    /// `clavenar-sandbox` static-analysis report computed by the
    /// proxy before the row was created. Carries operation_class,
    /// severity, targets, summary, predicted_changes. Opaque JSON to
    /// this transport — callers project it into their own typed view.
    #[serde(default)]
    pub sandbox_report: Option<serde_json::Value>,
    /// Delegation grant identifier (proxy parses `X-Clavenar-Grant`,
    /// extracts `jti`, plumbs to HIL). Joins the row to
    /// clavenar-identity's `grants` table.
    #[serde(default)]
    pub delegation_jti: Option<String>,
    /// Human principal `act.sub` from the same grant. Surfaced as
    /// "<human> via <agent>" — the EU-AI-Act-Article-12 audit story's
    /// payoff line.
    #[serde(default)]
    pub human_sub: Option<String>,
    /// Per-decision approver claim. JSON blob whose shape varies by
    /// auth mode — see clavenar-hil's `PendingRequest::approver_assertion`
    /// for the per-mode contract. Regulators read the richer "who"
    /// claim alongside `decided_by`.
    #[serde(default)]
    pub approver_assertion: Option<serde_json::Value>,
    /// Set by HIL's SLA sweep once a still-pending row crossed its
    /// escalation threshold; `None` on rows that haven't escalated.
    #[serde(default)]
    pub escalated_at: Option<DateTime<Utc>>,
    /// Post-hoc decision-narrative annotation written after a decision
    /// lands (`PATCH /pending/{id}/incident`), sourced from
    /// clavenar-brain's `/narrate-decision`. An annotation, never
    /// evidence — the deterministic `decision_reason` stays the
    /// compliance record.
    #[serde(default)]
    pub incident_summary: Option<String>,
    /// Just-in-time grant terms stamped by the proxy for JIT-shaped grants:
    /// consumption cap + activation/expiry window (epoch seconds) —
    /// renderable as a "1 use, valid 05:00–06:00" badge. `None` for
    /// plain delegated rows.
    #[serde(default)]
    pub grant_max_uses: Option<i64>,
    #[serde(default)]
    pub grant_not_before: Option<i64>,
    #[serde(default)]
    pub grant_not_after: Option<i64>,
    /// Pre-formatted recurring-schedule summary ("Mon–Fri 09:00–17:00 UTC")
    /// for a grant carrying a recurrence window. `None` for non-recurring.
    #[serde(default)]
    pub grant_recurrence_summary: Option<String>,
    /// Per-detector Brain scores captured at create time (opaque JSON).
    /// Non-evidentiary annotation.
    #[serde(default)]
    pub brain_scores: Option<serde_json::Value>,
    /// N-of-M quorum requirement. `None` / `Some(1)` ⇒ single-approver;
    /// `Some(n>1)` means the row needs n distinct approvals.
    #[serde(default)]
    pub required_approvers: Option<i64>,
    /// Distinct approvals accumulated so far on a quorum row (JSON array
    /// of `{by,provenance,at}`). Count its length against
    /// `required_approvers` for progress.
    #[serde(default)]
    pub approvals: Option<serde_json::Value>,
    /// Advisory hand-off target — "assigned to X".
    #[serde(default)]
    pub assigned_to: Option<String>,
    /// Named escalation pool snapshotted on the row. Display-only here.
    #[serde(default)]
    pub escalation_pool: Option<String>,
    /// Brain's per-request inspection-cost estimate (micro-USD) for the
    /// parked action — a *projected* $ figure (FinOps P3). `None` when
    /// unpriced (mock mode / older proxy).
    #[serde(default)]
    pub projected_cost_micros: Option<i64>,
    /// Rego-assigned approval tier: `auto` / `standard` / `strict`.
    /// `auto` rows are decided by `system:policy-tier`. `None` from an
    /// older proxy/HIL or a pending that did not traverse Rego.
    #[serde(default)]
    pub approval_tier: Option<String>,
    /// Operator-tenant scope stamped by the proxy/HIL. `None` in demo and
    /// single-tenant deployments.
    #[serde(default)]
    pub tenant: Option<String>,
}

/// Decision body sent to `POST /decide/{id}`. Mirror of
/// `clavenar_hil::Decide`, including the modify-and-resume path.
#[derive(Debug, Clone, Serialize)]
pub struct DecideRequest {
    pub decision: Decision,
    pub decided_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Required when `decision == Modify`; HIL rejects the request with
    /// 400 otherwise. Skipped from the wire when None so plain
    /// approve/deny calls match the original shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_payload: Option<serde_json::Value>,
    /// Per-decision approver claim. HIL's bearer-trust modes
    /// (oidc / basic-admin / disabled) forward this verbatim onto the
    /// audit row. The webauthn cookie path ignores any value here and
    /// mints server-side from the verified principal — `None` is the
    /// expected value on cookie-trust calls. Skipped from the wire
    /// when `None` so plain calls retain the legacy shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver_assertion: Option<serde_json::Value>,
    /// Operator surface the decision arrived through (`console`,
    /// `signed-link`, `terminal`, …). HIL trusts it only on the
    /// bearer/disabled paths — a trusted caller knows which surface the
    /// operator used; demo/webauthn callers have it derived server-side.
    /// Skipped from the wire when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_via: Option<String>,
    /// Operator tenant the caller acts for (Phase 4b). HIL's `/decide`
    /// asserts the pending's tenant matches it on non-demo paths. Skipped
    /// from the wire when `None` so demo / single-tenant calls keep the
    /// legacy shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// Result of `POST /decision-link/verify`. Mirror of
/// `clavenar_hil::handler::decision_link::VerifyResponse`. `valid` is
/// true only when the signed link checks out AND its target is still a
/// live (`Pending`) row — a redeemable link.
#[derive(Debug, Clone, Deserialize)]
pub struct DecisionLinkVerify {
    pub valid: bool,
    /// `ok` · `expired` · `invalid` · `not_pending` · `gone`.
    pub reason: String,
    #[serde(default)]
    pub pending_id: Option<Uuid>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub pending: Option<DecisionLinkPending>,
}

/// The target pending's summary, shown on a redemption surface so the
/// approver sees what they're confirming.
#[derive(Debug, Clone, Deserialize)]
pub struct DecisionLinkPending {
    pub agent_id: String,
    pub method: String,
    /// Concrete tool the request targets (`params.name`), distinct from
    /// the `call_tool` envelope in `method`. HIL lifts it from the
    /// pending's `request_payload`; `None` when the payload carries no
    /// `params.name`.
    #[serde(default)]
    pub tool: Option<String>,
    pub risk_summary: String,
    pub status: String,
    pub correlation_id: String,
    #[serde(default)]
    pub tenant: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Approve,
    Deny,
    /// "Approve with rewrite" — the proxy will forward the
    /// admin-supplied `modified_payload` upstream instead of the
    /// original.
    Modify,
}

/// Which trust path a [`HilClient::decide`] call presents to HIL.
///
/// The variants map onto HIL's three `/decide/{id}` auth modes:
///
/// * [`HilDecideCredential::SessionCookie`] — WebAuthn mode. The value
///   is the `clavenar_hil_session` cookie HIL issued during the
///   ceremony; HIL stamps `decided_by` server-side from the verified
///   credential, ignoring the request body's value.
/// * [`HilDecideCredential::Bearer`] — trusted Console bearer plus a typed
///   subject/method claim. HIL requires Console mTLS, supplies the peer
///   credential fingerprint, and ignores legacy body attribution.
/// * [`HilDecideCredential::DemoSession`] — demo-session JWT forwarded
///   as the `clavenar_demo_session` cookie. HIL re-verifies the
///   signature and enforces the prefix-against-correlation-id gate;
///   `decided_by` is stamped from the JWT's `sub` claim as `demo:<sub>`.
#[derive(Debug, Clone, Copy)]
pub enum HilDecideCredential<'a> {
    SessionCookie(&'a str),
    Bearer {
        token: &'a str,
        subject: &'a str,
        method: DecisionPrincipalMethod,
    },
    DemoSession(&'a str),
}

/// Async client for the HIL service.
///
/// Cheap to clone — the HTTP provider is behind an `Arc`.
#[derive(Debug, Clone)]
pub struct HilClient {
    base_url: Url,
    http: Arc<dyn HttpProvider>,
    /// Operator-tenant scope (Phase 4b). When set, reads stamp `?tenant=`
    /// and `/decide` carries the tenant so HIL confines the operator to
    /// their own queue. `None` ⇒ demo (cookie-scoped) / single-tenant.
    tenant: Option<String>,
}

impl HilClient {
    /// Build a client against `base_url` (e.g. `http://hil:8084`).
    /// Returns `InvalidConfig` if the URL is malformed.
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, ClavenarError> {
        let url = parse_base_url(base_url.as_ref())?;
        let http = default_provider()?;
        Ok(Self {
            base_url: url,
            http,
            tenant: None,
        })
    }

    /// A clone of this client scoped to an operator tenant. Mirrors
    /// [`crate::PoliciesClient::with_tenant`]: build a scoped client per
    /// request from the authenticated session so reads and `/decide`
    /// carry the operator's tenant. `None` leaves it unscoped
    /// (demo / single-tenant).
    pub fn with_tenant(mut self, tenant: Option<String>) -> Self {
        self.tenant = tenant;
        self
    }

    /// Inject a pre-built `reqwest::Client` (custom timeouts, TLS roots,
    /// mTLS identity, etc.).
    pub fn with_http_client(self, client: Client) -> Self {
        self.with_http_provider(Arc::new(StaticHttpClient::new(client)))
    }

    /// Inject a custom [`HttpProvider`] for hot-reloading credentials
    /// (workload-SVID refresh). Same shape as the other SDK clients.
    pub fn with_http_provider(mut self, provider: Arc<dyn HttpProvider>) -> Self {
        self.http = provider;
        self
    }

    /// Read-only access to the configured base URL. Mirrors
    /// [`crate::AgentsClient::base_url`] and [`crate::SimClient::base_url`]
    /// so a caller can surface the HIL URL without re-reading its own
    /// config.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// `POST /pending` — create a fresh HIL pending row directly, without
    /// traversing the proxy. HIL's `/pending` endpoint is intentionally
    /// NOT auth-gated (only `/decide/{id}` is); production callers are
    /// the proxy and trusted control-plane surfaces such as the
    /// console's demo path.
    pub async fn create_pending(
        &self,
        body: &serde_json::Value,
    ) -> Result<PendingRequest, ClavenarError> {
        let url = self.join("pending")?;
        let resp = self.http.client().post(url).json(body).send().await?;
        read_json(resp).await
    }

    /// `GET /pending?status=<status>` — newest first per HIL's own list
    /// ordering, optionally forwarding a demo-session JWT as the
    /// `clavenar_demo_session` cookie so HIL re-verifies it and filters
    /// the queue to that prefix server-side.
    async fn list_by_status(
        &self,
        status: &str,
        demo_session_jwt: Option<&str>,
    ) -> Result<Vec<PendingRequest>, ClavenarError> {
        let mut url = self.join("pending")?;
        url.query_pairs_mut().append_pair("status", status);
        if let Some(t) = &self.tenant {
            url.query_pairs_mut().append_pair("tenant", t);
        }

        let mut req = self.http.client().get(url);
        if let Some(jwt) = demo_session_jwt {
            req = req.header(
                reqwest::header::COOKIE,
                format!("{DEMO_SESSION_COOKIE}={jwt}"),
            );
        }
        let resp = req.send().await?;
        read_json(resp).await
    }

    /// Live queue — rows still awaiting a human decision.
    pub async fn list_pending(&self) -> Result<Vec<PendingRequest>, ClavenarError> {
        self.list_by_status("pending", None).await
    }

    /// Live queue scoped to a demo session — forwards the visitor's
    /// `clavenar_demo_session` cookie to HIL (which re-verifies + filters
    /// to the prefix). Callers on a demo read path should still apply
    /// their own prefix gate on the result as defense-in-depth.
    pub async fn list_pending_scoped(
        &self,
        demo_session_jwt: &str,
    ) -> Result<Vec<PendingRequest>, ClavenarError> {
        self.list_by_status("pending", Some(demo_session_jwt)).await
    }

    /// Retroactive-review feed — approved rows the policy `auto` tier
    /// decided on creation (`decided_by = system:policy-tier`). HIL has
    /// no dedicated endpoint, so this filters the approved list.
    pub async fn list_auto_approved(&self) -> Result<Vec<PendingRequest>, ClavenarError> {
        let mut rows = self.list_by_status("approved", None).await?;
        rows.retain(|p| p.decided_by.as_deref() == Some("system:policy-tier"));
        Ok(rows)
    }

    /// Retroactive-review feed scoped to a demo session — forwards the
    /// visitor's cookie so HIL filters the approved list to their prefix
    /// before the `system:policy-tier` retain runs.
    pub async fn list_auto_approved_scoped(
        &self,
        demo_session_jwt: &str,
    ) -> Result<Vec<PendingRequest>, ClavenarError> {
        let mut rows = self
            .list_by_status("approved", Some(demo_session_jwt))
            .await?;
        rows.retain(|p| p.decided_by.as_deref() == Some("system:policy-tier"));
        Ok(rows)
    }

    /// `POST /decision-link/verify` — validate a signed decision link and
    /// return its claim + the target pending's summary. A redemption
    /// surface calls this to resolve a token before it decides. HIL never
    /// `200`s with a malformed body here, so a non-2xx is a real
    /// transport/HIL fault.
    pub async fn verify_decision_link(
        &self,
        token: &str,
    ) -> Result<DecisionLinkVerify, ClavenarError> {
        let url = self.join("decision-link/verify")?;
        let resp = self
            .http
            .client()
            .post(url)
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await?;
        read_json(resp).await
    }

    /// `PATCH /pending/{id}/incident` — attach a decision narrative to an
    /// already-decided pending. HIL 409s if the row is still pending,
    /// 404s if it's gone; callers typically treat this as best-effort.
    pub async fn patch_incident_summary(
        &self,
        id: Uuid,
        incident_summary: &str,
    ) -> Result<PendingRequest, ClavenarError> {
        let url = self.join(&format!("pending/{id}/incident"))?;
        let body = serde_json::json!({ "incident_summary": incident_summary });
        let resp = self.http.client().patch(url).json(&body).send().await?;
        read_json(resp).await
    }

    /// `POST /pending/{id}/assign` — record an advisory hand-off target
    /// (and optionally repoint the escalation pool) on a still-pending
    /// row. HIL 409s if the row is no longer pending, 404s if it's gone.
    pub async fn assign(
        &self,
        id: Uuid,
        assigned_to: &str,
        escalation_pool: Option<&str>,
    ) -> Result<PendingRequest, ClavenarError> {
        let url = self.join(&format!("pending/{id}/assign"))?;
        let body = serde_json::json!({
            "assigned_to": assigned_to,
            "escalation_pool": escalation_pool,
        });
        let resp = self.http.client().post(url).json(&body).send().await?;
        read_json(resp).await
    }

    /// `GET /notifications/config` — which notifier channels are live
    /// (booleans + escalation-pool names, no secrets).
    pub async fn notifications_config(&self) -> Result<ChannelStatus, ClavenarError> {
        let url = self.join("notifications/config")?;
        let resp = self.http.client().get(url).send().await?;
        read_json(resp).await
    }

    /// `POST /notifications/test` — fire a synthetic notification to every
    /// configured channel. Returns the post-test channel status.
    pub async fn notifications_test(&self) -> Result<ChannelStatus, ClavenarError> {
        let url = self.join("notifications/test")?;
        let resp = self.http.client().post(url).send().await?;
        read_json(resp).await
    }

    /// `GET /pending/by-correlation/{cid}` — the most-recently-decided
    /// pending for a correlation, or `None` (HIL 404) when none decided.
    pub async fn get_pending_by_correlation(
        &self,
        correlation_id: &str,
    ) -> Result<Option<PendingRequest>, ClavenarError> {
        let url = self.join(&format!("pending/by-correlation/{correlation_id}"))?;
        let resp = self.http.client().get(url).send().await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        read_json(resp).await.map(Some)
    }

    /// `GET /approvals/stats?window=…` — read-only approver analytics
    /// (decided totals, deny rate, time-to-decide percentiles,
    /// per-approver breakdown). Ungated upstream like `/pending`;
    /// callers gate the surface that renders it.
    pub async fn approvals_stats(&self, window: &str) -> Result<ApprovalStats, ClavenarError> {
        self.approvals_stats_inner(window, None).await
    }

    /// As [`Self::approvals_stats`], forwarding the visitor's
    /// `clavenar_demo_session` cookie so HIL scopes the analytics to their
    /// prefix server-side — a demo visitor never sees fleet-wide approver
    /// names or cross-tenant decision rates.
    pub async fn approvals_stats_scoped(
        &self,
        window: &str,
        demo_session_jwt: &str,
    ) -> Result<ApprovalStats, ClavenarError> {
        self.approvals_stats_inner(window, Some(demo_session_jwt))
            .await
    }

    async fn approvals_stats_inner(
        &self,
        window: &str,
        demo_session_jwt: Option<&str>,
    ) -> Result<ApprovalStats, ClavenarError> {
        let mut url = self.join("approvals/stats")?;
        url.query_pairs_mut().append_pair("window", window);
        if let Some(t) = &self.tenant {
            url.query_pairs_mut().append_pair("tenant", t);
        }

        let mut req = self.http.client().get(url);
        if let Some(jwt) = demo_session_jwt {
            req = req.header(
                reqwest::header::COOKIE,
                format!("{DEMO_SESSION_COOKIE}={jwt}"),
            );
        }
        let resp = req.send().await?;
        read_json(resp).await
    }

    /// `GET /pending/stream` — open the upstream SSE feed of pending
    /// lifecycle events (created / decided / expired). Returns the raw
    /// streaming `reqwest::Response` so the caller can pump the body
    /// without buffering — mirrors [`crate::LedgerClient`]'s
    /// `/stream/audit` usage pattern.
    pub async fn stream_pending(&self) -> Result<reqwest::Response, ClavenarError> {
        self.stream_pending_inner(None).await
    }

    /// As [`Self::stream_pending`], forwarding the visitor's
    /// `clavenar_demo_session` cookie so HIL re-verifies it and scopes the
    /// SSE feed to the prefix server-side. Callers should still drop
    /// off-prefix frames as defense-in-depth.
    pub async fn stream_pending_scoped(
        &self,
        demo_session_jwt: &str,
    ) -> Result<reqwest::Response, ClavenarError> {
        self.stream_pending_inner(Some(demo_session_jwt)).await
    }

    async fn stream_pending_inner(
        &self,
        demo_session_jwt: Option<&str>,
    ) -> Result<reqwest::Response, ClavenarError> {
        let mut url = self.join("pending/stream")?;
        if let Some(t) = &self.tenant {
            url.query_pairs_mut().append_pair("tenant", t);
        }
        let mut req = self
            .http
            .client()
            .get(url)
            .header(reqwest::header::ACCEPT, "text/event-stream");
        if let Some(jwt) = demo_session_jwt {
            req = req.header(
                reqwest::header::COOKIE,
                format!("{DEMO_SESSION_COOKIE}={jwt}"),
            );
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClavenarError::Server { status, body });
        }
        Ok(resp)
    }

    /// `POST /decide/{id}` with `decision=approve|deny|modify`.
    /// For `Modify`, `modified_payload` is required (HIL returns 400 if
    /// absent); pass `None` for plain approve/deny.
    ///
    /// `credential` selects which trust path is presented to HIL — see
    /// [`HilDecideCredential`]. `None` is the fallback for a HIL booted
    /// with `AUTH_DISABLED=true`, where HIL stamps the body's
    /// `decided_by` directly.
    // 8 args reflect the genuinely-coupled decide payload (decision,
    // human stamp, reason, modify body, assertion, credential trust
    // path). Bundling them into a builder struct would just shuffle
    // the same data through one extra type.
    #[allow(clippy::too_many_arguments)]
    pub async fn decide(
        &self,
        id: Uuid,
        decision: Decision,
        decided_by: &str,
        reason: Option<String>,
        modified_payload: Option<serde_json::Value>,
        approver_assertion: Option<serde_json::Value>,
        credential: Option<HilDecideCredential<'_>>,
        decided_via: Option<&str>,
    ) -> Result<PendingRequest, ClavenarError> {
        let url = self.join(&format!("decide/{id}"))?;
        let body = DecideRequest {
            decision,
            decided_by: decided_by.to_owned(),
            reason,
            modified_payload,
            approver_assertion,
            decided_via: decided_via.map(str::to_owned),
            tenant: self.tenant.clone(),
        };
        let mut req = self.http.client().post(url).json(&body);
        match credential {
            Some(HilDecideCredential::SessionCookie(cookie)) => {
                // WebAuthn mode: HIL gates `/decide/{id}` on
                // `clavenar_hil_session`; forward the value captured
                // during login.
                req = req.header(
                    reqwest::header::COOKIE,
                    format!("{HIL_SESSION_COOKIE}={cookie}"),
                );
            }
            Some(HilDecideCredential::Bearer {
                token,
                subject,
                method,
            }) => {
                let principal = ConsolePrincipalClaim {
                    subject,
                    tenant: self.tenant.as_deref().unwrap_or("unscoped"),
                    method,
                };
                let encoded = hex::encode(
                    serde_json::to_vec(&principal)
                        .expect("ConsolePrincipalClaim serialization is infallible"),
                );
                req = req
                    .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(DECISION_PRINCIPAL_HEADER, encoded);
            }
            Some(HilDecideCredential::DemoSession(jwt)) => {
                // Demo-session: forward the verified JWT via the same
                // cookie name HIL's middleware reads. HIL re-verifies
                // the signature and enforces the prefix-against-
                // correlation_id gate; `decided_by` on the request
                // body is ignored on this path — it's stamped from
                // the JWT's `sub` claim as `demo:<sub>`.
                req = req.header(
                    reqwest::header::COOKIE,
                    format!("{DEMO_SESSION_COOKIE}={jwt}"),
                );
            }
            None => {}
        }
        let resp = req.send().await?;
        read_json(resp).await
    }

    /// Proxy a `POST /auth/{sub}` call to HIL. Body is a JSON `Value`
    /// so the same method serves both `/start` (name + optional
    /// display_name) and `/finish` (browser-supplied credential). On
    /// the way out, attach the HIL ceremony cookie if one was passed;
    /// on the way back, surface every `Set-Cookie` header verbatim so
    /// the caller can extract HIL's `clavenar_hil_ceremony` /
    /// `clavenar_hil_session` values.
    ///
    /// The body is deliberately *not* parsed here — `/start` returns
    /// a `CreationChallengeResponse` or `RequestChallengeResponse`
    /// (which the browser hands to `navigator.credentials.*`), and
    /// `/finish` returns a one-shot `{ ok, name }` payload. Both are
    /// proxied as opaque JSON.
    pub async fn auth_proxy_post(
        &self,
        sub_path: &str,
        body: &serde_json::Value,
        hil_cookie: Option<&str>,
    ) -> Result<AuthProxyResponse, ClavenarError> {
        let url = self.join(&format!("auth/{sub_path}"))?;
        let mut req = self.http.client().post(url).json(body);
        if let Some(c) = hil_cookie {
            req = req.header(reqwest::header::COOKIE, c);
        }
        let resp = req.send().await?;
        let status = resp.status();

        // Capture every Set-Cookie value before we consume the body —
        // `resp.text().await` consumes self, and `headers()` borrows
        // self, so we must clone the headers we care about up-front.
        let set_cookies: Vec<String> = resp
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_string))
            .collect();

        let text = resp.text().await?;
        // Auth endpoints return JSON on success and a plain-text
        // diagnostic on error. The body is surfaced verbatim either
        // way; the caller maps a non-2xx into a 4xx for the browser.
        let body: serde_json::Value = if text.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or_else(|_| serde_json::Value::String(text.clone()))
        };
        Ok(AuthProxyResponse {
            status,
            body,
            set_cookies,
        })
    }

    /// `POST /identities/upsert` — bearer-gated cross-channel identity
    /// self-link mirror (see TECH_SPEC.md#operator-authentication
    /// §"Cross-channel identity"). Called once an IdP has handed back a
    /// verified `slack_user_id` / `teams_user_id`. `bearer` is the same
    /// `CLAVENAR_HIL_DECIDE_TOKEN` presented on `/decide` calls; the
    /// spec deliberately re-uses one secret for the trusted-caller ↔
    /// HIL path rather than introducing a second.
    pub async fn identities_upsert(
        &self,
        bearer: &str,
        oidc_sub: &str,
        slack_user_id: Option<&str>,
        teams_user_id: Option<&str>,
    ) -> Result<UserIdentities, ClavenarError> {
        let url = self.join("identities/upsert")?;
        let body = serde_json::json!({
            "oidc_sub": oidc_sub,
            "slack_user_id": slack_user_id,
            "teams_user_id": teams_user_id,
        });
        let resp = self
            .http
            .client()
            .post(url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {bearer}"))
            .json(&body)
            .send()
            .await?;
        read_json(resp).await
    }

    /// `GET /identities/{oidc_sub}` — bearer-gated read-back of the
    /// current link state without a cookie / OAuth dance. Returns
    /// `Ok(None)` for a 404 (the user hasn't linked any channel yet);
    /// other non-2xx surfaces as [`ClavenarError::Server`].
    pub async fn identities_get(
        &self,
        bearer: &str,
        oidc_sub: &str,
    ) -> Result<Option<UserIdentities>, ClavenarError> {
        let url = self.join(&format!("identities/{oidc_sub}"))?;
        let resp = self
            .http
            .client()
            .get(url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {bearer}"))
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        read_json(resp).await.map(Some)
    }

    /// `DELETE /identities/{oidc_sub}/slack` — bearer-gated unlink.
    /// Idempotent: deleting an already-unlinked entry returns
    /// `cleared: false` rather than 404, matching HIL's response shape
    /// so an "Unlink" button is safe to double-click.
    pub async fn identities_unlink_slack(
        &self,
        bearer: &str,
        oidc_sub: &str,
    ) -> Result<bool, ClavenarError> {
        self.identities_unlink(bearer, oidc_sub, "slack").await
    }

    /// `DELETE /identities/{oidc_sub}/teams` — symmetric to the Slack
    /// unlink. Same idempotent semantics; HIL drops the row when the
    /// last channel clears.
    pub async fn identities_unlink_teams(
        &self,
        bearer: &str,
        oidc_sub: &str,
    ) -> Result<bool, ClavenarError> {
        self.identities_unlink(bearer, oidc_sub, "teams").await
    }

    async fn identities_unlink(
        &self,
        bearer: &str,
        oidc_sub: &str,
        channel: &str,
    ) -> Result<bool, ClavenarError> {
        let url = self.join(&format!("identities/{oidc_sub}/{channel}"))?;
        let resp = self
            .http
            .client()
            .delete(url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {bearer}"))
            .send()
            .await?;
        let body: serde_json::Value = read_json(resp).await?;
        Ok(body
            .get("cleared")
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
    }

    fn join(&self, path: &str) -> Result<Url, ClavenarError> {
        self.base_url
            .join(path)
            .map_err(|e| ClavenarError::InvalidConfig(format!("join /{path}: {e}")))
    }
}

/// Non-2xx → [`ClavenarError::Server`] with the verbatim body (never
/// the typed 401/400 arms — HIL callers branch per status themselves);
/// 2xx bodies go through serde.
async fn read_json<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, ClavenarError> {
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(ClavenarError::Server { status, body });
    }
    serde_json::from_str(&body).map_err(ClavenarError::Decode)
}

/// Which notifier channels are live. Mirror of `clavenar_hil::notify::
/// ChannelStatus` — booleans + escalation-pool names, no secrets.
#[derive(Debug, Clone, Deserialize)]
pub struct ChannelStatus {
    pub slack: bool,
    pub teams: bool,
    pub pagerduty: bool,
    pub webhook: bool,
    pub smtp: bool,
    #[serde(default)]
    pub escalation_pools: Vec<String>,
}

/// Per-approver row in [`ApprovalStats`]. Mirror of the HIL
/// `ApproverStat` shape.
#[derive(Debug, Clone, Deserialize)]
pub struct ApproverStat {
    pub decided_by: String,
    pub count: u64,
    pub deny_rate: f64,
    #[serde(default)]
    pub median_secs: Option<f64>,
}

/// Read-only approver analytics from `GET /approvals/stats`. Mirror of
/// the HIL `ApprovalStats` shape.
#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalStats {
    pub window: String,
    pub pending_count: u64,
    #[serde(default)]
    pub oldest_pending_secs: Option<f64>,
    pub total_decided: u64,
    pub approved: u64,
    pub modified: u64,
    pub denied: u64,
    pub expired: u64,
    #[serde(default)]
    pub deny_rate: Option<f64>,
    #[serde(default)]
    pub median_time_to_decide_secs: Option<f64>,
    #[serde(default)]
    pub p95_time_to_decide_secs: Option<f64>,
    #[serde(default)]
    pub by_approver: Vec<ApproverStat>,
}

/// Mirror of `clavenar_hil::identities::UserIdentities`. The
/// timestamps power a "Linked Apr 4, last verified Apr 12" line.
#[derive(Debug, Clone, Deserialize)]
pub struct UserIdentities {
    pub oidc_sub: String,
    #[serde(default)]
    pub slack_user_id: Option<String>,
    #[serde(default)]
    pub teams_user_id: Option<String>,
    pub linked_at: DateTime<Utc>,
    pub last_verified: DateTime<Utc>,
}

/// Response from [`HilClient::auth_proxy_post`]. `body` is handed back
/// to the browser verbatim; `set_cookies` carry every `Set-Cookie`
/// header so the caller can extract the relevant HIL cookie values
/// (`clavenar_hil_ceremony`, `clavenar_hil_session`).
#[derive(Debug, Clone)]
pub struct AuthProxyResponse {
    pub status: StatusCode,
    pub body: serde_json::Value,
    pub set_cookies: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_request_round_trips_minimal() {
        let raw = serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "correlation_id": "11111111-2222-3333-4444-555555555555",
            "agent_id": "demo-bot",
            "method": "tools/call",
            "request_payload": {"name":"wire_transfer"},
            "risk_summary": "Wire transfer requested",
            "created_at": "2026-05-02T12:34:56Z",
            "ttl_seconds": 300,
            "status": "pending"
        });
        let parsed: PendingRequest = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.status, PendingStatus::Pending);
        assert!(parsed.decided_by.is_none());
    }

    #[test]
    fn pending_request_carries_sandbox_report_when_present() {
        // HIL responses with a sandbox_report must round-trip the
        // field as opaque JSON; the transport doesn't validate the
        // shape — callers project it into their own typed view.
        let raw = serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "correlation_id": "11111111-2222-3333-4444-555555555555",
            "agent_id": "demo-bot",
            "method": "delete_file",
            "request_payload": {"path": "/var/log/audit.log"},
            "risk_summary": "log deletion",
            "created_at": "2026-05-02T12:34:56Z",
            "ttl_seconds": 300,
            "status": "pending",
            "sandbox_report": {
                "operation_class": "delete",
                "severity": "destructive",
                "targets": ["/var/log/audit.log"],
                "summary": "delete file `/var/log/audit.log`",
                "predicted_changes": [
                    {"kind":"delete","target":"/var/log/audit.log"}
                ]
            }
        });
        let parsed: PendingRequest = serde_json::from_value(raw).unwrap();
        let report = parsed.sandbox_report.unwrap();
        assert_eq!(report["severity"], "destructive");
        assert_eq!(report["operation_class"], "delete");
    }

    #[test]
    fn pending_request_carries_quorum_and_assignment_fields() {
        // A multi-approver row with one partial approval recorded must
        // round-trip the quorum + hand-off fields.
        let raw = serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "correlation_id": "11111111-2222-3333-4444-555555555555",
            "agent_id": "agent-quorum",
            "method": "wire_transfer",
            "request_payload": {"amount": 50000},
            "risk_summary": "two-person rule",
            "created_at": "2026-05-02T12:34:56Z",
            "ttl_seconds": 600,
            "status": "pending",
            "required_approvers": 2,
            "approvals": [{"by": "oidc:alice", "provenance": "oidc", "at": "2026-05-02T12:35:00Z"}],
            "assigned_to": "oidc:bob",
            "escalation_pool": "oncall"
        });
        let parsed: PendingRequest = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.required_approvers, Some(2));
        assert_eq!(
            parsed
                .approvals
                .as_ref()
                .and_then(|v| v.as_array())
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(parsed.assigned_to.as_deref(), Some("oidc:bob"));
        assert_eq!(parsed.escalation_pool.as_deref(), Some("oncall"));
    }

    #[test]
    fn decision_serializes_lowercase() {
        let body = DecideRequest {
            decision: Decision::Approve,
            decided_by: "clavenar-console".into(),
            reason: None,
            modified_payload: None,
            approver_assertion: None,
            decided_via: None,
            tenant: None,
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"decision\":\"approve\""));
        assert!(!json.contains("\"reason\""));
        // Plain approve must not leak `modified_payload` onto the
        // wire — HIL distinguishes "approve+drop_rewrite" from "modify"
        // by the absence of the field, so we verify it's not there.
        assert!(!json.contains("\"modified_payload\""));
        assert!(!json.contains("\"approver_assertion\""));
    }

    #[test]
    fn modify_serializes_with_payload() {
        let body = DecideRequest {
            decision: Decision::Modify,
            decided_by: "clavenar-console".into(),
            reason: Some("capped per policy".into()),
            modified_payload: Some(serde_json::json!({"amount": 100})),
            approver_assertion: None,
            decided_via: None,
            tenant: None,
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"decision\":\"modify\""));
        assert!(json.contains("\"modified_payload\""));
        assert!(json.contains("\"amount\":100"));
    }

    #[test]
    fn status_labels_are_capitalised() {
        assert_eq!(PendingStatus::Pending.label(), "Pending");
        assert_eq!(PendingStatus::Approved.label(), "Approved");
    }

    #[test]
    fn hil_client_surfaces_configured_base_url() {
        let client = HilClient::new("http://hil:8084").unwrap();
        assert_eq!(client.base_url().as_str(), "http://hil:8084/");
    }
}

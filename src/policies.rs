//! Async client for `clavenar-policy-engine`'s console-policy-management
//! surface (clavenar-specs/TECH_SPEC.md#console-policy-management §5).
//!
//! Mirrors the server-side handlers in
//! `clavenar-policy-engine::write_api` and `lib.rs`: every method here
//! corresponds 1:1 with a route there. Used by `clavenar-console`'s
//! `/policies` UI and (eventually) by `clavenarctl policies …`.
//!
//! ## Auth model
//!
//! `clavenar-policy-engine` does not terminate auth itself — it trusts
//! whoever can reach :8082, which in deployment is only the proxy and
//! console (internal-network mTLS). The `bearer` field is therefore
//! optional and unused by the server today; we keep it for symmetry
//! with `AgentsClient` and to be future-proof when policy-engine grows
//! a caller allowlist.
//!
//! ## Wire types
//!
//! [`PolicyRow`], [`PolicyVersionRow`], [`PolicyDetail`], [`MutationResponse`]
//! and the request bodies are duplicated verbatim from the server. The
//! "shared types are not in a common crate" repo invariant applies —
//! grep `clavenar-policy-engine`, `clavenar-sdk`, `clavenar-console`, and
//! `clavenarctl` before any rename.

use std::sync::Arc;

use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};

use crate::ClavenarError;
use crate::http::{
    HttpProvider, StaticHttpClient, decode_response, default_provider, parse_base_url,
    percent_encode,
};

/// One row of the `policies` table — current state of a managed
/// policy file.
///
/// Frontmatter fields (`domain` through `summary`) are populated by
/// the engine's seed/refresh pipeline from the `.rego` file's top
/// comment block. They carry `#[serde(default)]` so callers built
/// against a pre-frontmatter engine still deserialize the older
/// `policies` payload shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRow {
    pub name: String,
    pub content_type: String,
    pub active: bool,
    /// `true` for the baseline floor — always-active, refuses
    /// deactivate / delete. `#[serde(default)]` so older engine
    /// payloads (pre-protected) still deserialize as unprotected.
    #[serde(default)]
    pub protected: bool,
    pub current_version: i64,
    pub deleted_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub frameworks: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub tool_surface: Vec<String>,
    #[serde(default)]
    pub summary: Option<String>,
}

/// One row of `policy_versions` — append-only body history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersionRow {
    pub name: String,
    pub version: i64,
    pub body: String,
    pub body_sha256: String,
    pub reason: String,
    pub actor_sub: String,
    pub actor_idp: String,
    pub chain_seq: Option<i64>,
    pub created_at: String,
}

/// `GET /policies/{name}` envelope: `PolicyRow` flattened in,
/// plus the body of `current_version` so the console can render the
/// detail page in one round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDetail {
    #[serde(flatten)]
    pub policy: PolicyRow,
    pub current_body: String,
    pub current_body_sha256: String,
}

/// Body of a successful mutation (`POST /policies`,
/// `PUT /policies/{name}`, etc.). Returned alongside `200`/`201`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationResponse {
    pub name: String,
    pub version: i64,
    pub body_sha256: String,
    pub current_version: i64,
    pub active: bool,
    pub event_kind: String,
}

/// Body of a 409 from `PUT /policies/{name}` (and similar). The
/// embedded `policy` carries the up-to-date state so the caller can
/// re-render their editor against it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictResponse {
    pub error: String,
    pub policy: PolicyRow,
}

// ── Request bodies ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct CreatePolicyRequest<'a> {
    pub name: &'a str,
    pub content_type: &'a str,
    pub body: &'a str,
    pub reason: &'a str,
    pub actor_sub: &'a str,
    pub actor_idp: &'a str,
    /// Optional draft mode. Pre-Phase-7 callers omit this field and
    /// the server defaults to `active=true`. Phase-7 Self-Learn flow
    /// sets `Some(false)` so accepted candidates require an explicit
    /// Activate step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdatePolicyRequest<'a> {
    pub body: &'a str,
    pub reason: &'a str,
    pub actor_sub: &'a str,
    pub actor_idp: &'a str,
    pub expected_current_version: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StateChangeRequest<'a> {
    pub reason: &'a str,
    pub actor_sub: &'a str,
    pub actor_idp: &'a str,
    pub expected_current_version: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RollbackRequest<'a> {
    pub reason: &'a str,
    pub actor_sub: &'a str,
    pub actor_idp: &'a str,
}

/// Body for the category sweeps
/// (`POST /policies/categories/{domain}/{activate,deactivate}`). No
/// `expected_current_version` — a category sweep can't pin a per-row
/// concurrency token.
#[derive(Debug, Clone, Serialize)]
pub struct BatchStateChangeRequest<'a> {
    pub reason: &'a str,
    pub actor_sub: &'a str,
    pub actor_idp: &'a str,
}

/// Response from a category sweep: how many rows flipped (`changed`,
/// one `MutationResponse` each in `results`) vs were left as-is
/// (`skipped` — already in target state or protected).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchMutationResponse {
    pub changed: usize,
    pub skipped: usize,
    pub results: Vec<MutationResponse>,
}

// ── Response wrappers (read endpoints) ────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoliciesListResponse {
    pub policies: Vec<PolicyRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionsListResponse {
    pub versions: Vec<PolicyVersionRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResponse {
    pub name: String,
    pub from: i64,
    pub to: i64,
    pub diff: String,
}

// ── Policy Lab (evaluate-batch) wire types ────────────────────────────

/// Replay-corpus PolicyInput shape used by `evaluate_batch`. Mirrors
/// the policy-engine's `wire::PolicyInput` field-for-field; carried as
/// a Value here so adding a field server-side is non-breaking for SDK
/// consumers. Set this from the corpus entry returned by
/// [`crate::LedgerClient::replay_corpus`].
pub type PolicyInputJson = serde_json::Value;

/// Mode for the candidate Rego rule in
/// [`PoliciesClient::evaluate_batch`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BatchMode {
    /// Add the candidate alongside the active set.
    Add,
    /// Drop the named active rule before adding the candidate.
    Replace,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffClass {
    AllowToDeny,
    AllowToYellow,
    DenyToAllow,
    YellowToAllow,
    YellowToDeny,
    DenyToYellow,
    Unchanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerdict {
    pub allow: bool,
    pub reasons: Vec<String>,
    #[serde(default)]
    pub review_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerdictResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// The reconstructed Rego input the candidate rule evaluated,
    /// echoed by the policy-engine so the Lab can show what the rule
    /// keyed on. `None` against an older engine that doesn't echo it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<serde_json::Value>,
    pub before: BatchVerdict,
    pub after: BatchVerdict,
    pub diff: DiffClass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateBatchRequest {
    pub candidate_rego: String,
    pub candidate_name: String,
    pub mode: BatchMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_rule_name: Option<String>,
    pub inputs: Vec<PolicyInputJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateBatchResponse {
    pub active_compile_ok: bool,
    pub candidate_compile_ok: bool,
    pub results: Vec<BatchVerdictResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompileError {
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateBatchError {
    pub active_compile_ok: bool,
    pub candidate_compile_ok: bool,
    pub compile_error: CompileError,
}

/// Parse a 400 body from `evaluate_batch` into a typed
/// [`EvaluateBatchError`]. Returns `None` when the body isn't a
/// compile error (e.g. an envelope-level validation error from a
/// future server version).
pub fn parse_batch_error(body: &str) -> Option<EvaluateBatchError> {
    serde_json::from_str(body).ok()
}

// ── Self-Learn miner (Phase 7) ────────────────────────────────────────

/// Same shape as the active-engine [`BatchVerdict`] — kept distinct so
/// that the miner's diff tile counts can evolve without changing the
/// Lab wire format.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MineLabReplay {
    pub allow_to_deny: u32,
    pub allow_to_yellow: u32,
    pub deny_to_allow: u32,
    pub deny_to_yellow: u32,
    pub yellow_to_allow: u32,
    pub yellow_to_deny: u32,
    pub unchanged: u32,
    pub catalog_regressions: u32,
}

/// A single candidate rule the miner proposes. The console renders
/// these as cards; operator Accept lands the `rego_body` as a draft
/// policy via the existing `POST /policies` create path with
/// `active=false`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MineCandidate {
    pub id: String,
    pub kind: String,
    pub rule_name: String,
    pub one_liner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    #[serde(default)]
    pub brain_enriched: bool,
    pub rego_body: String,
    pub compile_ok: bool,
    pub evidence_count: u32,
    pub score: f32,
    pub lab_replay: MineLabReplay,
}

/// `POST /policies/mine` request. The console + ctl construct the
/// corpus by calling [`crate::LedgerClient::replay_corpus`] first and
/// forwarding the result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MineRequest {
    pub corpus: Vec<PolicyInputJson>,
    #[serde(default)]
    pub historical_verdicts: Vec<BatchVerdict>,
    pub max_candidates: u32,
    pub ask_brain: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MineResponse {
    pub candidates: Vec<MineCandidate>,
    pub corpus_size: u32,
    pub candidates_dropped: u32,
    pub evaluated_in_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MineError {
    pub message: String,
}

/// Parse a 400 body from `mine` into a typed [`MineError`]. Returns
/// `None` when the body shape doesn't match (e.g. a future server
/// emitting a different envelope).
pub fn parse_mine_error(body: &str) -> Option<MineError> {
    serde_json::from_str(body).ok()
}

// ── Library catalog (templates) ───────────────────────────────────────
//
// Mirror types for the `/policies/templates*` surface on
// `clavenar-policy-engine`. Templates are on-disk starter policies that
// live in `<policy_dir>/templates/`; the library endpoints read their
// frontmatter, join against the installed-set in SQLite, and proxy
// install/lab to the same write/batch paths managed policies use.

/// One row in the catalog listing
/// (`GET /policies/templates`). The seven frontmatter fields mirror
/// [`PolicyRow`]; the `installed` flag is `true` when a policy with
/// the same `name` exists in the active set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTemplate {
    pub name: String,
    pub content_type: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub frameworks: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub tool_surface: Vec<String>,
    #[serde(default)]
    pub summary: Option<String>,
    pub installed: bool,
}

/// `GET /policies/templates/{name}` envelope: `PolicyTemplate`
/// flattened in plus the body of the rego/json file and its sha256,
/// so the console's detail page renders the source + keys the auto-
/// Lab against a stable body hash in one round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTemplateDetail {
    #[serde(flatten)]
    pub template: PolicyTemplate,
    pub body: String,
    pub body_sha256: String,
}

/// Body of `POST /policies/templates/{name}/install`. Same audit
/// fields as `CreatePolicyRequest` minus `name`/`content_type`/`body`
/// — those come from the template file.
#[derive(Debug, Clone, Serialize)]
pub struct InstallTemplateRequest<'a> {
    pub reason: &'a str,
    pub actor_sub: &'a str,
    pub actor_idp: &'a str,
}

/// Body of `POST /policies/templates/{name}/lab`. Same diff
/// envelope as [`evaluate_batch`](PoliciesClient::evaluate_batch) but
/// the candidate body comes from the path-named template on disk —
/// the caller only supplies the corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabTemplateRequest {
    /// Defaults to `Add` server-side when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<BatchMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_rule_name: Option<String>,
    pub inputs: Vec<PolicyInputJson>,
}

// ── Client ────────────────────────────────────────────────────────────

/// Cheap to clone — the inner `reqwest::Client` is `Arc`-based, same
/// as `AgentsClient`. Enables `Arc<AppState>` patterns where the
/// console embeds the SDK client directly in shared state.
#[derive(Debug, Clone)]
pub struct PoliciesClient {
    base_url: Url,
    http: Arc<dyn HttpProvider>,
    bearer: Option<String>,
    /// When set, every CRUD call carries `?tenant=<prefix>` so the
    /// policy engine reads/writes the named tenant's editable namespace
    /// (list/get also surface the read-only protected base). The console
    /// pins this from a demo visitor's session cookie — never a client-
    /// supplied value — so a demo edit can only touch its own tenant.
    tenant: Option<String>,
}

/// Body for [`PoliciesClient::validate`].
#[derive(Debug, serde::Serialize)]
pub struct ValidatePolicyRequest<'a> {
    pub name: &'a str,
    pub content_type: &'a str,
    pub body: &'a str,
}

/// Result of [`PoliciesClient::validate`].
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ValidatePolicyResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<CompileError>,
}

impl PoliciesClient {
    /// Build a client against `base_url` (e.g. `http://localhost:8082`).
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, ClavenarError> {
        let url = parse_base_url(base_url.as_ref())?;
        let http = default_provider()?;
        Ok(Self {
            base_url: url,
            http,
            bearer: None,
            tenant: None,
        })
    }

    pub fn with_http_client(self, client: Client) -> Self {
        self.with_http_provider(Arc::new(StaticHttpClient::new(client)))
    }

    /// Inject a custom [`HttpProvider`] for hot-reloading credentials.
    /// See [`LedgerClient::with_http_provider`] for the trade-offs.
    pub fn with_http_provider(mut self, provider: Arc<dyn HttpProvider>) -> Self {
        self.http = provider;
        self
    }

    pub fn with_bearer(mut self, token: impl Into<String>) -> Self {
        self.bearer = Some(token.into());
        self
    }

    /// Return a tenant-scoped view of this client: every subsequent CRUD
    /// call carries `?tenant=<prefix>`. Cheap clone (all inner state is
    /// `Arc` / small). Pass the demo visitor's cookie-derived prefix —
    /// never a client-supplied tenant.
    pub fn with_tenant(mut self, tenant: Option<String>) -> Self {
        self.tenant = tenant;
        self
    }

    /// `POST /policies/tenant/{prefix}/provision` — idempotently create a
    /// tenant's editable copy of the active policy set. Called best-effort
    /// at demo-session exchange; safe to call repeatedly. Does NOT carry
    /// the `?tenant=` query (the prefix is in the path).
    pub async fn provision_tenant(&self, prefix: &str) -> Result<(), ClavenarError> {
        let url = self
            .base_url
            .join(&format!(
                "policies/tenant/{}/provision",
                percent_encode(prefix)
            ))
            .map_err(|e| ClavenarError::InvalidConfig(format!("join provision: {e}")))?;
        let mut req = self.http.client().post(url);
        if let Some(token) = self.bearer.as_ref() {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(ClavenarError::Server { status, body })
        }
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub fn has_bearer(&self) -> bool {
        self.bearer.is_some()
    }

    // ── Read API ─────────────────────────────────────────────────

    /// `GET /policies?include_deleted=<bool>`. Default: hide soft-deleted.
    pub async fn list(&self, include_deleted: bool) -> Result<Vec<PolicyRow>, ClavenarError> {
        let mut url = self.join("policies")?;
        if include_deleted {
            url.query_pairs_mut().append_pair("include_deleted", "true");
        }
        let resp: PoliciesListResponse = self.get_json(url).await?;
        Ok(resp.policies)
    }

    /// `GET /policies/{name}` — current row + body.
    pub async fn get(&self, name: &str) -> Result<PolicyDetail, ClavenarError> {
        let url = self.join(&format!("policies/{}", percent_encode(name)))?;
        self.get_json(url).await
    }

    /// `GET /policies/{name}/versions` — newest first.
    pub async fn list_versions(&self, name: &str) -> Result<Vec<PolicyVersionRow>, ClavenarError> {
        let url = self.join(&format!("policies/{}/versions", percent_encode(name)))?;
        let resp: VersionsListResponse = self.get_json(url).await?;
        Ok(resp.versions)
    }

    /// `GET /policies/{name}/versions/{n}` — one historical version.
    pub async fn get_version(
        &self,
        name: &str,
        version: i64,
    ) -> Result<PolicyVersionRow, ClavenarError> {
        let url = self.join(&format!(
            "policies/{}/versions/{}",
            percent_encode(name),
            version
        ))?;
        self.get_json(url).await
    }

    /// `GET /policies/{name}/diff?from=N&to=M` — unified diff between
    /// two versions, suitable for rendering in the console's edit-
    /// confirmation modal.
    pub async fn diff(
        &self,
        name: &str,
        from: i64,
        to: i64,
    ) -> Result<DiffResponse, ClavenarError> {
        let mut url = self.join(&format!("policies/{}/diff", percent_encode(name)))?;
        url.query_pairs_mut()
            .append_pair("from", &from.to_string())
            .append_pair("to", &to.to_string());
        self.get_json(url).await
    }

    // ── Write API (Admin in the console) ─────────────────────────

    /// `POST /policies` — create a new managed policy. Returns
    /// 400 on regorus compile / JSON Schema error; 409 if `name`
    /// already exists.
    pub async fn create(
        &self,
        req: &CreatePolicyRequest<'_>,
    ) -> Result<MutationResponse, ClavenarError> {
        let url = self.join("policies")?;
        self.send_json(reqwest::Method::POST, url, req).await
    }

    /// `POST /policies/validate` — compile-check a draft body without
    /// saving it, for a console "check syntax" action. Always returns
    /// 200 with `{ ok, error? }` (a compile failure is a normal
    /// answer, not an HTTP error).
    pub async fn validate(
        &self,
        req: &ValidatePolicyRequest<'_>,
    ) -> Result<ValidatePolicyResponse, ClavenarError> {
        let url = self.join("policies/validate")?;
        self.send_json(reqwest::Method::POST, url, req).await
    }

    /// `PUT /policies/{name}` — update body. 409 on
    /// `expected_current_version` mismatch carries [`ConflictResponse`]
    /// in `ClavenarError::Server.body`.
    pub async fn update(
        &self,
        name: &str,
        req: &UpdatePolicyRequest<'_>,
    ) -> Result<MutationResponse, ClavenarError> {
        let url = self.join(&format!("policies/{}", percent_encode(name)))?;
        self.send_json(reqwest::Method::PUT, url, req).await
    }

    pub async fn activate(
        &self,
        name: &str,
        req: &StateChangeRequest<'_>,
    ) -> Result<MutationResponse, ClavenarError> {
        let url = self.join(&format!("policies/{}/activate", percent_encode(name)))?;
        self.send_json(reqwest::Method::POST, url, req).await
    }

    pub async fn deactivate(
        &self,
        name: &str,
        req: &StateChangeRequest<'_>,
    ) -> Result<MutationResponse, ClavenarError> {
        let url = self.join(&format!("policies/{}/deactivate", percent_encode(name)))?;
        self.send_json(reqwest::Method::POST, url, req).await
    }

    /// `POST /policies/categories/{domain}/activate` — install every
    /// policy in a category in one transaction + one engine rebuild.
    pub async fn activate_category(
        &self,
        domain: &str,
        req: &BatchStateChangeRequest<'_>,
    ) -> Result<BatchMutationResponse, ClavenarError> {
        let url = self.join(&format!(
            "policies/categories/{}/activate",
            percent_encode(domain)
        ))?;
        self.send_json(reqwest::Method::POST, url, req).await
    }

    /// `POST /policies/categories/{domain}/deactivate` — uninstall a
    /// whole category (protected floor rows are skipped, never flipped).
    pub async fn deactivate_category(
        &self,
        domain: &str,
        req: &BatchStateChangeRequest<'_>,
    ) -> Result<BatchMutationResponse, ClavenarError> {
        let url = self.join(&format!(
            "policies/categories/{}/deactivate",
            percent_encode(domain)
        ))?;
        self.send_json(reqwest::Method::POST, url, req).await
    }

    /// `DELETE /policies/{name}` — soft delete. Body is a
    /// [`StateChangeRequest`] (reason + expected_current_version).
    pub async fn delete(
        &self,
        name: &str,
        req: &StateChangeRequest<'_>,
    ) -> Result<MutationResponse, ClavenarError> {
        let url = self.join(&format!("policies/{}", percent_encode(name)))?;
        self.send_json(reqwest::Method::DELETE, url, req).await
    }

    /// `POST /policies/evaluate-batch` — Policy Lab batch evaluator.
    /// Sends a candidate Rego rule + a list of `PolicyInput`s; the
    /// policy-engine compiles an ephemeral engine that includes the
    /// candidate and returns the per-input verdict diff against the
    /// active engine.
    ///
    /// `ClavenarError::Server { status: 400, body }` carries the
    /// structured [`EvaluateBatchError`] (compile error with line/col)
    /// when the candidate fails to parse; call [`parse_batch_error`]
    /// to lift it out.
    pub async fn evaluate_batch(
        &self,
        req: &EvaluateBatchRequest,
    ) -> Result<EvaluateBatchResponse, ClavenarError> {
        let url = self.join("policies/evaluate-batch")?;
        self.send_json(reqwest::Method::POST, url, req).await
    }

    /// `POST /policies/mine` — Self-Learn miner (Phase 7). Sends a
    /// corpus + historical verdicts; the policy-engine runs its
    /// detectors, renders each pattern into a candidate Rego rule,
    /// scores it via the same evaluate-batch pipeline, and returns
    /// a ranked list. Brain optionally enriches each candidate with
    /// a natural-language one-liner + rationale.
    ///
    /// `ClavenarError::Server { status: 400, body }` carries
    /// [`MineError`] (corpus malformed, too large, etc.); call
    /// [`parse_mine_error`] to lift it out.
    pub async fn mine(&self, req: &MineRequest) -> Result<MineResponse, ClavenarError> {
        let url = self.join("policies/mine")?;
        self.send_json(reqwest::Method::POST, url, req).await
    }

    // ── Library catalog ──────────────────────────────────────────

    /// `GET /policies/templates` — list every starter template in the
    /// engine's on-disk catalog, ordered by name. Each entry carries
    /// frontmatter metadata + an `installed` flag joined against the
    /// active policy set.
    pub async fn list_templates(&self) -> Result<Vec<PolicyTemplate>, ClavenarError> {
        let url = self.join("policies/templates")?;
        self.get_json(url).await
    }

    /// `GET /policies/templates/{name}` — one template's frontmatter,
    /// body, and body_sha256. 404 when the template file isn't on
    /// disk.
    pub async fn get_template(&self, name: &str) -> Result<PolicyTemplateDetail, ClavenarError> {
        let url = self.join(&format!("policies/templates/{}", percent_encode(name)))?;
        self.get_json(url).await
    }

    /// `POST /policies/templates/{name}/install` — copy a template
    /// into the active policy set. Returns the same
    /// [`MutationResponse`] as `create`; the ledger event kind is
    /// `policy.installed_from_template` rather than `policy.created`,
    /// so forensic queries can distinguish library installs from
    /// operator-authored creates.
    ///
    /// 404 when the template is missing; 409 when a policy with the
    /// same name is already installed.
    pub async fn install_template(
        &self,
        name: &str,
        req: &InstallTemplateRequest<'_>,
    ) -> Result<MutationResponse, ClavenarError> {
        let url = self.join(&format!(
            "policies/templates/{}/install",
            percent_encode(name)
        ))?;
        self.send_json(reqwest::Method::POST, url, req).await
    }

    /// `POST /policies/templates/{name}/lab` — run the template
    /// against a corpus of historical traffic without committing.
    /// Same diff envelope as `evaluate_batch`; the candidate body is
    /// read from disk so the caller only supplies the corpus.
    ///
    /// 404 when the template is missing — the error surfaces through
    /// [`EvaluateBatchError`] (`candidate_compile_ok = false`) so the
    /// console's existing Lab renderer needs no special-case branch.
    pub async fn lab_template(
        &self,
        name: &str,
        req: &LabTemplateRequest,
    ) -> Result<EvaluateBatchResponse, ClavenarError> {
        let url = self.join(&format!("policies/templates/{}/lab", percent_encode(name)))?;
        self.send_json(reqwest::Method::POST, url, req).await
    }

    /// `POST /policies/{name}/rollback/{version}` — recreate the
    /// body of `version` as a new version.
    pub async fn rollback(
        &self,
        name: &str,
        version: i64,
        req: &RollbackRequest<'_>,
    ) -> Result<MutationResponse, ClavenarError> {
        let url = self.join(&format!(
            "policies/{}/rollback/{}",
            percent_encode(name),
            version
        ))?;
        self.send_json(reqwest::Method::POST, url, req).await
    }

    /// Helper for a console row that just received a 409 from
    /// `update`/`activate`/`deactivate`/`delete` — parses the embedded
    /// [`ConflictResponse`] out of [`ClavenarError::Server.body`].
    /// Returns `None` when the body isn't a `ConflictResponse` (e.g.
    /// the 409 came from `create`'s `name already exists` arm, which
    /// is plain text).
    pub fn parse_conflict(body: &str) -> Option<ConflictResponse> {
        serde_json::from_str(body).ok()
    }

    // ── Internal helpers ─────────────────────────────────────────

    fn join(&self, suffix: &str) -> Result<Url, ClavenarError> {
        let mut url = self
            .base_url
            .join(suffix)
            .map_err(|e| ClavenarError::InvalidConfig(format!("join {suffix}: {e}")))?;
        // Single Url-construction chokepoint, so a tenant-scoped client
        // stamps `?tenant=` on every CRUD call without per-method churn.
        if let Some(tenant) = self.tenant.as_deref() {
            url.query_pairs_mut().append_pair("tenant", tenant);
        }
        Ok(url)
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: Url) -> Result<T, ClavenarError> {
        let mut req = self.http.client().get(url);
        if let Some(token) = self.bearer.as_ref() {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        decode_response(status, body)
    }

    async fn send_json<B: Serialize, T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        url: Url,
        body: &B,
    ) -> Result<T, ClavenarError> {
        let mut req = self.http.client().request(method, url).json(body);
        if let Some(token) = self.bearer.as_ref() {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
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
        match PoliciesClient::new("not a url") {
            Ok(_) => panic!("expected InvalidConfig"),
            Err(ClavenarError::InvalidConfig(_)) => {}
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn with_tenant_stamps_query_on_every_call() {
        let c = PoliciesClient::new("http://localhost:8082")
            .unwrap()
            .with_tenant(Some("deadbeef".into()));
        let url = c.join("policies/phi.rego").unwrap();
        assert_eq!(url.query(), Some("tenant=deadbeef"));
        // An untenanted client adds nothing.
        let c2 = PoliciesClient::new("http://localhost:8082").unwrap();
        assert!(c2.join("policies").unwrap().query().is_none());
    }

    #[test]
    fn parse_conflict_recovers_policy_row() {
        let body = serde_json::json!({
            "error": "version_conflict",
            "policy": {
                "name": "governance.rego",
                "content_type": "rego",
                "active": true,
                "current_version": 7,
                "deleted_at": null,
                "created_at": "2026-05-08T00:00:00Z",
                "updated_at": "2026-05-08T00:00:00Z"
            }
        })
        .to_string();
        let parsed = PoliciesClient::parse_conflict(&body).unwrap();
        assert_eq!(parsed.error, "version_conflict");
        assert_eq!(parsed.policy.current_version, 7);
        assert_eq!(parsed.policy.name, "governance.rego");
    }

    #[test]
    fn parse_conflict_returns_none_for_plain_text() {
        assert!(PoliciesClient::parse_conflict("policy already exists").is_none());
    }

    #[test]
    fn policy_row_round_trips_with_new_metadata() {
        let body = serde_json::json!({
            "name": "phi_egress.rego",
            "content_type": "rego",
            "active": true,
            "current_version": 1,
            "deleted_at": null,
            "created_at": "2026-05-20T00:00:00Z",
            "updated_at": "2026-05-20T00:00:00Z",
            "domain": "healthcare",
            "severity": "high",
            "frameworks": ["HIPAA", "HITRUST"],
            "tags": ["phi", "egress"],
            "tier": "deny",
            "tool_surface": ["phi_export", "send_email"],
            "summary": "Deny PHI exports."
        })
        .to_string();
        let row: PolicyRow = serde_json::from_str(&body).unwrap();
        assert_eq!(row.domain.as_deref(), Some("healthcare"));
        assert_eq!(row.frameworks, vec!["HIPAA", "HITRUST"]);
        assert_eq!(row.tool_surface, vec!["phi_export", "send_email"]);

        // Serialize back and parse again — full round-trip.
        let again = serde_json::to_string(&row).unwrap();
        let row2: PolicyRow = serde_json::from_str(&again).unwrap();
        assert_eq!(row2.domain, row.domain);
        assert_eq!(row2.tags, row.tags);
    }

    #[test]
    fn policy_template_deserializes_from_server_json() {
        let body = serde_json::json!({
            "name": "phi_egress.rego",
            "content_type": "rego",
            "domain": "healthcare",
            "severity": "high",
            "frameworks": ["HIPAA"],
            "tags": ["phi"],
            "tier": "deny",
            "tool_surface": ["phi_export"],
            "summary": "Deny PHI exports.",
            "installed": false
        })
        .to_string();
        let t: PolicyTemplate = serde_json::from_str(&body).unwrap();
        assert_eq!(t.name, "phi_egress.rego");
        assert!(!t.installed);
        assert_eq!(t.frameworks, vec!["HIPAA"]);
    }

    #[test]
    fn policy_template_detail_flatten_round_trips() {
        let body = serde_json::json!({
            "name": "phi_egress.rego",
            "content_type": "rego",
            "domain": "healthcare",
            "frameworks": [],
            "tags": [],
            "tool_surface": [],
            "installed": true,
            "body": "package clavenar.authz\ndefault allow := false\n",
            "body_sha256": "deadbeef"
        })
        .to_string();
        let d: PolicyTemplateDetail = serde_json::from_str(&body).unwrap();
        assert_eq!(d.template.name, "phi_egress.rego");
        assert_eq!(d.body_sha256, "deadbeef");
        assert!(d.body.starts_with("package clavenar.authz"));
        // Re-serializing keeps the flat shape (no `template: {...}` wrapper).
        let again = serde_json::to_string(&d).unwrap();
        assert!(again.contains("\"name\":\"phi_egress.rego\""));
        assert!(!again.contains("\"template\":{"));
    }

    #[test]
    fn install_template_request_serializes_with_audit_fields() {
        let req = InstallTemplateRequest {
            reason: "install phi_egress",
            actor_sub: "alice",
            actor_idp: "oidc:test",
        };
        let s = serde_json::to_value(&req).unwrap();
        assert_eq!(s["reason"], "install phi_egress");
        assert_eq!(s["actor_sub"], "alice");
        assert_eq!(s["actor_idp"], "oidc:test");
    }

    #[test]
    fn lab_template_request_omits_optional_fields_when_none() {
        let req = LabTemplateRequest {
            mode: None,
            replace_rule_name: None,
            inputs: vec![],
        };
        let s = serde_json::to_value(&req).unwrap();
        assert!(s.get("mode").is_none(), "mode should be skipped: {s}");
        assert!(
            s.get("replace_rule_name").is_none(),
            "replace_rule_name should be skipped: {s}"
        );
        assert_eq!(s["inputs"], serde_json::json!([]));
    }

    #[test]
    fn lab_template_request_serializes_mode_when_set() {
        let req = LabTemplateRequest {
            mode: Some(BatchMode::Replace),
            replace_rule_name: Some("phi_egress.rego".into()),
            inputs: vec![],
        };
        let s = serde_json::to_value(&req).unwrap();
        assert_eq!(s["mode"], "replace");
        assert_eq!(s["replace_rule_name"], "phi_egress.rego");
    }

    #[test]
    fn policy_row_back_compat_with_pre_frontmatter_engine() {
        // An older policy-engine (pre Step-1) returns a PolicyRow
        // without any of the seven catalog metadata fields. The SDK
        // must still deserialize it — that's the whole point of
        // marking the new fields `#[serde(default)]`.
        let body = serde_json::json!({
            "name": "governance.rego",
            "content_type": "rego",
            "active": true,
            "current_version": 1,
            "deleted_at": null,
            "created_at": "2026-04-01T00:00:00Z",
            "updated_at": "2026-04-01T00:00:00Z"
        })
        .to_string();
        let row: PolicyRow = serde_json::from_str(&body).unwrap();
        assert_eq!(row.name, "governance.rego");
        assert!(row.domain.is_none());
        assert!(row.frameworks.is_empty());
        assert!(row.tool_surface.is_empty());
        // Pre-protected payload defaults to unprotected.
        assert!(!row.protected);
    }

    #[test]
    fn policy_row_decodes_protected_flag() {
        let body = serde_json::json!({
            "name": "governance.rego",
            "content_type": "rego",
            "active": true,
            "protected": true,
            "current_version": 1,
            "deleted_at": null,
            "created_at": "2026-06-07T00:00:00Z",
            "updated_at": "2026-06-07T00:00:00Z"
        })
        .to_string();
        let row: PolicyRow = serde_json::from_str(&body).unwrap();
        assert!(row.protected);
    }

    #[test]
    fn batch_state_change_request_serializes() {
        let req = BatchStateChangeRequest {
            reason: "install finance",
            actor_sub: "alice",
            actor_idp: "oidc:test",
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["reason"], "install finance");
        assert_eq!(v["actor_sub"], "alice");
        // No expected_current_version on the batch shape.
        assert!(v.get("expected_current_version").is_none());
    }

    #[test]
    fn batch_mutation_response_decodes() {
        let body = serde_json::json!({
            "changed": 2,
            "skipped": 1,
            "results": [
                {"name": "a.rego", "version": 2, "body_sha256": "x",
                 "current_version": 2, "active": true, "event_kind": "policy.activated"},
                {"name": "b.rego", "version": 3, "body_sha256": "y",
                 "current_version": 3, "active": true, "event_kind": "policy.activated"}
            ]
        })
        .to_string();
        let resp: BatchMutationResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.changed, 2);
        assert_eq!(resp.skipped, 1);
        assert_eq!(resp.results.len(), 2);
        assert_eq!(resp.results[0].name, "a.rego");
    }
}

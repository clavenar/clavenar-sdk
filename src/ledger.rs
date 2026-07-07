//! Async client for the ledger's audit and verify endpoints.
//!
//! Six calls cover the operator's reconstruction surface:
//!
//! * [`LedgerClient::audit_correlation`] — the per-request join, used
//!   to pull every layer's row for a single original request. Each
//!   successful request lands two rows in the chain (proxy + policy);
//!   this is what stitches them.
//! * [`LedgerClient::audit_agent`] — every row in the chain that
//!   names a given agent CN, oldest first. Full-chain fetch — fine
//!   for compliance batch tooling.
//! * [`LedgerClient::audit_agent_paged`] — newest-first
//!   `?limit=&offset=` slice of the same data. Used by UI callers so
//!   memory scales with `per_page`, not chain depth.
//! * [`LedgerClient::audit_agent_count`] — total chain rows for the
//!   agent; pairs with `audit_agent_paged` to drive a paginated UI's
//!   total-pages count without a full row read.
//! * [`LedgerClient::verify`] — recompute every hash and check that
//!   the chain links up. Returns a [`VerifyResult`] mirroring what the
//!   server emits.
//! * [`LedgerClient::list_exports`] — bookkeeping list of cold-tier
//!   snapshots written so far (Parquet + manifest pointers). The
//!   console renders this as a browse-able table so operators don't
//!   have to `curl` the ledger directly.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ClavenarError;
use crate::http::{
    HttpProvider, StaticHttpClient, default_provider, parse_base_url, percent_encode,
};

/// One row from the ledger's hash chain. Fields and ordering mirror
/// the server-side `clavenar_ledger::LedgerEntry`. `correlation_id` is
/// `None` on rows produced by older publishers (pre-correlation-id);
/// new rows always carry it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub method: String,
    pub intent_category: String,
    pub authorized: bool,
    pub reasoning: String,
    pub policy_decision: Option<serde_json::Value>,
    pub seq: i64,
    pub prev_hash: String,
    pub entry_hash: String,
    #[serde(default)]
    pub correlation_id: Option<String>,
    /// Format the row's `entry_hash` was computed under. Old
    /// rows don't carry the field on the wire — `default_chain_version()`
    /// resolves it to `1`, matching what those rows were actually
    /// written under.
    #[serde(default = "default_chain_version")]
    pub chain_version: i64,
    /// Origin tag the proxy stamped on the forensic event when the
    /// `x-clavenar-source` request header was set. `Some("simulator")` for
    /// clavenar-simulator-driven traffic, `None` for real agents and for
    /// rows produced by publishers that don't yet stamp the field
    /// (policy engine, HIL — these inherit the request's source via
    /// `correlation_id` join, not via this column). UI affordance, not
    /// a security claim — see the warning in `clavenar_ledger`.
    #[serde(default)]
    pub source: Option<String>,
    /// Rejection / annotation signal (clavenar-specs/TECH_SPEC.md#agent-onboarding-wao §6.3 vocabulary):
    /// `unregistered_agent`, `scope_outside_envelope`,
    /// `yellow_scope_outside_envelope`, `agent_suspended`,
    /// `agent_decommissioned`, `attestation_kind_not_accepted`,
    /// `grant_expired`. `None` on every row that isn't gate-relevant.
    /// Drives the console's `/audit` filter chip and the "Register…"
    /// deep link on unregistered_agent rows.
    #[serde(default)]
    pub signal: Option<String>,
    /// Chain v3 — Clavenar Agent Onboarding lifecycle event kind
    /// (clavenar-specs/TECH_SPEC.md#agent-onboarding-wao §7.2). `None` on every v1/v2 row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_kind: Option<String>,
    /// v3 — Tenant the lifecycle row belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// v3 — Registered name of the agent the event applied to.
    /// Distinct from `agent_id` because v3 reuses the column for the
    /// `agents` table uuidv7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    /// v3 — OIDC `sub` of the human who triggered the lifecycle
    /// event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_sub: Option<String>,
    /// v3 — OIDC issuer string (e.g. `okta`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_idp: Option<String>,
    /// v3 — `sha256(canonical_payload_json)`. The bytes themselves
    /// live in the `entry_payloads` sibling table; `LifecycleRow`
    /// joins them onto the row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_sha256: Option<String>,
    /// Clavenar-issued signature over the v2 hashable. Carried as the
    /// Vault Transit envelope (`vault:v<N>:<base64>`); the verifier
    /// parses the envelope and checks against the JWKS-served
    /// public key for `key_id`. Hashable on v2 — tampering with the
    /// signature itself breaks the chain hash, so an attacker can't
    /// strip the signature without invalidating the row. Also set on
    /// v3 rows, signs over the lifecycle subset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// JWKS lookup hint for verifying [`Self::signature`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// v2 — SPIFFE id of the agent that produced this row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_spiffe: Option<String>,
    /// Per-decision approver claim. JSON-encoded blob whose
    /// shape varies by mode (see
    /// `clavenar_ledger::LedgerEntry::approver_assertion`):
    ///
    /// - WebAuthn: `{"method":"webauthn","credential_id":"…","iat":…}`
    /// - OIDC: `{"method":"oidc-session","sub":"…","iat":…}`
    /// - Basic: `{"method":"basic-admin","username":"…"}`
    ///
    /// `None` on rows that aren't HIL state-transitions and on
    /// legacy rows. Surfaced verbatim — consumers display alongside
    /// `decided_by` for the richer "who" claim. Excluded from chain
    /// hashing; the field is metadata, not an integrity primitive.
    #[serde(default)]
    pub approver_assertion: Option<String>,
    /// Chain v4 — `sha256(canonical_json(brain_evidence))` (EU AI Act
    /// Art 12). Set on a v4 verdict row whose publisher captured the
    /// Brain's deterministic inputs; the canonical evidence JSON lives
    /// in the ledger's `entry_payloads` table. Hashable on v4 (the chain
    /// commits to it); `None` on v1/v2/v3 rows. Mirrors
    /// `clavenar_ledger::LedgerEntry::brain_evidence_sha256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brain_evidence_sha256: Option<String>,
    /// Per-detector Brain confidence scores for this verdict (opaque
    /// JSON: injection / malicious-code / compromised-package / drift
    /// confidences + intent). Non-hashable annotation data — never a
    /// chain-integrity primitive. `None` on rows whose publisher
    /// captured no scores. Mirrors
    /// `clavenar_ledger::LedgerEntry::brain_scores`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brain_scores: Option<serde_json::Value>,
    /// SHA-256 (hex) of the canonical request `params` the proxy judged —
    /// a tamper-evident commitment to *what the agent sent*, never the
    /// payload itself. Non-hashable annotation. `None` on rows whose
    /// publisher captured no params. Mirrors
    /// `clavenar_ledger::LedgerEntry::tool_params_sha256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_params_sha256: Option<String>,
    /// SHA-256 (hex) of the presented mTLS leaf cert's DER — the
    /// credential generation that made the call. The proxy stamps it on
    /// every verdict row and identity stamps the identical hash at SVID
    /// issuance, so traffic attributes to a specific credential. Non-
    /// hashable annotation; `None` on rows whose publisher captured no
    /// cert. Mirrors `clavenar_ledger::LedgerEntry::credential_fingerprint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_fingerprint: Option<String>,
    /// Concrete MCP tool the verdict gated — `params.name` (e.g.
    /// `marketing.bulk_email`), distinct from `method` (the JSON-RPC
    /// envelope `call_tool`). Lets `/audit` surface *which tool* an agent
    /// invoked. Non-hashable annotation; `None` on rows whose publisher
    /// captured no tool name. Mirrors
    /// `clavenar_ledger::LedgerEntry::tool_name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
}

/// Lifecycle row + the per-event-kind payload bytes that the chain
/// row's `payload_sha256` commits to. Mirrors
/// `clavenar_ledger::LifecycleRow`. Powers the console's per-agent
/// timeline (clavenar-specs/TECH_SPEC.md#agent-onboarding-wao §10.1).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LifecycleRow {
    #[serde(flatten)]
    pub entry: LedgerEntry,
    /// `None` when the chain row is well-formed but the
    /// `entry_payloads` row is missing — surfaced rather than
    /// silently dropped so the console can render an explicit
    /// "payload missing" affordance.
    pub payload: Option<serde_json::Value>,
}

fn default_chain_version() -> i64 {
    1
}

/// One bookkeeping row from the ledger's `exports` table. Mirrors the
/// server-side `clavenar_ledger::export::ExportRecord`. Each row records
/// one cold-tier snapshot the export pipeline wrote out (Parquet data
/// blob + Iceberg manifest), with enough pointers for an operator to
/// fetch the artifacts and verify the SHA-256 themselves.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExportRecord {
    pub snapshot_id: Uuid,
    pub written_at: DateTime<Utc>,
    pub data_uri: String,
    pub manifest_uri: String,
    pub data_sha256: String,
    /// Size of the Parquet blob, bytes. `usize` mirrors the server.
    pub byte_size: usize,
    /// How many ledger rows landed in this snapshot.
    pub row_count: usize,
    /// First / last ledger `seq` covered by the snapshot. Useful when
    /// reconciling against the live chain — `[seq_lo, seq_hi]` is the
    /// inclusive range that's safe to prune from the hot tier.
    pub seq_lo: i64,
    pub seq_hi: i64,
}

/// Result of `POST /export`, the synchronous cold-tier export trigger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExportOutcome {
    NothingToExport,
    Wrote(ExportRecord),
}

/// Outcome of a chain re-hash. Mirrors `clavenar_ledger::VerifyResult`.
/// `valid=false` with `first_invalid_seq=Some(n)` means the entry at
/// `seq=n` is the first whose hash didn't match — that's a tamper.
/// `valid=false` with `unsupported_chain_version=Some(v)` means the
/// ledger has a row tagged with a chain version this binary doesn't
/// know how to verify — that's an "upgrade me" signal, not a tamper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub entries_checked: usize,
    pub first_invalid_seq: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsupported_chain_version: Option<i64>,
    /// External-anchor cross-checks (RFC 3161 / webhook notary roots vs the
    /// live chain). Empty when nothing is anchored or on the Postgres
    /// backend. Defaulted so older ledgers (no field) still decode.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchors: Vec<AnchorSummary>,
    /// `Some(true)` when an anchored root no longer matches the live chain —
    /// a rewrite-below-a-notarized-root signal that stands even when `valid`
    /// is true. `Some(false)` when anchors exist and all match; `None` when
    /// nothing is anchored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_mismatch: Option<bool>,
}

/// One anchored chain root surfaced on `GET /verify`. Mirrors
/// `clavenar_ledger::AnchorSummary` field-for-field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorSummary {
    pub anchored_seq: i64,
    pub anchored_entry_hash: String,
    pub source: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gen_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchored_at: Option<String>,
    /// `Some(true)` the live chain still matches the anchored root;
    /// `Some(false)` mismatch (tamper); `None` the row was vacuumed below
    /// the cold-tier cursor (verify the proof offline against the bundle).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_match: Option<bool>,
}

/// One row of the Policy Lab replay corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub captured_at: DateTime<Utc>,
    pub agent_id: String,
    pub method: String,
    /// Reconstructed PolicyInput shape. The client posts this back
    /// to the policy-engine's `evaluate-batch` endpoint under
    /// `inputs[]`. Opaque JSON — the policy-engine deserializes it.
    pub input: serde_json::Value,
    /// Verdict the policy engine recorded at the time of the
    /// originating call.
    pub historical_verdict: serde_json::Value,
}

/// `GET /audit/replay/corpus` response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayCorpus {
    pub corpus: Vec<CorpusEntry>,
    pub total_in_window: i64,
    pub returned: i64,
    pub sampled: bool,
}

/// Per-call params for [`LedgerClient::replay_corpus`]. Required:
/// `since`, `limit`. Optional: `until`, `agent_id`, `tool_type`,
/// `tenant_prefix`.
#[derive(Debug, Clone, Default)]
pub struct ReplayCorpusParams {
    pub since: chrono::DateTime<chrono::Utc>,
    pub until: Option<chrono::DateTime<chrono::Utc>>,
    pub agent_id: Option<String>,
    pub tool_type: Option<String>,
    /// Scope the corpus to one demo tenant: only rows whose
    /// `correlation_id`'s leading UUID group equals this 8-hex prefix.
    /// The console pins this from the visitor's session cookie so a demo
    /// Policy Lab / topology read never replays another tenant's traffic.
    pub tenant_prefix: Option<String>,
    pub limit: i64,
}

/// Per-call options for [`LedgerClient::regulatory_export`]. Boxed up
/// so adding a future slice 4+ field is non-breaking. Defaults to "no
/// readme, no exports" — i.e. the slice 1+2 shape.
#[derive(Debug, Clone, Default)]
pub struct RegulatoryExportOptions {
    /// Operator-supplied technical-documentation markdown. When
    /// `Some(bytes)`, the SDK uploads the bytes verbatim as the
    /// request body with `Content-Type: text/markdown`; the ledger
    /// embeds them as `technical_documentation.md` inside the
    /// bundle and commits to their sha256 + size in the manifest.
    /// The ledger caps the body at 1 MiB (413 above).
    pub readme: Option<Vec<u8>>,
    /// When `true`, the ledger scans its `exports` table and embeds
    /// Parquet pointers whose seq range overlaps the regulatory
    /// window. Empty pointers (no exports configured / no overlap)
    /// still serialize as an empty array on the wire so an auditor
    /// can distinguish "no overlap" from "didn't ask."
    pub include_exports: bool,
    /// When `true`, the ledger embeds an auto-derived EU AI Act Article
    /// 14/15 + SOC 2 / ISO 27001 `compliance_register.json` (manifest
    /// schema v4) and widens `article_scope` to cover Articles 14 + 15.
    /// Defaults to `false` — a plain Article 11/12 bundle.
    pub include_compliance: bool,
}

/// Whether a control's evidence is fully present, partial, or absent for
/// the window. Mirror of the ledger's `compliance::EvidenceStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Satisfied,
    Partial,
    NoData,
}

/// One control's derived evidence. `framework` is the auditor-facing
/// display string ("EU AI Act", "SOC 2", "ISO/IEC 27001"); `metric` is
/// an opaque control-specific JSON object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEvidence {
    pub control_id: String,
    pub framework: String,
    pub title: String,
    pub status: EvidenceStatus,
    pub metric: serde_json::Value,
    pub sample_seqs: Vec<i64>,
    pub narrative: String,
}

/// Chain-integrity summary embedded in the register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerifySummary {
    pub valid: bool,
    pub entries_checked: usize,
    pub first_invalid_seq: Option<i64>,
}

/// Half-open `[from, to)` window the register covers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterWindow {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

/// Live compliance evidence register. Mirror of the ledger's
/// `compliance::ComplianceRegister` (see
/// `clavenar-ledger/src/compliance.rs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRegister {
    pub schema_version: String,
    pub generated_at: DateTime<Utc>,
    pub window: RegisterWindow,
    pub row_count: usize,
    pub chain_verify: ChainVerifySummary,
    pub controls: Vec<ControlEvidence>,
    pub disclaimer: String,
}

/// Append payload for `POST /log` — the subset of the ledger's
/// `LogRequest` a non-proxy caller fills. The server defaults every
/// other field (chain version, signature, lifecycle columns) and
/// computes the hash chain, so a synthetic-traffic source need only
/// describe the logical decision. `policy_decision` is always
/// serialized (the server requires the field present) — pass
/// `Some(Value::Null)` rather than `None` if there is genuinely no
/// policy context.
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub agent_id: String,
    pub method: String,
    pub intent_category: String,
    pub authorized: bool,
    pub reasoning: String,
    pub policy_decision: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Receipt the ledger returns from `POST /log`: the chain position the
/// row landed at and its computed entry hash.
#[derive(Debug, Clone, Deserialize)]
pub struct LogReceipt {
    pub status: String,
    pub seq: i64,
    pub entry_hash: String,
}

/// Async client for the ledger HTTP surface.
///
/// Cheap to clone — the inner `Arc<dyn HttpProvider>` is `Arc`-based.
#[derive(Debug, Clone)]
pub struct LedgerClient {
    base_url: Url,
    http: Arc<dyn HttpProvider>,
}

/// One tool's windowed usage in [`EnvelopeAnalysis`].
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ToolUsage {
    pub tool_type: String,
    pub used_count: i64,
    /// `high` / `medium` / `low`, keyed to the call count.
    pub confidence: String,
}

/// Response from [`LedgerClient::envelope_analysis`].
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct EnvelopeAnalysis {
    pub agent_id: String,
    pub window_days: i64,
    pub since: String,
    pub until: String,
    pub total_calls: i64,
    pub used_tools: Vec<ToolUsage>,
}

/// One active-but-silent agent in [`SilentAgentsReport`].
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SilentAgent {
    pub agent_name: String,
    pub tenant: Option<String>,
    /// Last genuine tool-traffic timestamp, or `None` if never seen.
    pub last_activity: Option<String>,
    pub enrolled_at: String,
    pub silent_hours: i64,
    pub never_active: bool,
}

/// Response from [`LedgerClient::silent_agents`] — the Shadow-Agent-Radar
/// liveness read.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SilentAgentsReport {
    pub threshold_hours: i64,
    pub generated_at: String,
    pub silent_agents: Vec<SilentAgent>,
    pub active_total: usize,
}

/// One tool's share of a window in [`BehavioralBaseline`].
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ToolShare {
    pub tool_type: String,
    pub count: i64,
}

/// One window's behavioral profile in [`BehavioralBaseline`].
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BaselineWindowProfile {
    pub since: String,
    pub until: String,
    pub total: i64,
    pub authorized: i64,
    pub denied: i64,
    pub deny_rate: f64,
    pub intent_mean: f64,
    pub tool_mix: Vec<ToolShare>,
    /// 24 entries, UTC hour-of-day.
    pub hourly: Vec<i64>,
}

/// Per-dimension + overall deviation in [`BehavioralBaseline`], each `[0, 1]`.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BaselineDeviation {
    pub tool_mix: f64,
    pub hourly: f64,
    pub intent: f64,
    pub deny_rate: f64,
    pub overall: f64,
}

/// Window-over-window diff in [`BehavioralBaseline`] — the "what changed"
/// companion to the scalar [`BaselineDeviation`]. Deltas are signed
/// `recent − baseline`.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct WindowDiff {
    /// Tools in the recent window but absent from baseline, most-used first.
    pub new_tools: Vec<String>,
    /// Tools in the baseline window but absent from recent, most-used first.
    pub vanished_tools: Vec<String>,
    pub deny_rate_delta: f64,
    pub intent_delta: f64,
    pub total_delta: i64,
}

/// Response from [`LedgerClient::behavioral_baseline`] — a recent window
/// profiled against the immediately-prior baseline window, with a drift score.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BehavioralBaseline {
    pub agent_id: String,
    pub baseline_days: i64,
    pub recent_days: i64,
    pub baseline: BaselineWindowProfile,
    pub recent: BaselineWindowProfile,
    pub deviation: BaselineDeviation,
    /// New/vanished tools + signed rate deltas between the two windows.
    /// `#[serde(default)]` so a baseline response from a pre-window-diff
    /// ledger still deserializes (empty diff).
    #[serde(default)]
    pub diff: WindowDiff,
    pub drifted: bool,
    pub insufficient: bool,
}

/// One agent's row in [`FleetBehavioralDiff`].
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FleetDiffRow {
    pub agent_id: String,
    pub recent_total: i64,
    pub baseline_total: i64,
    pub deny_rate_delta: f64,
    pub intent_delta: f64,
    pub total_delta: i64,
    pub new_tools: Vec<String>,
    pub vanished_tools: Vec<String>,
    pub drift_overall: f64,
    pub drifted: bool,
    pub insufficient: bool,
}

/// Response from [`LedgerClient::fleet_behavioral_diff`] — every profiled
/// agent's recent-vs-prior window diff + drift, drift-descending.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FleetBehavioralDiff {
    pub baseline_days: i64,
    pub recent_days: i64,
    pub since_baseline: String,
    pub since_recent: String,
    pub now: String,
    pub agents: Vec<FleetDiffRow>,
    pub returned: i64,
}

/// One signal's share of a canary window's rejection-signal mix.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CanarySignalShare {
    pub signal: String,
    pub count: i64,
}

/// A Brain model identity attested in a canary window's on-chain evidence —
/// the per-detector `provider:model` map plus the build version.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CanaryModel {
    pub brain_version: String,
    pub mock_mode: bool,
    /// Detector → `provider:model`.
    pub provider_models: std::collections::BTreeMap<String, String>,
    pub observed: i64,
}

/// One side (before/after) of a model-upgrade canary comparison.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CanaryWindow {
    pub since: String,
    pub until: String,
    pub total: i64,
    pub authorized: i64,
    pub denied: i64,
    pub deny_rate: f64,
    pub intent_mean: f64,
    pub signal_mix: Vec<CanarySignalShare>,
    pub models: Vec<CanaryModel>,
    pub models_sampled: i64,
}

/// Signed `after − before` deltas across the canary cutover.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CanaryDeltas {
    pub deny_rate_delta: f64,
    pub intent_mean_delta: f64,
    pub total_delta: i64,
    pub new_signals: Vec<String>,
    pub vanished_signals: Vec<String>,
}

/// Response from [`LedgerClient::model_upgrade_canary`] — the before/after
/// windows around a Brain model change, the behavioral deltas, and whether
/// the dominant model identity flipped across the cutover.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ModelUpgradeCanary {
    pub cutover: String,
    pub window_hours: i64,
    pub before: CanaryWindow,
    pub after: CanaryWindow,
    pub deltas: CanaryDeltas,
    pub model_changed: bool,
    pub insufficient: bool,
}

/// Filters for [`LedgerClient::hunt`]. All optional except `limit`; an
/// empty `HuntParams { limit, ..Default::default() }` rolls up every
/// agent active in the chain.
#[derive(Debug, Clone, Default)]
pub struct HuntParams {
    /// Exact-match on the row's `method`.
    pub method: Option<String>,
    /// Exact-match on the `signal` column (rejection / egress vocabulary).
    pub signal: Option<String>,
    /// `Some(true)` authorized-only, `Some(false)` denied-only, `None` any.
    pub authorized: Option<bool>,
    /// Lower bound on the row timestamp — the selective, indexed filter.
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    /// Upper bound on the row timestamp.
    pub to: Option<chrono::DateTime<chrono::Utc>>,
    /// Max agent rows returned. Server-clamps to [1, 1000].
    pub limit: i64,
    /// Demo-session JWT. When set, the ledger scopes rows to the token's
    /// prefix before grouping by agent.
    pub demo_session_token: Option<String>,
    /// Authenticated-operator tenant. When set without a demo-session
    /// token, the ledger scopes rows to this tenant before grouping by
    /// agent.
    pub tenant: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AuditFilterParams {
    pub seq_from: Option<i64>,
    pub seq_to: Option<i64>,
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    pub to: Option<chrono::DateTime<chrono::Utc>>,
    pub methods: Vec<String>,
    pub original_method: Option<String>,
    pub reason: Option<String>,
    pub verdict: Option<String>,
    pub brain_delta: Option<String>,
}

impl AuditFilterParams {
    fn append_query(&self, path: &mut String) {
        if let Some(seq_from) = self.seq_from {
            path.push_str(&format!("&seq_from={seq_from}"));
        }
        if let Some(seq_to) = self.seq_to {
            path.push_str(&format!("&seq_to={seq_to}"));
        }
        if let Some(from) = self.from {
            path.push_str(&format!("&from={}", percent_encode(&from.to_rfc3339())));
        }
        if let Some(to) = self.to {
            path.push_str(&format!("&to={}", percent_encode(&to.to_rfc3339())));
        }
        if !self.methods.is_empty() {
            let methods = self
                .methods
                .iter()
                .filter(|m| !m.trim().is_empty())
                .map(|m| percent_encode(m))
                .collect::<Vec<_>>()
                .join(",");
            if !methods.is_empty() {
                path.push_str("&methods=");
                path.push_str(&methods);
            }
        }
        if let Some(value) = self.original_method.as_deref() {
            path.push_str(&format!("&original_method={}", percent_encode(value)));
        }
        if let Some(value) = self.reason.as_deref() {
            path.push_str(&format!("&reason={}", percent_encode(value)));
        }
        if let Some(value) = self.verdict.as_deref() {
            path.push_str(&format!("&verdict={}", percent_encode(value)));
        }
        if let Some(value) = self.brain_delta.as_deref() {
            path.push_str(&format!("&brain_delta={}", percent_encode(value)));
        }
    }
}

/// One agent's roll-up row in a [`HuntResult`].
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct HuntAgentRollup {
    pub agent_id: String,
    #[serde(default)]
    pub agent_name: Option<String>,
    /// Total rows this agent emitted in the filtered window.
    pub hit_count: i64,
    /// Of those, how many were denials (`authorized = false`).
    pub deny_count: i64,
    /// Highest-severity signal this agent emitted in the window, as a
    /// canonical signal string; `None` when no ranked signal was seen.
    #[serde(default)]
    pub worst_signal: Option<String>,
    /// Newest matching row's RFC 3339 timestamp.
    pub latest_hit_ts: String,
    /// Correlation id from the newest matching row for this agent.
    #[serde(default)]
    pub latest_correlation_id: Option<String>,
    /// Distinct methods this agent invoked in the window.
    #[serde(default)]
    pub methods: Vec<String>,
}

/// Response from [`LedgerClient::hunt`] — the fleet-wide incident
/// rollup, ordered worst-signal-first.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct HuntResult {
    pub agents: Vec<HuntAgentRollup>,
    /// `agents.len()`; compare against the requested `limit` to learn
    /// whether the server clamp bit.
    pub returned: i64,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
}

/// One agent's row in a [`SpendRollup`] — attributed spend over the
/// window plus priced-coverage counts (FinOps P3 dashboard).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SpendAgentRow {
    pub agent_id: String,
    #[serde(default)]
    pub agent_name: Option<String>,
    /// Summed `cost_micros` (micro-USD) over the window.
    pub spend_micros: i64,
    /// Rows this agent emitted in the window.
    pub request_count: i64,
    /// Of those, how many carried a priced (>0) estimate.
    pub priced_count: i64,
    #[serde(default)]
    pub latest_ts: Option<String>,
}

/// Response from [`LedgerClient::finops_spend`] — per-agent attributed
/// spend (top spenders first) plus fleet totals over the same window.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SpendRollup {
    #[serde(default)]
    pub window: Option<String>,
    pub agents: Vec<SpendAgentRow>,
    /// Fleet totals across every agent in the window (not just the
    /// returned top-N) — honest priced coverage + fleet spend.
    pub total_spend_micros: i64,
    pub total_requests: i64,
    pub total_priced: i64,
    pub returned: i64,
}

/// One entry in an incident case's activity timeline.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaseTimelineEvent {
    pub at: String,
    pub kind: String,
    pub actor: String,
    pub detail: String,
}

/// A persistent incident case ([`LedgerClient::create_case`] et al.).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaseRecord {
    pub id: String,
    pub title: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub agent_ids: Vec<String>,
    #[serde(default)]
    pub correlation_ids: Vec<String>,
    #[serde(default)]
    pub timeline: Vec<CaseTimelineEvent>,
    /// EU AI Act Art 73 severity once classified (`serious` / `death` /
    /// `critical_infra`); `None` until an operator classifies the case.
    #[serde(default)]
    pub severity: Option<String>,
    /// RFC 3339 authority-notification deadline stamped at classification.
    #[serde(default)]
    pub regulatory_deadline: Option<String>,
}

/// A case plus its expanded chain evidence ([`LedgerClient::get_case`]).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CaseDetail {
    pub case: CaseRecord,
    #[serde(default)]
    pub evidence: Vec<LedgerEntry>,
}

impl LedgerClient {
    /// Build a client against `base_url` (e.g. `http://localhost:8083`).
    /// Returns `InvalidConfig` if the URL is malformed.
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, ClavenarError> {
        let url = parse_base_url(base_url.as_ref())?;
        let http = default_provider()?;
        Ok(Self {
            base_url: url,
            http,
        })
    }

    /// Inject a pre-configured `reqwest::Client`. Wraps it in a
    /// [`StaticHttpClient`] so the per-request hot path stays uniform
    /// — same cost as caching a `Client`, no rebuild per call.
    pub fn with_http_client(self, client: Client) -> Self {
        self.with_http_provider(Arc::new(StaticHttpClient::new(client)))
    }

    /// Inject a custom [`HttpProvider`] (the hot-reload entrypoint).
    /// Use this when the caller wants the SDK to read a fresh
    /// `reqwest::Client` per request — e.g. from a workload-SVID
    /// refresh helper's ArcSwap. The trait's only method,
    /// [`HttpProvider::client`], is invoked per outbound call.
    pub fn with_http_provider(mut self, provider: Arc<dyn HttpProvider>) -> Self {
        self.http = provider;
        self
    }

    /// Read-only access to the configured base URL. Exposed so a
    /// caller can construct streaming requests (e.g. SSE) that don't
    /// fit the JSON-only `get_json` path the rest of this client uses
    /// — the clavenar-console live-tail proxy is the first such caller.
    /// Treat it as wire-level: the SDK still owns canonical request
    /// shaping, but a streaming response can't ride through the
    /// `get_json` decode pipeline.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Snapshot the active `reqwest::Client`. Same SSE-streaming
    /// rationale as `base_url`. Returns an `Arc<Client>` rather than a
    /// borrow so a hot-reloading provider can hand out the current
    /// credential without aliasing a stale reference into the caller.
    pub fn http_client(&self) -> Arc<Client> {
        self.http.client()
    }

    /// `GET /audit/correlation/{id}` — every chain entry sharing this
    /// correlation id, oldest first. Empty vec on an unknown id.
    pub async fn audit_correlation(
        &self,
        correlation_id: &str,
    ) -> Result<Vec<LedgerEntry>, ClavenarError> {
        // `Url::join` doesn't percent-encode path segments — we have
        // to do it ourselves so a correlation_id with a `/` or `?` in
        // it doesn't reroute the request. UUIDs are hex-only, so the
        // encode is a no-op for the common case but defensive in
        // general.
        let path = format!("audit/correlation/{}", percent_encode(correlation_id));
        self.get_json(&path).await
    }

    /// `GET /audit/{agent_id}` — every chain entry naming `agent_id`,
    /// oldest first. Empty vec on an unknown agent.
    pub async fn audit_agent(&self, agent_id: &str) -> Result<Vec<LedgerEntry>, ClavenarError> {
        let path = format!("audit/{}", percent_encode(agent_id));
        self.get_json(&path).await
    }

    /// `GET /audit/{agent_id}?limit=N&offset=M` — newest-first slice
    /// of size `N` skipping `M` rows. Backward-compatible companion to
    /// [`audit_agent`]: the legacy ASC-ordered, full-chain shape stays
    /// addressable via that method, while UI callers (the clavenar-console
    /// audit page) hit this one so memory and bandwidth scale with
    /// `per_page` instead of chain depth.
    pub async fn audit_agent_paged(
        &self,
        agent_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<LedgerEntry>, ClavenarError> {
        // Plain query-string concatenation. limit/offset are integers;
        // no percent-encoding needed for the values themselves.
        let path = format!(
            "audit/{}?limit={}&offset={}",
            percent_encode(agent_id),
            limit,
            offset,
        );
        self.get_json(&path).await
    }

    /// `GET /audit/{agent_id}?limit=N&before=S` — newest `N` rows
    /// strictly older than seq `S`. Backs the console audit page's
    /// forward seq-cursor pagination; stable across page navigation in
    /// a way [`audit_agent_paged`]'s offset-based shape is not.
    pub async fn audit_agent_paged_before(
        &self,
        agent_id: &str,
        limit: usize,
        before_seq: i64,
    ) -> Result<Vec<LedgerEntry>, ClavenarError> {
        let path = format!(
            "audit/{}?limit={}&before={}",
            percent_encode(agent_id),
            limit,
            before_seq,
        );
        self.get_json(&path).await
    }

    /// `GET /audit/{agent_id}?limit=N&after=S` — oldest `N` rows
    /// strictly newer than seq `S`, returned ASC so the caller can
    /// merge with the same-shape slices from other agents and then
    /// reverse to DESC for display. Backs backward seq-cursor
    /// pagination ("newer" button on the console audit page).
    pub async fn audit_agent_paged_after(
        &self,
        agent_id: &str,
        limit: usize,
        after_seq: i64,
    ) -> Result<Vec<LedgerEntry>, ClavenarError> {
        let path = format!(
            "audit/{}?limit={}&after={}",
            percent_encode(agent_id),
            limit,
            after_seq,
        );
        self.get_json(&path).await
    }

    /// `_since`-filtered companion to [`Self::audit_agent_paged`].
    /// Adds `&since=<rfc3339>` so the wire response carries only rows
    /// at or after the given instant — used by the console's
    /// activity / velocity / stats panels to push the timestamp
    /// window into SQL.
    pub async fn audit_agent_paged_since(
        &self,
        agent_id: &str,
        limit: usize,
        offset: usize,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<LedgerEntry>, ClavenarError> {
        let path = format!(
            "audit/{}?limit={}&offset={}&since={}",
            percent_encode(agent_id),
            limit,
            offset,
            percent_encode(&since.to_rfc3339()),
        );
        self.get_json(&path).await
    }

    /// `_since`-filtered companion to [`Self::audit_agent_paged_before`].
    pub async fn audit_agent_paged_before_since(
        &self,
        agent_id: &str,
        limit: usize,
        before_seq: i64,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<LedgerEntry>, ClavenarError> {
        let path = format!(
            "audit/{}?limit={}&before={}&since={}",
            percent_encode(agent_id),
            limit,
            before_seq,
            percent_encode(&since.to_rfc3339()),
        );
        self.get_json(&path).await
    }

    /// `_since`-filtered companion to [`Self::audit_agent_paged_after`].
    pub async fn audit_agent_paged_after_since(
        &self,
        agent_id: &str,
        limit: usize,
        after_seq: i64,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<LedgerEntry>, ClavenarError> {
        let path = format!(
            "audit/{}?limit={}&after={}&since={}",
            percent_encode(agent_id),
            limit,
            after_seq,
            percent_encode(&since.to_rfc3339()),
        );
        self.get_json(&path).await
    }

    pub async fn audit_agent_paged_filtered(
        &self,
        agent_id: &str,
        limit: usize,
        offset: usize,
        filter: &AuditFilterParams,
    ) -> Result<Vec<LedgerEntry>, ClavenarError> {
        let mut path = format!(
            "audit/{}?limit={}&offset={}",
            percent_encode(agent_id),
            limit,
            offset,
        );
        filter.append_query(&mut path);
        self.get_json(&path).await
    }

    pub async fn audit_agent_paged_before_filtered(
        &self,
        agent_id: &str,
        limit: usize,
        before_seq: i64,
        filter: &AuditFilterParams,
    ) -> Result<Vec<LedgerEntry>, ClavenarError> {
        let mut path = format!(
            "audit/{}?limit={}&before={}",
            percent_encode(agent_id),
            limit,
            before_seq,
        );
        filter.append_query(&mut path);
        self.get_json(&path).await
    }

    pub async fn audit_agent_paged_after_filtered(
        &self,
        agent_id: &str,
        limit: usize,
        after_seq: i64,
        filter: &AuditFilterParams,
    ) -> Result<Vec<LedgerEntry>, ClavenarError> {
        let mut path = format!(
            "audit/{}?limit={}&after={}",
            percent_encode(agent_id),
            limit,
            after_seq,
        );
        filter.append_query(&mut path);
        self.get_json(&path).await
    }

    /// `GET /audit/{agent_id}/count` — total chain rows naming
    /// `agent_id`. The console uses this with `audit_agent_paged` to
    /// compute total-pages without paying for the full row read. Cheap
    /// (`COUNT(*)` against the indexed column).
    pub async fn audit_agent_count(&self, agent_id: &str) -> Result<usize, ClavenarError> {
        // Tiny one-field response shape. Mirror it inline rather than
        // exposing a `pub struct Count {...}` — the field is incidental
        // to this single call's wire contract.
        #[derive(Deserialize)]
        struct Wrap {
            count: i64,
        }
        let path = format!("audit/{}/count", percent_encode(agent_id));
        let w: Wrap = self.get_json(&path).await?;
        // SQLite `COUNT(*)` can't return a negative — cast safely. The
        // `as usize` is lossless for positive i64 on 64-bit hosts; on
        // 32-bit hosts SQLite would have to host >2B chain rows for
        // truncation, which isn't a realistic concern.
        Ok(w.count.max(0) as usize)
    }

    pub async fn audit_agent_count_filtered(
        &self,
        agent_id: &str,
        filter: &AuditFilterParams,
    ) -> Result<usize, ClavenarError> {
        #[derive(Deserialize)]
        struct Wrap {
            count: i64,
        }
        let mut path = format!("audit/{}/count?", percent_encode(agent_id));
        filter.append_query(&mut path);
        let w: Wrap = self.get_json(&path).await?;
        Ok(w.count.max(0) as usize)
    }

    /// `GET /verify` — re-hash every entry and check the chain. Cheap
    /// for a few thousand entries; not intended to be called on a
    /// hot path.
    pub async fn verify(&self) -> Result<VerifyResult, ClavenarError> {
        self.get_json("verify").await
    }

    /// `GET /agents` — distinct CN-shaped agents that have ever
    /// emitted a v1/v2 verdict row. The console uses this as the
    /// "all agents" default for the audit page so any CN that has
    /// logged a row appears, not just those known to the simulator
    /// roster.
    pub async fn list_agents(&self) -> Result<Vec<String>, ClavenarError> {
        // Inline shape — single-field response, identical pattern to
        // `audit_agent_count` above.
        #[derive(Deserialize)]
        struct Wrap {
            agents: Vec<String>,
        }
        let w: Wrap = self.get_json("agents").await?;
        Ok(w.agents)
    }

    /// `GET /audit/agent/{tenant}/{agent_id}/lifecycle` — chain v3
    /// rows for a registered agent, joined with the per-kind
    /// payload bytes. Ordered chain-ascending so the timeline reads
    /// "registered → suspended → unsuspended → …". `agent_id` is
    /// the `agents` table's uuidv7 (distinct from the audit
    /// endpoints' CN-shaped agent_id). Empty vec when the chain has
    /// no v3 rows for the agent.
    pub async fn lifecycle_for_agent(
        &self,
        tenant: &str,
        agent_id: &str,
    ) -> Result<Vec<LifecycleRow>, ClavenarError> {
        let path = format!(
            "audit/agent/{}/{}/lifecycle",
            percent_encode(tenant),
            percent_encode(agent_id),
        );
        self.get_json(&path).await
    }

    /// `GET /audit/entry/{entry_id}/masked-params` — the PII-masked
    /// canonical params archived for one entry, or `None` when nothing was
    /// archived. The archive is opt-in (the Brain emits masked params only
    /// under `CLAVENAR_BRAIN_EMIT_MASKED_PARAMS`) and lives outside the
    /// hash chain, so `None` is the common, non-error shape — not a tamper
    /// signal. Backs the console reconstruction view.
    pub async fn masked_params_for_entry(
        &self,
        entry_id: &str,
    ) -> Result<Option<serde_json::Value>, ClavenarError> {
        #[derive(Deserialize)]
        struct Wrap {
            masked_params: Option<serde_json::Value>,
        }
        let path = format!("audit/entry/{}/masked-params", percent_encode(entry_id));
        let w: Wrap = self.get_json(&path).await?;
        Ok(w.masked_params)
    }

    /// `GET /audit/replay/corpus` — Policy Lab replay corpus. Returns
    /// policy-decision rows in the time window whose stored
    /// `policy_decision` carries an `input_replay` block, with each
    /// row's PolicyInput reconstructed for replay against a candidate
    /// Rego rule.
    pub async fn replay_corpus(
        &self,
        params: ReplayCorpusParams,
    ) -> Result<ReplayCorpus, ClavenarError> {
        let mut path = format!(
            "audit/replay/corpus?since={}&limit={}",
            percent_encode(&params.since.to_rfc3339()),
            params.limit,
        );
        if let Some(until) = params.until {
            path.push_str(&format!("&until={}", percent_encode(&until.to_rfc3339())));
        }
        if let Some(a) = params.agent_id.as_deref() {
            path.push_str(&format!("&agent_id={}", percent_encode(a)));
        }
        if let Some(t) = params.tool_type.as_deref() {
            path.push_str(&format!("&tool_type={}", percent_encode(t)));
        }
        if let Some(tp) = params.tenant_prefix.as_deref() {
            path.push_str(&format!("&tenant_prefix={}", percent_encode(tp)));
        }
        self.get_json(&path).await
    }

    /// `GET /analysis/agent-envelope-recommendations` — the used-tool
    /// side of Blast-Radius Autopilot. Returns per-tool usage counts +
    /// confidence over the window for one agent; the caller joins it
    /// against the agent's provisioned `scope_envelope`.
    pub async fn envelope_analysis(
        &self,
        agent_id: &str,
        window_days: u32,
    ) -> Result<EnvelopeAnalysis, ClavenarError> {
        let path = format!(
            "analysis/agent-envelope-recommendations?agent_id={}&window_days={}",
            percent_encode(agent_id),
            window_days,
        );
        self.get_json(&path).await
    }

    /// `GET /analysis/agent-behavioral-baseline` — Temporal intelligence.
    /// Profiles the agent's recent window (tool mix, hourly cadence, intent +
    /// deny-rate) against the immediately-prior baseline window and returns a
    /// drift score. Internal (mTLS) surface, like [`Self::envelope_analysis`].
    pub async fn behavioral_baseline(
        &self,
        agent_id: &str,
        baseline_days: u32,
        recent_days: u32,
    ) -> Result<BehavioralBaseline, ClavenarError> {
        let path = format!(
            "analysis/agent-behavioral-baseline?agent_id={}&baseline_days={}&recent_days={}",
            percent_encode(agent_id),
            baseline_days,
            recent_days,
        );
        self.get_json(&path).await
    }

    /// `GET /analysis/silent-agents` — Shadow-Agent-Radar silence
    /// watchdog. Lists enrolled, active agents whose tool traffic has
    /// gone quiet past `since_hours` ("credential active, zero traffic").
    /// Internal (mTLS) surface, like [`Self::envelope_analysis`].
    pub async fn silent_agents(
        &self,
        since_hours: u32,
    ) -> Result<SilentAgentsReport, ClavenarError> {
        let path = format!("analysis/silent-agents?since_hours={}", since_hours);
        self.get_json(&path).await
    }

    /// `GET /analysis/fleet-behavioral-diff` — Temporal intelligence,
    /// fleet-wide. Rolls every profiled agent's recent-vs-prior window diff +
    /// drift into one drift-descending list. The server clamps `limit` to
    /// [1, 1000]; the window defaults to week-over-week (`recent_days=7`,
    /// `baseline_days=14`). Internal (mTLS) surface, like [`Self::hunt`].
    pub async fn fleet_behavioral_diff(
        &self,
        baseline_days: u32,
        recent_days: u32,
        limit: i64,
    ) -> Result<FleetBehavioralDiff, ClavenarError> {
        let path = format!(
            "analysis/fleet-behavioral-diff?baseline_days={}&recent_days={}&limit={}",
            baseline_days, recent_days, limit,
        );
        self.get_json(&path).await
    }

    /// `GET /analysis/model-upgrade-canary` — Temporal intelligence. Compares
    /// fleet detector behavior in the window before a Brain model/provider
    /// change against the window after (deny-rate, intent mean, rejection-
    /// signal mix, and the model identity attested in each window's on-chain
    /// evidence). `cutover` pins the upgrade instant; `None` defaults to
    /// `now - window_hours` (prior-vs-recent). Internal (mTLS) surface, like
    /// [`Self::fleet_behavioral_diff`].
    pub async fn model_upgrade_canary(
        &self,
        cutover: Option<&str>,
        window_hours: u32,
    ) -> Result<ModelUpgradeCanary, ClavenarError> {
        let mut path = format!(
            "analysis/model-upgrade-canary?window_hours={}",
            window_hours
        );
        if let Some(c) = cutover {
            path.push_str(&format!("&cutover={}", percent_encode(c)));
        }
        self.get_json(&path).await
    }

    /// `GET /audit/hunt` — fleet-wide incident hunt. One server-side
    /// aggregation rolls every agent active in the filtered window into
    /// a single row (hit/deny counts, worst signal, distinct methods,
    /// last seen), worst-signal-first. Internal (mTLS) surface — the
    /// console reaches it with its operator-authenticated client.
    pub async fn hunt(&self, params: HuntParams) -> Result<HuntResult, ClavenarError> {
        let mut path = format!("audit/hunt?limit={}", params.limit);
        if let Some(m) = params.method.as_deref() {
            path.push_str(&format!("&method={}", percent_encode(m)));
        }
        if let Some(s) = params.signal.as_deref() {
            path.push_str(&format!("&signal={}", percent_encode(s)));
        }
        if let Some(a) = params.authorized {
            path.push_str(&format!("&authorized={a}"));
        }
        if let Some(f) = params.from {
            path.push_str(&format!("&from={}", percent_encode(&f.to_rfc3339())));
        }
        if let Some(t) = params.to {
            path.push_str(&format!("&to={}", percent_encode(&t.to_rfc3339())));
        }
        if let Some(token) = params.demo_session_token.as_deref() {
            path.push_str(&format!("&demo_session_token={}", percent_encode(token)));
        }
        if let Some(tenant) = params.tenant.as_deref() {
            path.push_str(&format!("&tenant={}", percent_encode(tenant)));
        }
        self.get_json(&path).await
    }

    /// `GET /finops/spend?window=YYYY-MM&tenant=<t>&limit=N` — attributed-
    /// spend rollup (FinOps P3). `window` omitted → all-time. `tenant`
    /// omitted → the whole deployment; `Some` scopes to one operator
    /// tenant (per-tenant billing/quota). The server clamps `limit` to
    /// [1, 1000].
    pub async fn finops_spend(
        &self,
        window: Option<&str>,
        tenant: Option<&str>,
        limit: i64,
    ) -> Result<SpendRollup, ClavenarError> {
        let mut path = format!("finops/spend?limit={limit}");
        if let Some(w) = window {
            path.push_str(&format!("&window={}", percent_encode(w)));
        }
        if let Some(t) = tenant {
            path.push_str(&format!("&tenant={}", percent_encode(t)));
        }
        self.get_json(&path).await
    }

    /// `GET /exports` — bookkeeping list of cold-tier snapshots, newest
    /// first. Empty vec when the export sweeper has never run (or when
    /// the sink isn't configured — the table exists either way, the
    /// rows are just absent). Cheap call: it's a `SELECT *` over what
    /// is typically a small bookkeeping table.
    pub async fn list_exports(&self) -> Result<Vec<ExportRecord>, ClavenarError> {
        self.get_json("exports").await
    }

    /// `POST /export` — synchronously run one cold-tier export pass.
    /// Returns `NothingToExport` when all eligible rows are already
    /// covered, `Wrote(record)` when a snapshot lands, and
    /// [`ClavenarError::Server`] for backend-mode/configuration errors
    /// such as Postgres mode or an unset export sink.
    pub async fn trigger_export(&self) -> Result<ExportOutcome, ClavenarError> {
        let endpoint = self
            .base_url
            .join("export")
            .map_err(|e| ClavenarError::InvalidConfig(format!("join export: {e}")))?;
        let resp = self.http.client().post(endpoint).send().await?;
        let status = resp.status();
        let raw = resp.text().await?;
        if status == StatusCode::OK {
            serde_json::from_str(&raw).map_err(ClavenarError::Decode)
        } else {
            Err(ClavenarError::Server { status, body: raw })
        }
    }

    /// `POST /export/regulatory?from=…&to=…[&include_exports=true]` —
    /// produce a regulatory `.tar.gz` for the half-open time window
    /// `[from, to)`. Returns the raw bundle bytes. The bundle layout
    /// and auditor verification recipe live in
    /// `clavenar-ledger/src/regulatory.rs`. Manifest schema v6 ships
    /// chain rows plus optional operator prose, optional Parquet
    /// pointers, an optional auto-derived compliance register, optional
    /// external chain-anchor proofs, an optional EU AI Act Annex IV
    /// coverage assertion and Article 72 post-market-monitoring plan
    /// (operator-triggered via the `annex_iv` / `include_post_market_plan`
    /// query params), and an optional ed25519 detached signature.
    ///
    /// `opts.readme` (optional) is the operator-supplied prose
    /// embedded as `technical_documentation.md`. The SDK uploads it
    /// with `Content-Type: text/markdown`; the ledger commits to the
    /// bytes' sha256 in the manifest. Capped at 1 MiB by the server
    /// (the ledger refuses larger bodies with 413).
    ///
    /// `opts.include_exports` (optional, defaults false) tells the
    /// ledger to scan its `exports` table and embed Parquet pointers
    /// whose seq range overlaps the window. Pointers are descriptive
    /// — the bundle is self-contained without them.
    ///
    /// The half-open semantics, error-status mapping (400 inverted,
    /// 413 oversize, 503 signing-unavailable), and signature recipe
    /// match the ledger's surface 1:1.
    pub async fn regulatory_export(
        &self,
        from: &chrono::DateTime<chrono::Utc>,
        to: &chrono::DateTime<chrono::Utc>,
        opts: RegulatoryExportOptions,
    ) -> Result<Vec<u8>, ClavenarError> {
        // RFC 3339 on both bounds — same format the ledger uses for
        // chain timestamps. `to_rfc3339_opts` with `SecondsFormat::Secs`
        // produces a stable shape across hosts.
        let from_str = from.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let to_str = to.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let mut path = format!(
            "export/regulatory?from={}&to={}",
            percent_encode(&from_str),
            percent_encode(&to_str),
        );
        if opts.include_exports {
            path.push_str("&include_exports=true");
        }
        if opts.include_compliance {
            path.push_str("&include_compliance=true");
        }
        let endpoint = self
            .base_url
            .join(&path)
            .map_err(|e| ClavenarError::InvalidConfig(format!("join {path}: {e}")))?;
        let http = self.http.client();
        let mut req = http.post(endpoint);
        if let Some(readme) = opts.readme {
            // text/markdown is the canonical content-type for `.md`
            // bodies (RFC 7763). The ledger accepts any `text/*`,
            // including `text/plain`, but markdown is the intended
            // shape and the ctl CLI wraps a `.md` file path.
            req = req
                .header(reqwest::header::CONTENT_TYPE, "text/markdown")
                .body(readme);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClavenarError::Server { status, body });
        }
        let bytes = resp.bytes().await?;
        Ok(bytes.to_vec())
    }

    /// `POST /compliance/evidence?from=…&to=…` — live EU AI Act Article
    /// 14/15 + SOC 2 / ISO 27001 evidence register for the half-open
    /// window `[from, to)`. Returns the parsed [`ComplianceRegister`].
    /// The downloadable, signed counterpart rides
    /// [`Self::regulatory_export`] with
    /// [`RegulatoryExportOptions::include_compliance`].
    ///
    /// An empty window returns `200` with every control `no_data`; an
    /// inverted or malformed window maps to `400`
    /// (`ClavenarError::Server`).
    pub async fn compliance_evidence(
        &self,
        from: &chrono::DateTime<chrono::Utc>,
        to: &chrono::DateTime<chrono::Utc>,
    ) -> Result<ComplianceRegister, ClavenarError> {
        let from_str = from.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let to_str = to.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let path = format!(
            "compliance/evidence?from={}&to={}",
            percent_encode(&from_str),
            percent_encode(&to_str),
        );
        let endpoint = self
            .base_url
            .join(&path)
            .map_err(|e| ClavenarError::InvalidConfig(format!("join {path}: {e}")))?;
        let resp = self.http.client().post(endpoint).send().await?;
        let status = resp.status();
        let raw = resp.text().await?;
        if status == StatusCode::OK {
            serde_json::from_str(&raw).map_err(ClavenarError::Decode)
        } else {
            Err(ClavenarError::Server { status, body: raw })
        }
    }

    /// `POST /cases` — open an incident case over the given agents +
    /// correlations. Returns the created case.
    pub async fn create_case(
        &self,
        title: &str,
        agent_ids: &[String],
        correlation_ids: &[String],
        actor: Option<&str>,
    ) -> Result<CaseRecord, ClavenarError> {
        let body = serde_json::json!({
            "title": title,
            "agent_ids": agent_ids,
            "correlation_ids": correlation_ids,
            "actor": actor,
        });
        self.post_json("cases", &body).await
    }

    /// `GET /cases` — list cases newest-first, optionally filtered by
    /// status (`open` / `contained` / `closed`).
    pub async fn list_cases(
        &self,
        status: Option<&str>,
        limit: i64,
    ) -> Result<Vec<CaseRecord>, ClavenarError> {
        let mut path = format!("cases?limit={limit}");
        if let Some(s) = status {
            path.push_str(&format!("&status={}", percent_encode(s)));
        }
        self.get_json(&path).await
    }

    /// `GET /cases/{id}` — the case plus its expanded chain evidence.
    pub async fn get_case(&self, id: &str) -> Result<CaseDetail, ClavenarError> {
        self.get_json(&format!("cases/{}", percent_encode(id)))
            .await
    }

    /// `POST /cases/{id}/timeline` — append an event.
    pub async fn append_case_timeline(
        &self,
        id: &str,
        ev: &CaseTimelineEvent,
    ) -> Result<(), ClavenarError> {
        self.post_json(&format!("cases/{}/timeline", percent_encode(id)), ev)
            .await
    }

    /// `POST /cases/{id}/status` — set `open` / `contained` / `closed`.
    pub async fn set_case_status(&self, id: &str, status: &str) -> Result<(), ClavenarError> {
        self.post_json(
            &format!("cases/{}/status", percent_encode(id)),
            &serde_json::json!({ "status": status }),
        )
        .await
    }

    /// `POST /log` — append a forensic entry. The ledger computes the
    /// hash chain and returns the row's chain position + entry hash.
    /// Reaches the same internal mTLS router as the `audit_*` reads.
    pub async fn log(&self, entry: &LogEntry) -> Result<LogReceipt, ClavenarError> {
        self.post_json("log", entry).await
    }

    /// `POST /cases/{id}/classify` — set the EU AI Act Art 73 severity
    /// (`serious` / `death` / `critical_infra`); the server stamps the
    /// authority-notification deadline. Returns `(severity, deadline)`.
    pub async fn classify_case(
        &self,
        id: &str,
        severity: &str,
    ) -> Result<(String, String), ClavenarError> {
        #[derive(serde::Deserialize)]
        struct Resp {
            severity: String,
            regulatory_deadline: String,
        }
        let r: Resp = self
            .post_json(
                &format!("cases/{}/classify", percent_encode(id)),
                &serde_json::json!({ "severity": severity }),
            )
            .await?;
        Ok((r.severity, r.regulatory_deadline))
    }

    /// `POST /cases/{id}/attach` — union more agents/correlations in.
    pub async fn attach_case(
        &self,
        id: &str,
        agent_ids: &[String],
        correlation_ids: &[String],
    ) -> Result<(), ClavenarError> {
        self.post_json(
            &format!("cases/{}/attach", percent_encode(id)),
            &serde_json::json!({ "agent_ids": agent_ids, "correlation_ids": correlation_ids }),
        )
        .await
    }

    /// `POST /admin/tenants/{tenant}/tombstone` — logically erase a
    /// tenant's audit rows (Phase 7 offboarding). Sets `deleted_at` on
    /// every live row whose `tenant` matches, hiding them from all reads
    /// while leaving the hash chain (and `/verify`) intact. Returns the
    /// number of rows newly tombstoned. Internal/mTLS-gated server-side;
    /// the console calls it after the identity offboard. Idempotent.
    pub async fn tombstone_tenant(
        &self,
        tenant: &str,
        reason: Option<&str>,
    ) -> Result<i64, ClavenarError> {
        #[derive(serde::Deserialize)]
        struct Resp {
            tombstoned: i64,
        }
        let r: Resp = self
            .post_json(
                &format!("admin/tenants/{}/tombstone", percent_encode(tenant)),
                &serde_json::json!({ "reason": reason }),
            )
            .await?;
        Ok(r.tombstoned)
    }

    /// Internal: POST `<base_url>/<path>` with a JSON body, decode the
    /// JSON response on any 2xx (a 204 No Content decodes as `()` via an
    /// empty-body→`null` fallback); `Server { status, body }` otherwise.
    async fn post_json<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ClavenarError> {
        let endpoint = self
            .base_url
            .join(path)
            .map_err(|e| ClavenarError::InvalidConfig(format!("join {path}: {e}")))?;
        let resp = self.http.client().post(endpoint).json(body).send().await?;
        let status = resp.status();
        let raw = resp.text().await?;
        if status.is_success() {
            let raw = if raw.trim().is_empty() {
                "null".to_string()
            } else {
                raw
            };
            serde_json::from_str(&raw).map_err(ClavenarError::Decode)
        } else {
            Err(ClavenarError::Server { status, body: raw })
        }
    }

    /// Internal: GET `<base_url>/<path>` and decode JSON. Returns
    /// `Server { status, body }` for any non-2xx; transport / decode
    /// errors flow through `?`.
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, ClavenarError> {
        let endpoint = self
            .base_url
            .join(path)
            .map_err(|e| ClavenarError::InvalidConfig(format!("join {path}: {e}")))?;
        let resp = self.http.client().get(endpoint).send().await?;
        let status = resp.status();
        let raw = resp.text().await?;
        if status == StatusCode::OK {
            serde_json::from_str(&raw).map_err(ClavenarError::Decode)
        } else {
            Err(ClavenarError::Server { status, body: raw })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_entry_round_trips_through_json() {
        // Build a value matching what the server emits, deserialize,
        // re-serialize, and confirm the round-trip is stable. Catches
        // accidental field-name drift in the mirror struct.
        let server_shape = serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "timestamp": "2026-05-02T12:34:56Z",
            "agent_id": "demo-bot",
            "method": "tools/call",
            "intent_category": "BenignTool",
            "authorized": true,
            "reasoning": "policy: allow",
            "policy_decision": { "allow": true, "reasons": [] },
            "seq": 42,
            "prev_hash": "0".repeat(64),
            "entry_hash": "a".repeat(64),
            "correlation_id": "cid-1"
        });
        let parsed: LedgerEntry = serde_json::from_value(server_shape.clone()).unwrap();
        assert_eq!(parsed.seq, 42);
        assert_eq!(parsed.correlation_id.as_deref(), Some("cid-1"));
        let again = serde_json::to_value(&parsed).unwrap();
        // chrono normalizes the timezone marker; compare the parsed
        // representation rather than the literal JSON string.
        let again_back: LedgerEntry = serde_json::from_value(again).unwrap();
        assert_eq!(again_back.id, parsed.id);
        assert_eq!(again_back.entry_hash, parsed.entry_hash);
    }

    #[test]
    fn ledger_entry_accepts_missing_correlation_id() {
        // Older publishers don't emit `correlation_id`; the
        // `#[serde(default)]` on the field keeps the parse green.
        let pre_correlation = serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "timestamp": "2026-05-02T12:34:56Z",
            "agent_id": "demo-bot",
            "method": "tools/call",
            "intent_category": "BenignTool",
            "authorized": true,
            "reasoning": "policy: allow",
            "policy_decision": null,
            "seq": 1,
            "prev_hash": "0".repeat(64),
            "entry_hash": "a".repeat(64)
        });
        let parsed: LedgerEntry = serde_json::from_value(pre_correlation).unwrap();
        assert!(parsed.correlation_id.is_none());
        // chain_version defaults to 1 when absent — legacy rows
        // were all written under v1.
        assert_eq!(parsed.chain_version, 1);
    }

    #[test]
    fn ledger_entry_carries_explicit_chain_version_when_present() {
        let v1 = serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "timestamp": "2026-05-02T12:34:56Z",
            "agent_id": "demo-bot",
            "method": "tools/call",
            "intent_category": "BenignTool",
            "authorized": true,
            "reasoning": "policy: allow",
            "policy_decision": null,
            "seq": 1,
            "prev_hash": "0".repeat(64),
            "entry_hash": "a".repeat(64),
            "chain_version": 2,
        });
        let parsed: LedgerEntry = serde_json::from_value(v1).unwrap();
        assert_eq!(parsed.chain_version, 2);
    }

    #[test]
    fn ledger_entry_decodes_v4_brain_evidence() {
        // A v4 verdict row carries `brain_evidence_sha256`; older rows
        // omit it (default None), so the mirror stays a forgiving subset.
        let v4 = serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "timestamp": "2026-06-12T12:34:56Z",
            "agent_id": "demo-bot",
            "method": "tools/call",
            "intent_category": "DirectExecution",
            "authorized": true,
            "reasoning": "security: ok | upstream: ok",
            "policy_decision": null,
            "seq": 7,
            "prev_hash": "0".repeat(64),
            "entry_hash": "a".repeat(64),
            "chain_version": 4,
            "brain_evidence_sha256": "b".repeat(64),
        });
        let parsed: LedgerEntry = serde_json::from_value(v4).unwrap();
        assert_eq!(parsed.chain_version, 4);
        assert_eq!(
            parsed.brain_evidence_sha256.as_deref(),
            Some("b".repeat(64).as_str())
        );

        // Legacy row without the field decodes to None.
        let legacy = serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440001",
            "timestamp": "2026-06-12T12:34:56Z",
            "agent_id": "demo-bot",
            "method": "tools/call",
            "intent_category": "DirectExecution",
            "authorized": true,
            "reasoning": "ok",
            "policy_decision": null,
            "seq": 1,
            "prev_hash": "0".repeat(64),
            "entry_hash": "a".repeat(64),
        });
        let parsed: LedgerEntry = serde_json::from_value(legacy).unwrap();
        assert!(parsed.brain_evidence_sha256.is_none());
    }

    #[test]
    fn ledger_entry_decodes_brain_scores() {
        // Non-hashable per-detector scores ride as opaque JSON; rows
        // without them (the overwhelming majority) decode to None.
        let with_scores = serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440002",
            "timestamp": "2026-06-12T12:34:56Z",
            "agent_id": "demo-abc123",
            "method": "call_tool",
            "intent_category": "Meta-Reasoning",
            "authorized": false,
            "reasoning": "Potential bypass attempt detected (Heuristic)",
            "policy_decision": null,
            "seq": 9,
            "prev_hash": "0".repeat(64),
            "entry_hash": "a".repeat(64),
            "brain_scores": {
                "injection_confidence": 0.85,
                "malicious_code_confidence": 0.0,
                "compromised_package_confidence": 0.0,
                "persona_drift_score": 0.0,
                "drift_available": false,
            },
        });
        let parsed: LedgerEntry = serde_json::from_value(with_scores).unwrap();
        let scores = parsed.brain_scores.expect("scores present");
        assert_eq!(scores["injection_confidence"], 0.85);

        let without = serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440003",
            "timestamp": "2026-06-12T12:34:56Z",
            "agent_id": "demo-abc123",
            "method": "call_tool",
            "intent_category": "DirectExecution",
            "authorized": true,
            "reasoning": "ok",
            "policy_decision": null,
            "seq": 10,
            "prev_hash": "0".repeat(64),
            "entry_hash": "a".repeat(64),
        });
        let parsed: LedgerEntry = serde_json::from_value(without).unwrap();
        assert!(parsed.brain_scores.is_none());
    }

    #[test]
    fn verify_result_round_trips() {
        let valid = serde_json::json!({
            "valid": true,
            "entries_checked": 47,
            "first_invalid_seq": null
        });
        let parsed: VerifyResult = serde_json::from_value(valid).unwrap();
        assert!(parsed.valid);
        assert_eq!(parsed.entries_checked, 47);
        assert!(parsed.first_invalid_seq.is_none());
        assert!(parsed.unsupported_chain_version.is_none());

        let invalid = serde_json::json!({
            "valid": false,
            "entries_checked": 12,
            "first_invalid_seq": 7
        });
        let parsed: VerifyResult = serde_json::from_value(invalid).unwrap();
        assert!(!parsed.valid);
        assert_eq!(parsed.first_invalid_seq, Some(7));
    }

    #[test]
    fn export_record_round_trips_through_json() {
        // Mirrors what the ledger's `GET /exports` emits per row. The
        // mirror struct on this side has to track the server's field
        // order/names exactly — drift here turns into silent decode
        // failures on the console's exports page.
        let server_shape = serde_json::json!({
            "snapshot_id": "550e8400-e29b-41d4-a716-446655440000",
            "written_at": "2026-05-02T12:34:56Z",
            "data_uri": "file:///snapshots/abc.parquet",
            "manifest_uri": "file:///snapshots/abc.manifest.json",
            "data_sha256": "f".repeat(64),
            "byte_size": 1024,
            "row_count": 42,
            "seq_lo": 1,
            "seq_hi": 42
        });
        let parsed: ExportRecord = serde_json::from_value(server_shape).unwrap();
        assert_eq!(parsed.row_count, 42);
        assert_eq!(parsed.byte_size, 1024);
        assert_eq!(parsed.seq_lo, 1);
        assert_eq!(parsed.seq_hi, 42);
        // Round-trip through serde to catch field-name drift in either
        // direction (server adds a field — we'd silently drop it; we
        // rename one — round-trip blows up).
        let again = serde_json::to_value(&parsed).unwrap();
        let again_back: ExportRecord = serde_json::from_value(again).unwrap();
        assert_eq!(again_back, parsed);
    }

    #[test]
    fn verify_result_decodes_unsupported_chain_version_signal() {
        // Server returns valid=false + unsupported_chain_version=Some
        // when the ledger is newer than the verifier. The SDK must
        // expose both signals so a caller can distinguish "tampered"
        // from "upgrade me."
        let upgrade_me = serde_json::json!({
            "valid": false,
            "entries_checked": 4,
            "first_invalid_seq": null,
            "unsupported_chain_version": 2
        });
        let parsed: VerifyResult = serde_json::from_value(upgrade_me).unwrap();
        assert!(!parsed.valid);
        assert!(parsed.first_invalid_seq.is_none());
        assert_eq!(parsed.unsupported_chain_version, Some(2));
        // Anchors default to empty / None when the ledger omits them
        // (pre-anchoring builds, or nothing anchored yet).
        assert!(parsed.anchors.is_empty());
        assert!(parsed.anchor_mismatch.is_none());
    }

    #[test]
    fn verify_result_decodes_anchor_cross_checks() {
        // A ledger with external anchoring surfaces the anchor list plus a
        // top-level mismatch flag; the SDK mirror must carry both.
        let with_anchors = serde_json::json!({
            "valid": true,
            "entries_checked": 9,
            "first_invalid_seq": null,
            "anchors": [{
                "anchored_seq": 7,
                "anchored_entry_hash": "ab",
                "source": "rfc3161",
                "status": "anchored",
                "gen_time": "2026-06-12T00:00:00Z",
                "proof_sha256": "cd",
                "anchored_at": "2026-06-12T00:00:01Z",
                "chain_match": false
            }],
            "anchor_mismatch": true
        });
        let parsed: VerifyResult = serde_json::from_value(with_anchors).unwrap();
        assert!(parsed.valid);
        assert_eq!(parsed.anchors.len(), 1);
        assert_eq!(parsed.anchors[0].source, "rfc3161");
        assert_eq!(parsed.anchors[0].chain_match, Some(false));
        assert_eq!(parsed.anchor_mismatch, Some(true));
    }

    #[test]
    fn lifecycle_row_decodes_v3_fields_with_payload_join() {
        // Mock the ledger's GET /audit/agent/{tenant}/{agent_id}/lifecycle
        // shape — flattened LedgerEntry plus a sibling `payload` Value.
        // Verify the v3-only fields (event_kind, tenant, agent_name,
        // actor_sub, actor_idp, payload_sha256) all decode through and
        // the payload object is preserved verbatim.
        let body = serde_json::json!({
            "id": "01940000-0000-7000-8000-000000000000",
            "timestamp": "2026-05-05T14:30:00Z",
            "agent_id": "01HW-AGENT-uuid",
            "method": "agent.registered",
            "intent_category": "Lifecycle",
            "authorized": true,
            "reasoning": "",
            "policy_decision": null,
            "seq": 1,
            "prev_hash": "00".repeat(32),
            "entry_hash": "ab".repeat(32),
            "chain_version": 3,
            "event_kind": "agent.registered",
            "tenant": "acme",
            "agent_name": "support-bot-3",
            "actor_sub": "user:alice@acme.com",
            "actor_idp": "okta",
            "payload_sha256": "cd".repeat(32),
            "signature": "vault:v1:ZmFrZQ==",
            "key_id": "clavenar-identity:v1",
            "payload": {
                "owner_team": "payments",
                "scope_envelope": ["mcp:read:tickets"]
            }
        });
        let row: LifecycleRow = serde_json::from_value(body).unwrap();
        assert_eq!(row.entry.chain_version, 3);
        assert_eq!(row.entry.event_kind.as_deref(), Some("agent.registered"));
        assert_eq!(row.entry.tenant.as_deref(), Some("acme"));
        assert_eq!(row.entry.agent_name.as_deref(), Some("support-bot-3"));
        let payload = row.payload.expect("payload joined in");
        assert_eq!(payload["owner_team"], "payments");
    }

    #[tokio::test]
    async fn lifecycle_for_agent_round_trips_against_mock() {
        use axum::{Router, routing::get};
        use tokio::sync::oneshot;

        // Mock the ledger endpoint with two canned v3 rows.
        let app =
            Router::new().route(
                "/audit/agent/{tenant}/{agent_id}/lifecycle",
                get(
                    |axum::extract::Path((tenant, agent_id)): axum::extract::Path<(
                        String,
                        String,
                    )>| async move {
                        axum::Json(serde_json::json!([
                            {
                                "id": "01940000-0000-7000-8000-000000000001",
                                "timestamp": "2026-05-05T14:00:00Z",
                                "agent_id": agent_id,
                                "method": "agent.registered",
                                "intent_category": "Lifecycle",
                                "authorized": true,
                                "reasoning": "",
                                "policy_decision": null,
                                "seq": 1,
                                "prev_hash": "00".repeat(32),
                                "entry_hash": "ab".repeat(32),
                                "chain_version": 3,
                                "event_kind": "agent.registered",
                                "tenant": tenant,
                                "agent_name": "support-bot-3",
                                "actor_sub": "user:alice@acme.com",
                                "actor_idp": "okta",
                                "payload_sha256": "cd".repeat(32),
                                "payload": { "owner_team": "payments" }
                            },
                            {
                                "id": "01940000-0000-7000-8000-000000000002",
                                "timestamp": "2026-05-05T14:30:00Z",
                                "agent_id": agent_id,
                                "method": "agent.suspended",
                                "intent_category": "Lifecycle",
                                "authorized": true,
                                "reasoning": "",
                                "policy_decision": null,
                                "seq": 2,
                                "prev_hash": "ab".repeat(32),
                                "entry_hash": "ef".repeat(32),
                                "chain_version": 3,
                                "event_kind": "agent.suspended",
                                "tenant": tenant,
                                "agent_name": "support-bot-3",
                                "actor_sub": "user:alice@acme.com",
                                "actor_idp": "okta",
                                "payload_sha256": "01".repeat(32),
                                "payload": { "state_before": "active", "state_after": "suspended" }
                            }
                        ]))
                    },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (kill_tx, kill_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = kill_rx.await;
                })
                .await
                .unwrap();
        });

        let client = LedgerClient::new(format!("http://{addr}/")).unwrap();
        let rows = client
            .lifecycle_for_agent("acme", "01HW-AGENT-uuid")
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].entry.event_kind.as_deref(),
            Some("agent.registered")
        );
        assert_eq!(rows[1].entry.event_kind.as_deref(), Some("agent.suspended"));
        assert_eq!(
            rows[1].payload.as_ref().unwrap()["state_after"],
            "suspended"
        );
        let _ = kill_tx.send(());
    }

    #[tokio::test]
    async fn hunt_threads_demo_session_token_query_param() {
        use axum::{Router, extract::Query, routing::get};
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};
        use tokio::sync::oneshot;

        let captured: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
        let captured_for_handler = captured.clone();

        let app = Router::new().route(
            "/audit/hunt",
            get(move |Query(q): Query<HashMap<String, String>>| {
                let captured_for_handler = captured_for_handler.clone();
                async move {
                    *captured_for_handler.lock().unwrap() = q;
                    axum::Json(serde_json::json!({
                        "agents": [],
                        "returned": 0
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (kill_tx, kill_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = kill_rx.await;
                })
                .await
                .unwrap();
        });

        let client = LedgerClient::new(format!("http://{addr}/")).unwrap();
        let result = client
            .hunt(HuntParams {
                limit: 200,
                signal: Some("egress_violation".into()),
                demo_session_token: Some("jwt.with/slash".into()),
                tenant: Some("acme".into()),
                ..Default::default()
            })
            .await
            .unwrap();

        assert!(result.agents.is_empty());
        let q = captured.lock().unwrap();
        assert_eq!(q.get("limit").map(String::as_str), Some("200"));
        assert_eq!(
            q.get("signal").map(String::as_str),
            Some("egress_violation")
        );
        assert_eq!(
            q.get("demo_session_token").map(String::as_str),
            Some("jwt.with/slash")
        );
        assert_eq!(q.get("tenant").map(String::as_str), Some("acme"));
        let _ = kill_tx.send(());
    }

    #[tokio::test]
    async fn regulatory_export_threads_query_params_and_optional_readme() {
        // Mock the ledger handler. Captures the request — the body
        // bytes we got, content-type header, and query string — into
        // an Arc<Mutex> the test reads after the call. The handler
        // returns a deterministic .tar.gz-shaped placeholder.
        use axum::extract::Query;
        use axum::http::{HeaderMap, StatusCode};
        use axum::{Router, routing::post};
        use std::sync::{Arc, Mutex};
        use tokio::sync::oneshot;

        #[derive(Default, Clone, Debug)]
        struct Captured {
            from: String,
            to: String,
            include_exports: Option<String>,
            include_compliance: Option<String>,
            content_type: Option<String>,
            body_len: usize,
        }
        let captured: Arc<Mutex<Captured>> = Arc::new(Mutex::new(Captured::default()));
        let captured_for_handler = captured.clone();

        let app = Router::new().route(
            "/export/regulatory",
            post(
                move |Query(q): Query<std::collections::HashMap<String, String>>,
                      headers: HeaderMap,
                      body: axum::body::Bytes| {
                    let captured = captured_for_handler.clone();
                    async move {
                        let mut c = captured.lock().unwrap();
                        c.from = q.get("from").cloned().unwrap_or_default();
                        c.to = q.get("to").cloned().unwrap_or_default();
                        c.include_exports = q.get("include_exports").cloned();
                        c.include_compliance = q.get("include_compliance").cloned();
                        c.content_type = headers
                            .get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());
                        c.body_len = body.len();
                        // 8-byte placeholder gzip-magic-prefix shape
                        // (real bundle bytes; the SDK doesn't decode).
                        let placeholder = vec![0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
                        (StatusCode::OK, placeholder)
                    }
                },
            ),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (kill_tx, kill_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = kill_rx.await;
                })
                .await
                .unwrap();
        });

        let client = LedgerClient::new(format!("http://{addr}/")).unwrap();
        let from = chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let to = chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_010_000, 0).unwrap();

        // Path A: no readme, no include_exports → minimal request.
        let bytes = client
            .regulatory_export(&from, &to, RegulatoryExportOptions::default())
            .await
            .unwrap();
        assert_eq!(bytes.len(), 8, "placeholder bundle bytes returned verbatim");
        {
            let c = captured.lock().unwrap();
            assert!(c.from.starts_with("2023-"));
            assert!(c.to.starts_with("2023-"));
            assert!(c.include_exports.is_none());
            assert!(c.content_type.is_none() || c.body_len == 0);
            assert_eq!(c.body_len, 0, "no readme → empty body");
        }

        // Path B: readme + include_exports → body, header, query flag.
        let prose = b"# Clavenar\n\nProse here.\n";
        let _ = client
            .regulatory_export(
                &from,
                &to,
                RegulatoryExportOptions {
                    readme: Some(prose.to_vec()),
                    include_exports: true,
                    include_compliance: false,
                },
            )
            .await
            .unwrap();
        {
            let c = captured.lock().unwrap();
            assert_eq!(c.include_exports.as_deref(), Some("true"));
            assert!(c.include_compliance.is_none());
            assert_eq!(c.content_type.as_deref(), Some("text/markdown"));
            assert_eq!(c.body_len, prose.len());
        }

        // Path C: include_compliance flips the query flag.
        let _ = client
            .regulatory_export(
                &from,
                &to,
                RegulatoryExportOptions {
                    include_compliance: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        {
            let c = captured.lock().unwrap();
            assert_eq!(c.include_compliance.as_deref(), Some("true"));
        }

        let _ = kill_tx.send(());
    }

    #[tokio::test]
    async fn regulatory_export_propagates_4xx_as_server_error() {
        // A 400 / 413 from the ledger lands as `ClavenarError::Server`
        // with the status preserved. Lets ctl distinguish "operator
        // misuse" (validation, payload too large) from transport.
        use axum::http::StatusCode;
        use axum::{Router, routing::post};
        use tokio::sync::oneshot;

        let app = Router::new().route(
            "/export/regulatory",
            post(|| async { (StatusCode::PAYLOAD_TOO_LARGE, "readme too big") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (kill_tx, kill_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = kill_rx.await;
                })
                .await
                .unwrap();
        });

        let client = LedgerClient::new(format!("http://{addr}/")).unwrap();
        let from = chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let to = chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_010_000, 0).unwrap();
        let err = client
            .regulatory_export(&from, &to, RegulatoryExportOptions::default())
            .await
            .expect_err("413 must surface as ClavenarError::Server");
        match err {
            ClavenarError::Server { status, body } => {
                assert_eq!(status, reqwest::StatusCode::PAYLOAD_TOO_LARGE);
                assert!(body.contains("too big"));
            }
            other => panic!("expected ClavenarError::Server, got {other:?}"),
        }
        let _ = kill_tx.send(());
    }

    #[tokio::test]
    async fn compliance_evidence_parses_register() {
        use axum::http::StatusCode;
        use axum::{Json, Router, routing::post};
        use tokio::sync::oneshot;

        let app = Router::new().route(
            "/compliance/evidence",
            post(|| async {
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "schema_version": "1",
                        "generated_at": "2026-01-01T00:00:00Z",
                        "window": { "from": "2026-01-01T00:00:00Z", "to": "2026-01-02T00:00:00Z" },
                        "row_count": 2,
                        "chain_verify": { "valid": true, "entries_checked": 2, "first_invalid_seq": null },
                        "controls": [{
                            "control_id": "EU-AI-Act-Article-15",
                            "framework": "EU AI Act",
                            "title": "Accuracy, robustness and cybersecurity",
                            "status": "satisfied",
                            "metric": { "total_requests": 2 },
                            "sample_seqs": [1, 2],
                            "narrative": "ok"
                        }],
                        "disclaimer": "projection of logged facts"
                    })),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (kill_tx, kill_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = kill_rx.await;
                })
                .await
                .unwrap();
        });

        let client = LedgerClient::new(format!("http://{addr}/")).unwrap();
        let from = chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let to = chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_010_000, 0).unwrap();
        let register = client.compliance_evidence(&from, &to).await.unwrap();
        assert_eq!(register.schema_version, "1");
        assert_eq!(register.controls.len(), 1);
        assert_eq!(register.controls[0].status, EvidenceStatus::Satisfied);
        assert_eq!(register.controls[0].metric["total_requests"], 2);
        let _ = kill_tx.send(());
    }
}

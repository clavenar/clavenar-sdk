//! Async Rust client for Clavenar.
//!
//! This crate is the OIDC/SPIFFE-aware client lib called out in the
//! Tier-2 GTM plan, paired with `clavenar-lite`: lite is the OSS proxy
//! you put in front of an agent, this SDK is what an external app calls
//! when it needs to talk to that proxy without relearning the wire
//! contract on every integration.
//!
//! Two thin clients live here:
//!
//! * [`ClavenarClient`] — wraps the proxy's `POST /mcp` surface. Returns
//!   either the upstream JSON-RPC response or a typed
//!   [`ClavenarError::Veto`] parsed from the structured 403 envelope
//!   that both `clavenar-lite` and full-edition `clavenar-proxy` emit
//!   (`layer`, `reasons`, `intent_category`, `correlation_id`, …). The
//!   verbatim body is preserved on `Veto.raw`, and an older server that
//!   returns a non-JSON 403 still surfaces as a `Veto` (raw only).
//!
//! * [`LedgerClient`] — wraps the ledger's `/audit/correlation/{id}`,
//!   `/audit/{agent_id}`, and `/verify` endpoints with typed mirrors of
//!   the server-side [`LedgerEntry`] and [`VerifyResult`] structs.
//!
//! Auth is currently [`Auth::None`] or [`Auth::Bearer`]; mTLS / OIDC /
//! SPIFFE land in a future minor.
//!
//! # Quick start
//!
//! ```no_run
//! use clavenar_sdk::{Auth, ClavenarClient, ClavenarError};
//! use serde_json::json;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let client = ClavenarClient::builder("http://localhost:8088")?
//!     .auth(Auth::Bearer("dev-token".into()))
//!     .build()?;
//!
//! match client.call_tool("search", json!({"q": "rust async"})).await {
//!     Ok(reply)              => println!("{}", reply),
//!     Err(ClavenarError::Veto { intent_category, reasons, .. }) => {
//!         eprintln!("blocked ({}): {:?}", intent_category, reasons);
//!     }
//!     Err(e)                 => return Err(e.into()),
//! }
//! # Ok(()) }
//! ```

mod agents;
mod brain;
mod client;
mod error;
mod http;
mod ledger;
mod pack;
mod policies;
mod sim;

pub use agents::{
    AgentCreated, AgentListFilter, AgentRecord, AgentState, AgentsClient, CertificateBody,
    CertificationCase, CertificationRequest, ContainmentStatus, CreateAgentRequest,
    EnvelopeRequest, ForceHilFlag, GrantConsumption, LifecycleRequest, LifecycleResponse,
    MIGRATION_ACTOR_SUB_PREFIX, OrphanWorkload, SignedCertificate, TenantBudget,
    TenantOffboardResult, create_request_matches,
};
pub use brain::{BrainClient, ExplainPatternRequest, ExplainPatternResponse};
pub use client::{Auth, ClavenarClient, ClavenarClientBuilder};
pub use error::ClavenarError;
pub use http::{HttpProvider, StaticHttpClient};
pub use ledger::{
    AnchorSummary, AuditFilterParams, BaselineDeviation, BaselineWindowProfile, BehavioralBaseline,
    CanaryDeltas, CanaryModel, CanarySignalShare, CanaryWindow, CaseDetail, CaseRecord,
    CaseTimelineEvent, ChainVerifySummary, ComplianceEvidenceScope, ComplianceRegister,
    ControlEvidence, CorpusEntry, EnvelopeAnalysis, EvidenceStatus, ExportOutcome, ExportRecord,
    FleetBehavioralDiff, FleetDiffRow, HuntAgentRollup, HuntParams, HuntResult, LedgerClient,
    LedgerEntry, LifecycleRow, LogEntry, LogReceipt, ModelUpgradeCanary, RegisterWindow,
    RegulatoryExportOptions, ReplayCorpus, ReplayCorpusParams, SilentAgent, SilentAgentsReport,
    SpendAgentRow, SpendRollup, ToolShare, ToolUsage, VerifyResult, WindowDiff,
};
pub use pack::{
    PACK_AUDIENCE, PACK_MANIFEST_FILENAME, PACK_MANIFEST_SCHEMA_VERSION, PACK_SIGNATURE_SIDECAR,
    PackEntry, PackManifest, PackSignature, PackSignatureRef, PackSigner, PackVerifyOutcome,
    VerifyingKey, verify_pack, verifying_key_from_jwks, verifying_key_from_pem,
};
pub use policies::{
    BatchMode, BatchMutationResponse, BatchStateChangeRequest, BatchVerdict, BatchVerdictResult,
    CompileError, ConflictResponse, CreatePolicyRequest, DiffClass, DiffResponse,
    EvaluateBatchError, EvaluateBatchRequest, EvaluateBatchResponse, InstallTemplateRequest,
    LabTemplateRequest, MineCandidate, MineError, MineLabReplay, MineRequest, MineResponse,
    MutationResponse, PoliciesClient, PoliciesListResponse, PolicyDetail, PolicyInputJson,
    PolicyRow, PolicyTemplate, PolicyTemplateDetail, PolicyVersionRow, RollbackRequest,
    StateChangeRequest, UpdatePolicyRequest, ValidatePolicyRequest, ValidatePolicyResponse,
    VersionsListResponse, parse_batch_error, parse_mine_error,
};
pub use sim::{SimAgentRecord, SimClient, SimStats, SimStatus};

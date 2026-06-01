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
//!   [`ClavenarError::Veto`] parsed from the structured 403 body that
//!   `clavenar-lite` emits. The full-edition `clavenar-proxy` returns a
//!   plain-text 403 today; the verbatim body is preserved on the
//!   `Veto.raw` field so callers don't lose information either way.
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
mod policies;
mod sim;

pub use agents::{
    create_request_matches, AgentCreated, AgentListFilter, AgentRecord, AgentState, AgentsClient,
    CreateAgentRequest, EnvelopeRequest, LifecycleRequest, LifecycleResponse,
    MIGRATION_ACTOR_SUB_PREFIX,
};
pub use client::{Auth, ClavenarClient, ClavenarClientBuilder};
pub use error::ClavenarError;
pub use http::{HttpProvider, StaticHttpClient};
pub use ledger::{
    CorpusEntry, ExportRecord, LedgerClient, LedgerEntry, LifecycleRow, RegulatoryExportOptions,
    ReplayCorpus, ReplayCorpusParams, VerifyResult,
};
pub use brain::{
    BrainClient, ExplainPatternRequest, ExplainPatternResponse,
};
pub use policies::{
    parse_batch_error, parse_mine_error, BatchMode, BatchVerdict, BatchVerdictResult, CompileError,
    ConflictResponse, CreatePolicyRequest, DiffClass, DiffResponse, EvaluateBatchError,
    EvaluateBatchRequest, EvaluateBatchResponse, InstallTemplateRequest, LabTemplateRequest,
    MineCandidate, MineError, MineLabReplay, MineRequest, MineResponse, MutationResponse,
    PoliciesClient, PoliciesListResponse, PolicyDetail, PolicyInputJson, PolicyRow, PolicyTemplate,
    PolicyTemplateDetail, PolicyVersionRow, RollbackRequest, StateChangeRequest,
    UpdatePolicyRequest, VersionsListResponse,
};
pub use sim::{SimAgentRecord, SimClient, SimStats, SimStatus};

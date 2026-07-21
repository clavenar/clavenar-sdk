//! SDK-governed execution contract.
//!
//! Proxy authorizes an exact, canonical JSON-RPC payload without invoking the
//! upstream. The SDK invokes its registered executor with those signed bytes,
//! then durably stores the actual effect and submits a terminal receipt from a
//! retrying outbox with the private P-256 key for the same mTLS SVID.
//! Whole-batch decisions share this path. Human-review decisions return a
//! stable pending handle; the retained prepared request polls and atomically
//! claims the eventual exact authorization once. Every effect crosses a
//! durable in-flight boundary before the executor runs. A crash or ambiguous
//! executor result stays explicitly uncertain until the registered executor's
//! idempotency lookup reconciles it; the SDK never executes it automatically
//! again. Automatic transport-retry removal and non-Rust SDK parity remain
//! later work.

use std::{collections::HashSet, fmt, future::Future, ops::Deref, pin::Pin, sync::Arc};

use base64::{Engine as _, engine::general_purpose};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{Auth, ClavenarClient, ClavenarError};

type ToolExecutorFuture =
    Pin<Box<dyn Future<Output = Result<ExecutionEffect, ClavenarError>> + Send + 'static>>;
type ToolExecutorCallback =
    dyn Fn(ToolExecutionRequest) -> ToolExecutorFuture + Send + Sync + 'static;
type ToolEffectLookupFuture =
    Pin<Box<dyn Future<Output = Result<EffectLookupOutcome, ClavenarError>> + Send + 'static>>;
type ToolEffectLookupCallback =
    dyn Fn(EffectLookupRequest) -> ToolEffectLookupFuture + Send + Sync + 'static;

pub type DurableStoreFuture<T> =
    Pin<Box<dyn Future<Output = Result<T, ClavenarError>> + Send + 'static>>;

/// Application-provided durable persistence for SDK-governed effects.
///
/// `commit_effect_and_enqueue_receipt` must atomically store the completion and
/// enqueue its exact receipt. Delivery failures remain pending until
/// `mark_receipt_delivered` succeeds.
pub trait DurableExecutionStore: fmt::Debug + Send + Sync + 'static {
    fn commit_intent(&self, intent: ExecutionIntent) -> DurableStoreFuture<()>;

    /// Whether this store implements an atomic first-claim boundary for a
    /// resumed human-approved authorization. The default is deliberately
    /// false so existing WP-06.5 stores fail before an executor rather than
    /// pretending that an ordinary intent insert is a single-use claim.
    fn supports_single_use_authorization(&self) -> bool {
        false
    }

    /// Atomically commit the exact intent only for the first claimant. A
    /// concurrent or repeated claimant returns `AlreadyClaimed`; it must not
    /// invoke an executor. Stores opt in through
    /// `supports_single_use_authorization` and override this method together.
    fn claim_intent_once(
        &self,
        _intent: ExecutionIntent,
    ) -> DurableStoreFuture<AuthorizationClaim> {
        Box::pin(async {
            Err(ClavenarError::InvalidConfig(
                "durable execution store does not support single-use authorization claims".into(),
            ))
        })
    }

    /// Whether the store atomically commits the exact intent, authorization
    /// use, and in-flight effect marker before an executor can be invoked.
    /// The default is false so an older store fails before decision network
    /// access instead of admitting an automatically repeatable effect.
    fn supports_uncertain_effect_reconciliation(&self) -> bool {
        false
    }

    /// Atomically admit the first effect attempt for this exact intent. A
    /// `SingleUse` admission also consumes the authorization in the same
    /// transaction. Once `Started` has been returned, every later call must
    /// return `AlreadyInFlight` or `AlreadyCompleted`; it must never reopen the
    /// executor boundary.
    fn begin_effect_attempt(
        &self,
        _intent: ExecutionIntent,
        _authorization_use: EffectAuthorizationUse,
    ) -> DurableStoreFuture<EffectAttemptClaim> {
        Box::pin(async {
            Err(ClavenarError::InvalidConfig(
                "durable execution store does not support uncertain-effect reconciliation".into(),
            ))
        })
    }

    /// Load the exact durable intent for an in-flight authorization. This is
    /// used only by explicit reconciliation and must not change its state.
    fn load_uncertain_intent(
        &self,
        _authorization_id: Uuid,
    ) -> DurableStoreFuture<Option<ExecutionIntent>> {
        Box::pin(async {
            Err(ClavenarError::InvalidConfig(
                "durable execution store does not support uncertain-effect reconciliation".into(),
            ))
        })
    }

    fn commit_effect_and_enqueue_receipt(
        &self,
        completion: ExecutionCompletion,
    ) -> DurableStoreFuture<ReceiptOutboxEntry>;

    fn pending_receipts(&self, limit: usize) -> DurableStoreFuture<Vec<ReceiptOutboxEntry>>;

    fn mark_receipt_delivered(
        &self,
        outbox_id: String,
        recorded: ReceiptRecorded,
    ) -> DurableStoreFuture<()>;
}

const DEFAULT_EXECUTOR_ID: &str = "clavenar.registered-sdk-executor/default";
const MAX_OUTBOX_FLUSH: usize = 128;

#[derive(Clone)]
pub(crate) struct RegisteredToolExecutor {
    id: String,
    callback: Arc<ToolExecutorCallback>,
    effect_lookup: Option<Arc<ToolEffectLookupCallback>>,
}

impl RegisteredToolExecutor {
    pub(crate) fn new<F, Fut>(executor: F) -> Self
    where
        F: Fn(Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ExecutionEffect, ClavenarError>> + Send + 'static,
    {
        Self {
            id: DEFAULT_EXECUTOR_ID.into(),
            callback: Arc::new(move |request| Box::pin(executor(request.execution_payload))),
            effect_lookup: None,
        }
    }

    pub(crate) fn new_idempotent<F, Fut>(executor_id: String, executor: F) -> Self
    where
        F: Fn(ToolExecutionRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ExecutionEffect, ClavenarError>> + Send + 'static,
    {
        Self {
            id: executor_id,
            callback: Arc::new(move |request| Box::pin(executor(request))),
            effect_lookup: None,
        }
    }

    pub(crate) fn new_reconciling<F, Fut, L, LookupFut>(
        executor_id: String,
        executor: F,
        effect_lookup: L,
    ) -> Self
    where
        F: Fn(ToolExecutionRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ExecutionEffect, ClavenarError>> + Send + 'static,
        L: Fn(EffectLookupRequest) -> LookupFut + Send + Sync + 'static,
        LookupFut: Future<Output = Result<EffectLookupOutcome, ClavenarError>> + Send + 'static,
    {
        Self {
            id: executor_id,
            callback: Arc::new(move |request| Box::pin(executor(request))),
            effect_lookup: Some(Arc::new(move |request| Box::pin(effect_lookup(request)))),
        }
    }

    async fn execute(
        &self,
        request: ToolExecutionRequest,
    ) -> Result<ExecutionEffect, ClavenarError> {
        (self.callback)(request).await
    }

    async fn lookup_effect(
        &self,
        request: EffectLookupRequest,
    ) -> Option<Result<EffectLookupOutcome, ClavenarError>> {
        match &self.effect_lookup {
            Some(lookup) => Some(lookup(request).await),
            None => None,
        }
    }
}

impl fmt::Debug for RegisteredToolExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegisteredToolExecutor")
    }
}

pub const DECISION_CONTRACT: &str = "clavenar.decision/v1";
pub const DECISION_CONTRACT_HEADER: &str = "x-clavenar-decision-contract";
pub const EXECUTION_CONTRACT: &str = "clavenar.execution/v1";
pub const EXECUTION_CONTRACT_HEADER: &str = "x-clavenar-execution-contract";
pub const IDEMPOTENCY_ID_HEADER: &str = "x-clavenar-idempotency-id";
pub const PENDING_AUTHORIZATION_CONTRACT: &str = "clavenar.pending-authorization/v1";
pub const PENDING_ID_HEADER: &str = "x-clavenar-pending-id";
pub const PENDING_PAYLOAD_SHA256_HEADER: &str = "x-clavenar-pending-payload-sha256";
pub const ATOMIC_TOOL_CALL_BATCH_CONTRACT: &str = "clavenar.atomic-tool-call-batch/v1";
pub const ATOMIC_TOOL_CALL_BATCH_METHOD: &str = "clavenar/tools.batch";
pub const ATOMIC_TOOL_CALL_BATCH_NAME: &str = "clavenar.atomic-batch";
pub const SDK_EXECUTION_AUTHORITY_CONTRACT: &str =
    include_str!("../contracts/sdk-execution-authority-v1.json");
pub const SIDE_EFFECT_FREE_DECISION_CONTRACT: &str =
    include_str!("../contracts/side-effect-free-decision-v1.json");
pub const ATOMIC_TOOL_CALL_BATCH_CONTRACT_DOCUMENT: &str =
    include_str!("../contracts/atomic-tool-call-batch-v1.json");
pub const STABLE_REQUEST_IDENTITY_CONTRACT: &str =
    include_str!("../contracts/stable-request-identity-v1.json");
pub const DURABLE_EXECUTION_OUTBOX_CONTRACT: &str =
    include_str!("../contracts/durable-execution-outbox-v1.json");
pub const PENDING_AUTHORIZATION_CONTRACT_DOCUMENT: &str =
    include_str!("../contracts/pending-authorization-v1.json");
pub const UNCERTAIN_EFFECT_RECONCILIATION_CONTRACT: &str =
    include_str!("../contracts/uncertain-effect-reconciliation-v1.json");
pub const DURABLE_EXECUTION_OUTBOX_WIRE_CONTRACT: &str = "clavenar.sdk-durable-intent-outbox/v1";
pub const UNCERTAIN_EFFECT_CONTRACT: &str = "clavenar.uncertain-effect/v1";

const MAX_BATCH_CALLS: usize = 128;

/// One model-produced sibling in an atomically authorized tool-call batch.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ModelToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

/// A serializable single-tool request whose stable identity exists before any
/// authorization or execution network attempt.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PreparedToolRequest {
    idempotency_id: Uuid,
    name: String,
    arguments: Value,
}

impl PreparedToolRequest {
    /// Prepare a new request and allocate its stable identity locally.
    pub fn new(name: impl Into<String>, arguments: Value) -> Result<Self, ClavenarError> {
        Self::restore(Uuid::new_v4(), name, arguments)
    }

    /// Restore a previously persisted request without replacing its identity.
    pub fn restore(
        idempotency_id: Uuid,
        name: impl Into<String>,
        arguments: Value,
    ) -> Result<Self, ClavenarError> {
        let prepared = Self {
            idempotency_id,
            name: name.into(),
            arguments,
        };
        prepared.validate()?;
        Ok(prepared)
    }

    pub fn idempotency_id(&self) -> Uuid {
        self.idempotency_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn arguments(&self) -> &Value {
        &self.arguments
    }

    fn validate(&self) -> Result<(), ClavenarError> {
        validate_tool_name(&self.name)
    }
}

/// A serializable atomic batch whose stable identity exists before any
/// authorization or execution network attempt.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PreparedToolBatch {
    idempotency_id: Uuid,
    calls: Vec<ModelToolCall>,
}

impl PreparedToolBatch {
    /// Prepare a new batch and allocate its stable identity locally.
    pub fn new(calls: Vec<ModelToolCall>) -> Result<Self, ClavenarError> {
        Self::restore(Uuid::new_v4(), calls)
    }

    /// Restore a previously persisted batch without replacing its identity.
    pub fn restore(idempotency_id: Uuid, calls: Vec<ModelToolCall>) -> Result<Self, ClavenarError> {
        let prepared = Self {
            idempotency_id,
            calls,
        };
        prepared.validate()?;
        Ok(prepared)
    }

    pub fn idempotency_id(&self) -> Uuid {
        self.idempotency_id
    }

    pub fn calls(&self) -> &[ModelToolCall] {
        &self.calls
    }

    fn validate(&self) -> Result<(), ClavenarError> {
        validate_model_tool_calls(&self.calls)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct AtomicBatchArguments {
    contract: String,
    calls: Vec<ModelToolCall>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct AtomicBatchParams {
    name: String,
    arguments: AtomicBatchArguments,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct AtomicBatchEnvelope {
    jsonrpc: String,
    id: String,
    method: String,
    params: AtomicBatchParams,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentitySignature {
    pub algorithm: String,
    pub key_id: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundleProvenance {
    pub schema_version: u8,
    pub version: String,
    pub hash_sha256: String,
    pub policy_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub contract: String,
    pub stage: String,
    pub authorization_id: Uuid,
    pub idempotency_id: Uuid,
    pub correlation_id: Uuid,
    pub agent_id: String,
    pub agent_spiffe: String,
    pub tenant: String,
    pub credential_fingerprint: String,
    pub method: String,
    pub tool_name: String,
    pub execution_payload: Value,
    pub payload_sha256: String,
    pub decision_principal: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modification_diff: Option<Value>,
    pub policy_bundle: PolicyBundleProvenance,
    pub brain_version: String,
    pub brain_evidence_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorization {
    pub authorization: Authorization,
    pub identity_signature: IdentitySignature,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkloadSignature {
    pub algorithm: String,
    pub credential_fingerprint: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceipt {
    pub contract: String,
    pub stage: String,
    pub authorization_id: Uuid,
    pub idempotency_id: Uuid,
    pub correlation_id: Uuid,
    pub agent_id: String,
    pub agent_spiffe: String,
    pub tenant: String,
    pub credential_fingerprint: String,
    pub method: String,
    pub payload_sha256: String,
    pub authorization: SignedAuthorization,
    pub result_sha256: String,
    pub effect_id: String,
    pub workload_signature: WorkloadSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionIntent {
    pub contract: String,
    pub stage: String,
    pub authorization_id: Uuid,
    pub idempotency_id: Uuid,
    pub tenant: String,
    pub workload_id: String,
    pub workload_spiffe: String,
    pub payload_sha256: String,
    pub executor_id: String,
    pub authorization: SignedAuthorization,
}

/// Whether the durable in-flight transition consumes a direct decision or a
/// one-use human-approved authorization.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EffectAuthorizationUse {
    Direct,
    SingleUse,
}

/// Result of the store's atomic effect-attempt admission.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EffectAttemptClaim {
    Started,
    AlreadyInFlight,
    AlreadyCompleted,
}

/// Exact input to an idempotency-capable registered tool executor.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolExecutionRequest {
    pub idempotency_id: Uuid,
    pub authorization_id: Uuid,
    pub executor_id: String,
    pub execution_payload: Value,
}

/// Exact, non-executing query supplied to a registered effect lookup.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectLookupRequest {
    pub authorization_id: Uuid,
    pub idempotency_id: Uuid,
    pub executor_id: String,
    pub payload_sha256: String,
}

impl Deref for ToolExecutionRequest {
    type Target = Value;

    fn deref(&self) -> &Self::Target {
        &self.execution_payload
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCompletion {
    pub contract: String,
    pub stage: String,
    pub authorization_id: Uuid,
    pub idempotency_id: Uuid,
    pub executor_id: String,
    pub actual_result: Value,
    pub actual_result_sha256: String,
    pub effect_id: String,
    pub receipt: ExecutionReceipt,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptOutboxEntry {
    pub outbox_id: String,
    pub receipt: ExecutionReceipt,
}

#[derive(Clone, Debug, Serialize)]
struct UnsignedExecutionReceipt<'a> {
    contract: &'a str,
    stage: &'a str,
    authorization_id: Uuid,
    idempotency_id: Uuid,
    correlation_id: Uuid,
    agent_id: &'a str,
    agent_spiffe: &'a str,
    tenant: &'a str,
    credential_fingerprint: &'a str,
    method: &'a str,
    payload_sha256: &'a str,
    authorization: &'a SignedAuthorization,
    result_sha256: &'a str,
    effect_id: &'a str,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEffect {
    pub result: Value,
    pub effect_id: String,
}

/// Executor-side idempotency/effect lookup result. `NotFound` is not
/// permission to execute again automatically; only `Found` can complete
/// reconciliation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EffectLookupOutcome {
    Found { effect: ExecutionEffect },
    NotFound,
    Ambiguous,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptRecorded {
    pub status: String,
    pub contract: String,
    pub stage: String,
    pub authorization_id: Uuid,
    pub receipt_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizationClaim {
    Claimed,
    AlreadyClaimed,
}

/// Why an exact effect cannot currently be reported complete. Every reason is
/// non-executable and requires explicit reconciliation or human handling.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UncertainEffectReason {
    InFlightAfterPriorAttempt,
    ExecutorOutcomeUnknown,
    LookupNotRegistered,
    LookupUnavailable,
    EffectNotFound,
    LookupAmbiguous,
    LookupInvalid,
    DurableIntentUnavailable,
    ReconciledEffectPersistenceFailed,
}

/// Serializable, non-executable handle for an effect whose exact durable
/// attempt crossed the in-flight boundary without a trusted completion.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UncertainExecution {
    pub contract: String,
    pub status: String,
    pub reason: UncertainEffectReason,
    pub authorization_id: Uuid,
    pub idempotency_id: Uuid,
    pub tenant: String,
    pub workload_id: String,
    pub workload_spiffe: String,
    pub payload_sha256: String,
    pub executor_id: String,
    pub effect_lookup_registered: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PendingAuthorization {
    pub contract: String,
    pub status: String,
    pub pending_id: Uuid,
    pub idempotency_id: Uuid,
    pub correlation_id: Uuid,
    pub payload_sha256: String,
    pub ttl_seconds: i64,
    pub poll_after_ms: u64,
}

#[derive(Clone, Debug, PartialEq)]
enum AuthorizationState {
    Authorized(Box<SignedAuthorization>),
    Pending(PendingAuthorization),
}

enum KnownEffectCompletionError {
    PersistenceUncertain,
    ReceiptDelivery(ClavenarError),
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionOutcome {
    pub receipt: ReceiptRecorded,
    pub result: Value,
    pub effect_id: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ResumableExecutionOutcome {
    Pending(PendingAuthorization),
    Completed(ExecutionOutcome),
}

#[derive(Clone, Debug, PartialEq)]
pub enum ExecutionReconciliationOutcome {
    Completed(ExecutionOutcome),
    Uncertain(UncertainExecution),
}

impl ClavenarClient {
    /// Authorize a locally prepared single-tool request without changing its
    /// retained identity.
    pub async fn authorize_prepared_tool(
        &self,
        prepared: &PreparedToolRequest,
    ) -> Result<SignedAuthorization, ClavenarError> {
        prepared.validate()?;
        self.authorize_tool(
            prepared.idempotency_id,
            &prepared.name,
            prepared.arguments.clone(),
        )
        .await
    }

    /// Request side-effect-free authorization for an exact tool payload.
    /// Reusing `idempotency_id` is safe only with byte-equivalent input.
    pub async fn authorize_tool(
        &self,
        idempotency_id: Uuid,
        name: &str,
        arguments: Value,
    ) -> Result<SignedAuthorization, ClavenarError> {
        let body = tool_envelope(idempotency_id, name, arguments);
        self.authorize_payload(idempotency_id, &body).await
    }

    /// Request one atomic decision for a complete ordered model tool-call
    /// batch. No sibling is exposed to the registered executor by this method.
    pub async fn authorize_tool_batch(
        &self,
        idempotency_id: Uuid,
        calls: Vec<ModelToolCall>,
    ) -> Result<SignedAuthorization, ClavenarError> {
        validate_model_tool_calls(&calls)?;
        let body = atomic_batch_envelope(idempotency_id, calls.clone());
        let authorization = self.authorize_payload(idempotency_id, &body).await?;
        validate_batch_authorization(&authorization, idempotency_id, &calls, &body)?;
        Ok(authorization)
    }

    /// Authorize a locally prepared atomic batch without changing its retained
    /// identity or sibling order.
    pub async fn authorize_prepared_tool_batch(
        &self,
        prepared: &PreparedToolBatch,
    ) -> Result<SignedAuthorization, ClavenarError> {
        prepared.validate()?;
        self.authorize_tool_batch(prepared.idempotency_id, prepared.calls.clone())
            .await
    }

    /// Authorize, execute through the registered executor, and record one
    /// exact tool effect.
    ///
    /// The registered executor receives the complete authorized JSON-RPC
    /// value, including any HIL modification. Proxy never executes this mode,
    /// and the authorized payload is not returned to the caller. If execution
    /// or receipt recording fails, successful completion is not reported.
    pub async fn execute_tool(
        &self,
        idempotency_id: Uuid,
        name: &str,
        arguments: Value,
    ) -> Result<ExecutionOutcome, ClavenarError> {
        let (executor, signing_key, store) = self.execution_dependencies()?;
        let authorization = self.authorize_tool(idempotency_id, name, arguments).await?;
        self.execute_authorization(executor, signing_key, store, authorization, false)
            .await
    }

    /// Execute a locally prepared single-tool request with its retained
    /// identity.
    pub async fn execute_prepared_tool(
        &self,
        prepared: &PreparedToolRequest,
    ) -> Result<ExecutionOutcome, ClavenarError> {
        prepared.validate()?;
        self.execute_tool(
            prepared.idempotency_id,
            &prepared.name,
            prepared.arguments.clone(),
        )
        .await
    }

    /// Atomically authorize a complete model tool-call batch, then invoke the
    /// registered SDK executor exactly once with the whole signed payload.
    /// Individual siblings are never returned to the host's normal tool loop.
    pub async fn execute_tool_batch(
        &self,
        idempotency_id: Uuid,
        calls: Vec<ModelToolCall>,
    ) -> Result<ExecutionOutcome, ClavenarError> {
        let (executor, signing_key, store) = self.execution_dependencies()?;
        let authorization = self.authorize_tool_batch(idempotency_id, calls).await?;
        self.execute_authorization(executor, signing_key, store, authorization, false)
            .await
    }

    /// Execute a locally prepared atomic batch with its retained identity and
    /// sibling order.
    pub async fn execute_prepared_tool_batch(
        &self,
        prepared: &PreparedToolBatch,
    ) -> Result<ExecutionOutcome, ClavenarError> {
        prepared.validate()?;
        self.execute_tool_batch(prepared.idempotency_id, prepared.calls.clone())
            .await
    }

    /// Start a prepared SDK-governed tool request. A human-review decision
    /// returns a serializable pending handle and releases no executor effect.
    /// A direct authorization completes through the normal durable path.
    pub async fn begin_prepared_tool_execution(
        &self,
        prepared: &PreparedToolRequest,
    ) -> Result<ResumableExecutionOutcome, ClavenarError> {
        prepared.validate()?;
        let (executor, signing_key, store) = self.execution_dependencies()?;
        let body = tool_envelope(
            prepared.idempotency_id,
            &prepared.name,
            prepared.arguments.clone(),
        );
        match self
            .authorize_payload_state(prepared.idempotency_id, &body, None)
            .await?
        {
            AuthorizationState::Pending(pending) => Ok(ResumableExecutionOutcome::Pending(pending)),
            AuthorizationState::Authorized(authorization) => self
                .execute_authorization(executor, signing_key, store, *authorization, false)
                .await
                .map(ResumableExecutionOutcome::Completed),
        }
    }

    /// Poll and resume the exact retained prepared request. The caller does
    /// not provide another model tool call; local digest validation happens
    /// before HTTP. An approval is atomically claimed from the durable store
    /// before the registered executor is released.
    pub async fn resume_prepared_tool_execution(
        &self,
        prepared: &PreparedToolRequest,
        pending: &PendingAuthorization,
    ) -> Result<ResumableExecutionOutcome, ClavenarError> {
        prepared.validate()?;
        let (executor, signing_key, store) = self.execution_dependencies()?;
        require_single_use_store(store)?;
        let body = tool_envelope(
            prepared.idempotency_id,
            &prepared.name,
            prepared.arguments.clone(),
        );
        validate_pending_authorization(pending, prepared.idempotency_id, &body)?;
        match self
            .authorize_payload_state(prepared.idempotency_id, &body, Some(pending))
            .await?
        {
            AuthorizationState::Pending(retained) => {
                if retained != *pending {
                    return Err(ClavenarError::InvalidConfig(
                        "Proxy changed the retained pending authorization handle".into(),
                    ));
                }
                Ok(ResumableExecutionOutcome::Pending(retained))
            }
            AuthorizationState::Authorized(authorization) => self
                .execute_authorization(executor, signing_key, store, *authorization, true)
                .await
                .map(ResumableExecutionOutcome::Completed),
        }
    }

    /// Batch counterpart to [`Self::begin_prepared_tool_execution`].
    pub async fn begin_prepared_tool_batch_execution(
        &self,
        prepared: &PreparedToolBatch,
    ) -> Result<ResumableExecutionOutcome, ClavenarError> {
        prepared.validate()?;
        let (executor, signing_key, store) = self.execution_dependencies()?;
        let body = atomic_batch_envelope(prepared.idempotency_id, prepared.calls.clone());
        match self
            .authorize_payload_state(prepared.idempotency_id, &body, None)
            .await?
        {
            AuthorizationState::Pending(pending) => Ok(ResumableExecutionOutcome::Pending(pending)),
            AuthorizationState::Authorized(authorization) => {
                validate_batch_authorization(
                    &authorization,
                    prepared.idempotency_id,
                    &prepared.calls,
                    &body,
                )?;
                self.execute_authorization(executor, signing_key, store, *authorization, false)
                    .await
                    .map(ResumableExecutionOutcome::Completed)
            }
        }
    }

    /// Batch counterpart to [`Self::resume_prepared_tool_execution`].
    pub async fn resume_prepared_tool_batch_execution(
        &self,
        prepared: &PreparedToolBatch,
        pending: &PendingAuthorization,
    ) -> Result<ResumableExecutionOutcome, ClavenarError> {
        prepared.validate()?;
        let (executor, signing_key, store) = self.execution_dependencies()?;
        require_single_use_store(store)?;
        let body = atomic_batch_envelope(prepared.idempotency_id, prepared.calls.clone());
        validate_pending_authorization(pending, prepared.idempotency_id, &body)?;
        match self
            .authorize_payload_state(prepared.idempotency_id, &body, Some(pending))
            .await?
        {
            AuthorizationState::Pending(retained) => {
                if retained != *pending {
                    return Err(ClavenarError::InvalidConfig(
                        "Proxy changed the retained pending authorization handle".into(),
                    ));
                }
                Ok(ResumableExecutionOutcome::Pending(retained))
            }
            AuthorizationState::Authorized(authorization) => {
                validate_batch_authorization(
                    &authorization,
                    prepared.idempotency_id,
                    &prepared.calls,
                    &body,
                )?;
                self.execute_authorization(executor, signing_key, store, *authorization, true)
                    .await
                    .map(ResumableExecutionOutcome::Completed)
            }
        }
    }

    /// Deliver pending workload-signed receipts without authorizing or
    /// executing any tool. Each entry is attempted once per call and remains
    /// pending unless Proxy confirms persistence and the store marks it
    /// delivered.
    pub async fn flush_execution_receipt_outbox(
        &self,
        limit: usize,
    ) -> Result<usize, ClavenarError> {
        if limit == 0 || limit > MAX_OUTBOX_FLUSH {
            return Err(ClavenarError::InvalidConfig(format!(
                "receipt outbox flush limit must contain 1..={MAX_OUTBOX_FLUSH} entries"
            )));
        }
        let store = self.durable_execution_store.as_deref().ok_or_else(|| {
            ClavenarError::InvalidConfig(
                "durable_execution_store is required for receipt outbox delivery".into(),
            )
        })?;
        let pending = store.pending_receipts(limit).await?;
        if pending.len() > limit {
            return Err(ClavenarError::InvalidConfig(
                "durable execution store exceeded the requested outbox limit".into(),
            ));
        }
        let mut delivered = 0;
        for entry in pending {
            self.deliver_outbox_entry(store, entry).await?;
            delivered += 1;
        }
        Ok(delivered)
    }

    /// Reconcile one explicit uncertain effect through the registered
    /// executor's idempotency lookup. This method never invokes the executor.
    /// A missing, unavailable, ambiguous, or invalid lookup result remains an
    /// explicit uncertain outcome for later reconciliation or human handling.
    pub async fn reconcile_uncertain_effect(
        &self,
        uncertain: &UncertainExecution,
    ) -> Result<ExecutionReconciliationOutcome, ClavenarError> {
        validate_uncertain_execution(uncertain)?;
        let (executor, signing_key, store) = self.execution_dependencies()?;
        if executor.id != uncertain.executor_id {
            return Err(ClavenarError::InvalidConfig(
                "uncertain effect is bound to a different registered executor".into(),
            ));
        }
        let intent = match store
            .load_uncertain_intent(uncertain.authorization_id)
            .await
        {
            Ok(Some(intent)) => intent,
            Ok(None) | Err(_) => {
                return Ok(ExecutionReconciliationOutcome::Uncertain(
                    uncertain_with_reason(
                        uncertain,
                        UncertainEffectReason::DurableIntentUnavailable,
                        executor.effect_lookup.is_some(),
                    ),
                ));
            }
        };
        if validate_uncertain_intent(uncertain, &intent).is_err() {
            return Ok(ExecutionReconciliationOutcome::Uncertain(
                uncertain_with_reason(
                    uncertain,
                    UncertainEffectReason::LookupInvalid,
                    executor.effect_lookup.is_some(),
                ),
            ));
        }
        let lookup = executor
            .lookup_effect(EffectLookupRequest {
                authorization_id: intent.authorization_id,
                idempotency_id: intent.idempotency_id,
                executor_id: intent.executor_id.clone(),
                payload_sha256: intent.payload_sha256.clone(),
            })
            .await;
        let lookup = match lookup {
            None => {
                return Ok(ExecutionReconciliationOutcome::Uncertain(
                    uncertain_with_reason(
                        uncertain,
                        UncertainEffectReason::LookupNotRegistered,
                        false,
                    ),
                ));
            }
            Some(Err(_)) => {
                return Ok(ExecutionReconciliationOutcome::Uncertain(
                    uncertain_with_reason(
                        uncertain,
                        UncertainEffectReason::LookupUnavailable,
                        true,
                    ),
                ));
            }
            Some(Ok(outcome)) => outcome,
        };
        let effect = match lookup {
            EffectLookupOutcome::Found { effect } => effect,
            EffectLookupOutcome::NotFound => {
                return Ok(ExecutionReconciliationOutcome::Uncertain(
                    uncertain_with_reason(uncertain, UncertainEffectReason::EffectNotFound, true),
                ));
            }
            EffectLookupOutcome::Ambiguous => {
                return Ok(ExecutionReconciliationOutcome::Uncertain(
                    uncertain_with_reason(uncertain, UncertainEffectReason::LookupAmbiguous, true),
                ));
            }
        };
        if validate_execution_effect(&effect).is_err() {
            return Ok(ExecutionReconciliationOutcome::Uncertain(
                uncertain_with_reason(uncertain, UncertainEffectReason::LookupInvalid, true),
            ));
        }
        match self
            .complete_known_effect(
                signing_key,
                store,
                intent.authorization,
                effect,
                &executor.id,
            )
            .await
        {
            Ok(completed) => Ok(ExecutionReconciliationOutcome::Completed(completed)),
            Err(KnownEffectCompletionError::PersistenceUncertain) => Ok(
                ExecutionReconciliationOutcome::Uncertain(uncertain_with_reason(
                    uncertain,
                    UncertainEffectReason::ReconciledEffectPersistenceFailed,
                    true,
                )),
            ),
            Err(KnownEffectCompletionError::ReceiptDelivery(error)) => Err(error),
        }
    }

    async fn authorize_payload(
        &self,
        idempotency_id: Uuid,
        body: &Value,
    ) -> Result<SignedAuthorization, ClavenarError> {
        match self
            .authorize_payload_state(idempotency_id, body, None)
            .await?
        {
            AuthorizationState::Authorized(authorization) => Ok(*authorization),
            AuthorizationState::Pending(pending) => Err(ClavenarError::Server {
                status: StatusCode::ACCEPTED,
                body: serde_json::to_string(&pending)?,
            }),
        }
    }

    async fn authorize_payload_state(
        &self,
        idempotency_id: Uuid,
        body: &Value,
        pending: Option<&PendingAuthorization>,
    ) -> Result<AuthorizationState, ClavenarError> {
        let endpoint = self
            .base_url
            .join("mcp")
            .map_err(|error| ClavenarError::InvalidConfig(format!("join /mcp: {error}")))?;
        let mut request = self
            .http
            .client()
            .post(endpoint)
            .header(DECISION_CONTRACT_HEADER, DECISION_CONTRACT)
            .header(IDEMPOTENCY_ID_HEADER, idempotency_id.to_string())
            .json(body);
        if let Some(pending) = pending {
            request = request
                .header(PENDING_ID_HEADER, pending.pending_id.to_string())
                .header(PENDING_PAYLOAD_SHA256_HEADER, &pending.payload_sha256);
        }
        if let Auth::Bearer(token) = &self.auth {
            request = request.bearer_auth(token);
        }
        let response = request.send().await?;
        let status = response.status();
        let raw = response.text().await?;
        if status == StatusCode::ACCEPTED {
            let pending: PendingAuthorization = serde_json::from_str(&raw)?;
            validate_pending_authorization(&pending, idempotency_id, body)?;
            return Ok(AuthorizationState::Pending(pending));
        }
        if status != StatusCode::OK {
            return execution_http_error(status, raw);
        }
        let authorization: SignedAuthorization = serde_json::from_str(&raw)?;
        validate_authorization(&authorization, idempotency_id)?;
        if authorization.authorization.modification_diff.is_none()
            && authorization.authorization.execution_payload != *body
        {
            return Err(ClavenarError::InvalidConfig(
                "Proxy returned an unmodified authorization for a different payload".into(),
            ));
        }
        if pending.is_some_and(|pending| {
            authorization.authorization.correlation_id != pending.correlation_id
        }) {
            return Err(ClavenarError::InvalidConfig(
                "Proxy returned an authorization for a different pending correlation".into(),
            ));
        }
        Ok(AuthorizationState::Authorized(Box::new(authorization)))
    }

    fn execution_dependencies(
        &self,
    ) -> Result<
        (
            &RegisteredToolExecutor,
            &SigningKey,
            &dyn DurableExecutionStore,
        ),
        ClavenarError,
    > {
        let executor = self.tool_executor.as_ref().ok_or_else(|| {
            ClavenarError::InvalidConfig(
                "tool_executor is required for SDK-governed execution".into(),
            )
        })?;
        validate_executor_id(&executor.id)?;
        let signing_key = self.execution_signing_key.as_deref().ok_or_else(|| {
            ClavenarError::InvalidConfig(
                "execution_signing_key is required for SDK-governed execution".into(),
            )
        })?;
        let store = self.durable_execution_store.as_deref().ok_or_else(|| {
            ClavenarError::InvalidConfig(
                "durable_execution_store is required for SDK-governed execution".into(),
            )
        })?;
        require_uncertain_effect_store(store)?;
        Ok((executor, signing_key, store))
    }

    async fn execute_authorization(
        &self,
        executor: &RegisteredToolExecutor,
        signing_key: &SigningKey,
        store: &dyn DurableExecutionStore,
        authorization: SignedAuthorization,
        single_use: bool,
    ) -> Result<ExecutionOutcome, ClavenarError> {
        let claims = &authorization.authorization;
        let intent = ExecutionIntent {
            contract: DURABLE_EXECUTION_OUTBOX_WIRE_CONTRACT.into(),
            stage: "execution.intent".into(),
            authorization_id: claims.authorization_id,
            idempotency_id: claims.idempotency_id,
            tenant: claims.tenant.clone(),
            workload_id: claims.agent_id.clone(),
            workload_spiffe: claims.agent_spiffe.clone(),
            payload_sha256: claims.payload_sha256.clone(),
            executor_id: executor.id.clone(),
            authorization: authorization.clone(),
        };
        let uncertain = uncertain_from_intent(
            &intent,
            UncertainEffectReason::ExecutorOutcomeUnknown,
            executor.effect_lookup.is_some(),
        );
        let authorization_use = if single_use {
            EffectAuthorizationUse::SingleUse
        } else {
            EffectAuthorizationUse::Direct
        };
        match store
            .begin_effect_attempt(intent, authorization_use)
            .await?
        {
            EffectAttemptClaim::Started => {}
            EffectAttemptClaim::AlreadyInFlight => {
                return Err(ClavenarError::ExecutionUncertain(Box::new(
                    uncertain_with_reason(
                        &uncertain,
                        UncertainEffectReason::InFlightAfterPriorAttempt,
                        executor.effect_lookup.is_some(),
                    ),
                )));
            }
            EffectAttemptClaim::AlreadyCompleted => {
                return Err(ClavenarError::ExecutionAlreadyCompleted {
                    authorization_id: claims.authorization_id,
                    idempotency_id: claims.idempotency_id,
                });
            }
        }
        let effect = match executor
            .execute(ToolExecutionRequest {
                idempotency_id: claims.idempotency_id,
                authorization_id: claims.authorization_id,
                executor_id: executor.id.clone(),
                execution_payload: claims.execution_payload.clone(),
            })
            .await
        {
            Ok(effect) => effect,
            Err(_) => return Err(ClavenarError::ExecutionUncertain(Box::new(uncertain))),
        };
        if validate_execution_effect(&effect).is_err() {
            return Err(ClavenarError::ExecutionUncertain(Box::new(
                uncertain_with_reason(
                    &uncertain,
                    UncertainEffectReason::LookupInvalid,
                    executor.effect_lookup.is_some(),
                ),
            )));
        }
        match self
            .complete_known_effect(signing_key, store, authorization, effect, &executor.id)
            .await
        {
            Ok(outcome) => Ok(outcome),
            Err(KnownEffectCompletionError::PersistenceUncertain) => {
                Err(ClavenarError::ExecutionUncertain(Box::new(uncertain)))
            }
            Err(KnownEffectCompletionError::ReceiptDelivery(error)) => Err(error),
        }
    }

    async fn complete_known_effect(
        &self,
        signing_key: &SigningKey,
        store: &dyn DurableExecutionStore,
        authorization: SignedAuthorization,
        effect: ExecutionEffect,
        executor_id: &str,
    ) -> Result<ExecutionOutcome, KnownEffectCompletionError> {
        let claims = &authorization.authorization;
        let result_sha256 = sha256(canonical_json_value(&effect.result).as_bytes());
        let unsigned = UnsignedExecutionReceipt {
            contract: EXECUTION_CONTRACT,
            stage: "execution.completed",
            authorization_id: claims.authorization_id,
            idempotency_id: claims.idempotency_id,
            correlation_id: claims.correlation_id,
            agent_id: &claims.agent_id,
            agent_spiffe: &claims.agent_spiffe,
            tenant: &claims.tenant,
            credential_fingerprint: &claims.credential_fingerprint,
            method: &claims.method,
            payload_sha256: &claims.payload_sha256,
            authorization: &authorization,
            result_sha256: &result_sha256,
            effect_id: &effect.effect_id,
        };
        let canonical_unsigned = canonical_json(&unsigned)
            .map_err(|_| KnownEffectCompletionError::PersistenceUncertain)?;
        let signature: Signature = signing_key.sign(canonical_unsigned.as_bytes());
        let receipt = ExecutionReceipt {
            contract: EXECUTION_CONTRACT.into(),
            stage: "execution.completed".into(),
            authorization_id: claims.authorization_id,
            idempotency_id: claims.idempotency_id,
            correlation_id: claims.correlation_id,
            agent_id: claims.agent_id.clone(),
            agent_spiffe: claims.agent_spiffe.clone(),
            tenant: claims.tenant.clone(),
            credential_fingerprint: claims.credential_fingerprint.clone(),
            method: claims.method.clone(),
            payload_sha256: claims.payload_sha256.clone(),
            authorization: authorization.clone(),
            result_sha256: result_sha256.clone(),
            effect_id: effect.effect_id.clone(),
            workload_signature: WorkloadSignature {
                algorithm: "ES256".into(),
                credential_fingerprint: claims.credential_fingerprint.clone(),
                value: general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            },
        };
        let queued = store
            .commit_effect_and_enqueue_receipt(ExecutionCompletion {
                contract: DURABLE_EXECUTION_OUTBOX_WIRE_CONTRACT.into(),
                stage: "execution.effect-recorded".into(),
                authorization_id: claims.authorization_id,
                idempotency_id: claims.idempotency_id,
                executor_id: executor_id.into(),
                actual_result: effect.result.clone(),
                actual_result_sha256: result_sha256,
                effect_id: effect.effect_id.clone(),
                receipt: receipt.clone(),
            })
            .await
            .map_err(|_| KnownEffectCompletionError::PersistenceUncertain)?;
        if queued.receipt != receipt {
            return Err(KnownEffectCompletionError::PersistenceUncertain);
        }
        let recorded = self
            .deliver_outbox_entry(store, queued)
            .await
            .map_err(KnownEffectCompletionError::ReceiptDelivery)?;
        Ok(ExecutionOutcome {
            receipt: recorded,
            result: effect.result,
            effect_id: effect.effect_id,
        })
    }

    async fn deliver_outbox_entry(
        &self,
        store: &dyn DurableExecutionStore,
        entry: ReceiptOutboxEntry,
    ) -> Result<ReceiptRecorded, ClavenarError> {
        validate_outbox_entry(&entry)?;
        let recorded = self.record_receipt(&entry.receipt).await?;
        if recorded.authorization_id != entry.receipt.authorization_id
            || recorded.contract != EXECUTION_CONTRACT
            || recorded.stage != "execution.completed"
        {
            return Err(ClavenarError::InvalidConfig(
                "Proxy returned invalid receipt persistence metadata".into(),
            ));
        }
        store
            .mark_receipt_delivered(entry.outbox_id, recorded.clone())
            .await?;
        Ok(recorded)
    }

    async fn record_receipt(
        &self,
        receipt: &ExecutionReceipt,
    ) -> Result<ReceiptRecorded, ClavenarError> {
        let endpoint = self.base_url.join("execution-receipts").map_err(|error| {
            ClavenarError::InvalidConfig(format!("join /execution-receipts: {error}"))
        })?;
        let mut request = self.http.client().post(endpoint).json(receipt);
        if let Auth::Bearer(token) = &self.auth {
            request = request.bearer_auth(token);
        }
        let response = request.send().await?;
        let status = response.status();
        let raw = response.text().await?;
        if status != StatusCode::OK && status != StatusCode::CREATED {
            return execution_http_error(status, raw);
        }
        Ok(serde_json::from_str(&raw)?)
    }
}

fn atomic_batch_envelope(idempotency_id: Uuid, calls: Vec<ModelToolCall>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": idempotency_id.to_string(),
        "method": ATOMIC_TOOL_CALL_BATCH_METHOD,
        "params": {
            "name": ATOMIC_TOOL_CALL_BATCH_NAME,
            "arguments": {
                "contract": ATOMIC_TOOL_CALL_BATCH_CONTRACT,
                "calls": calls,
            }
        }
    })
}

fn tool_envelope(idempotency_id: Uuid, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": idempotency_id.to_string(),
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments },
    })
}

fn require_single_use_store(store: &dyn DurableExecutionStore) -> Result<(), ClavenarError> {
    if !store.supports_single_use_authorization() {
        return Err(ClavenarError::InvalidConfig(
            "durable execution store must support atomic single-use authorization claims".into(),
        ));
    }
    Ok(())
}

fn require_uncertain_effect_store(store: &dyn DurableExecutionStore) -> Result<(), ClavenarError> {
    if !store.supports_uncertain_effect_reconciliation() {
        return Err(ClavenarError::InvalidConfig(
            "durable execution store must atomically persist exact intent, authorization use, and an in-flight effect marker before decision network access".into(),
        ));
    }
    Ok(())
}

fn uncertain_from_intent(
    intent: &ExecutionIntent,
    reason: UncertainEffectReason,
    effect_lookup_registered: bool,
) -> UncertainExecution {
    UncertainExecution {
        contract: UNCERTAIN_EFFECT_CONTRACT.into(),
        status: "uncertain".into(),
        reason,
        authorization_id: intent.authorization_id,
        idempotency_id: intent.idempotency_id,
        tenant: intent.tenant.clone(),
        workload_id: intent.workload_id.clone(),
        workload_spiffe: intent.workload_spiffe.clone(),
        payload_sha256: intent.payload_sha256.clone(),
        executor_id: intent.executor_id.clone(),
        effect_lookup_registered,
    }
}

fn uncertain_with_reason(
    uncertain: &UncertainExecution,
    reason: UncertainEffectReason,
    effect_lookup_registered: bool,
) -> UncertainExecution {
    UncertainExecution {
        reason,
        effect_lookup_registered,
        ..uncertain.clone()
    }
}

fn validate_uncertain_execution(uncertain: &UncertainExecution) -> Result<(), ClavenarError> {
    if uncertain.contract != UNCERTAIN_EFFECT_CONTRACT
        || uncertain.status != "uncertain"
        || uncertain.authorization_id.is_nil()
        || uncertain.idempotency_id.is_nil()
        || uncertain.tenant.is_empty()
        || uncertain.workload_id.is_empty()
        || uncertain.workload_spiffe.is_empty()
        || uncertain.payload_sha256.len() != 71
        || !uncertain.payload_sha256.starts_with("sha256:")
    {
        return Err(ClavenarError::InvalidConfig(
            "invalid uncertain-effect reconciliation handle".into(),
        ));
    }
    validate_executor_id(&uncertain.executor_id)
}

fn validate_uncertain_intent(
    uncertain: &UncertainExecution,
    intent: &ExecutionIntent,
) -> Result<(), ClavenarError> {
    let claims = &intent.authorization.authorization;
    validate_authorization(&intent.authorization, intent.idempotency_id)?;
    if intent.contract != DURABLE_EXECUTION_OUTBOX_WIRE_CONTRACT
        || intent.stage != "execution.intent"
        || intent.authorization_id != uncertain.authorization_id
        || intent.idempotency_id != uncertain.idempotency_id
        || intent.tenant != uncertain.tenant
        || intent.workload_id != uncertain.workload_id
        || intent.workload_spiffe != uncertain.workload_spiffe
        || intent.payload_sha256 != uncertain.payload_sha256
        || intent.executor_id != uncertain.executor_id
        || claims.authorization_id != intent.authorization_id
        || claims.idempotency_id != intent.idempotency_id
        || claims.tenant != intent.tenant
        || claims.agent_id != intent.workload_id
        || claims.agent_spiffe != intent.workload_spiffe
        || claims.payload_sha256 != intent.payload_sha256
    {
        return Err(ClavenarError::InvalidConfig(
            "durable uncertain intent does not match its exact reconciliation handle".into(),
        ));
    }
    Ok(())
}

fn validate_execution_effect(effect: &ExecutionEffect) -> Result<(), ClavenarError> {
    if effect.effect_id.is_empty() || effect.effect_id.len() > 256 {
        return Err(ClavenarError::InvalidConfig(
            "execution effect_id must contain 1..=256 characters".into(),
        ));
    }
    Ok(())
}

fn validate_pending_authorization(
    pending: &PendingAuthorization,
    idempotency_id: Uuid,
    body: &Value,
) -> Result<(), ClavenarError> {
    let payload_sha256 = sha256(canonical_json_value(body).as_bytes());
    if pending.contract != PENDING_AUTHORIZATION_CONTRACT
        || pending.status != "pending"
        || pending.idempotency_id != idempotency_id
        || pending.pending_id.is_nil()
        || pending.correlation_id.is_nil()
        || pending.payload_sha256 != payload_sha256
        || pending.ttl_seconds <= 0
        || pending.ttl_seconds > 86_400
        || pending.poll_after_ms == 0
        || pending.poll_after_ms > 60_000
    {
        return Err(ClavenarError::InvalidConfig(
            "Proxy returned an invalid pending authorization handle".into(),
        ));
    }
    Ok(())
}

fn validate_model_tool_calls(calls: &[ModelToolCall]) -> Result<(), ClavenarError> {
    if calls.is_empty() || calls.len() > MAX_BATCH_CALLS {
        return Err(ClavenarError::InvalidConfig(format!(
            "atomic tool-call batch must contain 1..={MAX_BATCH_CALLS} calls"
        )));
    }
    let mut ids = HashSet::with_capacity(calls.len());
    for call in calls {
        if call.id.is_empty() || call.id.len() > 256 || !ids.insert(call.id.as_str()) {
            return Err(ClavenarError::InvalidConfig(
                "atomic tool-call batch IDs must be unique and contain 1..=256 characters".into(),
            ));
        }
        if call.name.is_empty() || call.name.len() > 256 {
            return Err(ClavenarError::InvalidConfig(
                "atomic tool-call names must contain 1..=256 characters".into(),
            ));
        }
    }
    Ok(())
}

fn validate_tool_name(name: &str) -> Result<(), ClavenarError> {
    if name.is_empty() || name.len() > 256 {
        return Err(ClavenarError::InvalidConfig(
            "tool name must contain 1..=256 characters".into(),
        ));
    }
    Ok(())
}

fn validate_executor_id(executor_id: &str) -> Result<(), ClavenarError> {
    if executor_id.is_empty()
        || executor_id.len() > 256
        || !executor_id
            .chars()
            .all(|character| character.is_ascii_graphic())
    {
        return Err(ClavenarError::InvalidConfig(
            "executor identity must contain 1..=256 visible ASCII characters".into(),
        ));
    }
    Ok(())
}

fn validate_outbox_entry(entry: &ReceiptOutboxEntry) -> Result<(), ClavenarError> {
    if entry.outbox_id.is_empty()
        || entry.outbox_id.len() > 256
        || entry.receipt.contract != EXECUTION_CONTRACT
        || entry.receipt.stage != "execution.completed"
        || entry.receipt.workload_signature.algorithm != "ES256"
    {
        return Err(ClavenarError::InvalidConfig(
            "durable execution store returned an invalid receipt outbox entry".into(),
        ));
    }
    Ok(())
}

fn validate_batch_authorization(
    signed: &SignedAuthorization,
    idempotency_id: Uuid,
    requested_calls: &[ModelToolCall],
    requested_payload: &Value,
) -> Result<(), ClavenarError> {
    let envelope: AtomicBatchEnvelope =
        serde_json::from_value(signed.authorization.execution_payload.clone()).map_err(|_| {
            ClavenarError::InvalidConfig(
                "Proxy returned an invalid atomic tool-call batch authorization".into(),
            )
        })?;
    validate_model_tool_calls(&envelope.params.arguments.calls)?;
    let requested_ids = requested_calls
        .iter()
        .map(|call| call.id.as_str())
        .collect::<Vec<_>>();
    let authorized_ids = envelope
        .params
        .arguments
        .calls
        .iter()
        .map(|call| call.id.as_str())
        .collect::<Vec<_>>();
    if envelope.jsonrpc != "2.0"
        || envelope.id != idempotency_id.to_string()
        || envelope.method != ATOMIC_TOOL_CALL_BATCH_METHOD
        || envelope.params.name != ATOMIC_TOOL_CALL_BATCH_NAME
        || envelope.params.arguments.contract != ATOMIC_TOOL_CALL_BATCH_CONTRACT
        || authorized_ids != requested_ids
        || (signed.authorization.modification_diff.is_none()
            && signed.authorization.execution_payload != *requested_payload)
    {
        return Err(ClavenarError::InvalidConfig(
            "Proxy returned an invalid atomic tool-call batch authorization".into(),
        ));
    }
    Ok(())
}

fn validate_authorization(
    signed: &SignedAuthorization,
    idempotency_id: Uuid,
) -> Result<(), ClavenarError> {
    let claims = &signed.authorization;
    let payload_sha256 = sha256(canonical_json_value(&claims.execution_payload).as_bytes());
    if claims.contract != EXECUTION_CONTRACT
        || claims.stage != "authorization"
        || claims.idempotency_id != idempotency_id
        || claims.payload_sha256 != payload_sha256
        || signed.identity_signature.algorithm != "Ed25519"
    {
        return Err(ClavenarError::InvalidConfig(
            "Proxy returned an invalid execution authorization".into(),
        ));
    }
    Ok(())
}

fn execution_http_error<T>(status: StatusCode, body: String) -> Result<T, ClavenarError> {
    match status {
        StatusCode::UNAUTHORIZED => Err(ClavenarError::Unauthorized(body)),
        StatusCode::BAD_REQUEST => Err(ClavenarError::BadRequest(body)),
        other => Err(ClavenarError::Server {
            status: other,
            body,
        }),
    }
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String, ClavenarError> {
    let value = serde_json::to_value(value)?;
    Ok(canonical_json_value(&value))
}

fn canonical_json_value(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(_) | Value::Number(_) | Value::String(_) => value.to_string(),
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(canonical_json_value)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|key| format!(
                        "{}:{}",
                        Value::String(key.clone()),
                        canonical_json_value(&object[key])
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier as _;

    #[test]
    fn canonical_json_and_es256_encoding_are_stable() {
        assert_eq!(
            canonical_json_value(&json!({"z": 1, "a": {"y": 2, "b": 3}})),
            r#"{"a":{"b":3,"y":2},"z":1}"#
        );
        let key = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let signature: Signature = key.sign(b"canonical receipt");
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let decoded = general_purpose::URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let signature = Signature::from_slice(&decoded).unwrap();
        key.verifying_key()
            .verify(b"canonical receipt", &signature)
            .unwrap();
    }

    #[test]
    fn public_contract_fixture_is_byte_pinned_and_decodes() {
        let schema = include_bytes!("../contracts/execution-receipt-v1.schema.json");
        let fixture = include_bytes!("../contracts/execution-receipt-v1.fixture.json");
        assert_eq!(
            hex::encode(Sha256::digest(schema)),
            "2284cb6990663af9eb4954b2fcf5e5d21944ed6f33754fc9ed5765e52d4e6970"
        );
        assert_eq!(
            hex::encode(Sha256::digest(fixture)),
            "fa51afcfa2c69006e83670b5921af361d6e7acb32a8fbcb94dffd9e16871967c"
        );
        let fixture: Value = serde_json::from_slice(fixture).unwrap();
        serde_json::from_value::<SignedAuthorization>(fixture["authorization"].clone()).unwrap();
        serde_json::from_value::<ExecutionReceipt>(fixture["receipt"].clone()).unwrap();
    }

    #[test]
    fn sdk_execution_authority_contract_is_embedded_and_strict() {
        let contract: Value = serde_json::from_str(SDK_EXECUTION_AUTHORITY_CONTRACT).unwrap();
        assert_eq!(contract["schemaVersion"], 1);
        assert_eq!(contract["feature"], "WP-06.1");
        assert_eq!(contract["governedExecutor"]["authority"], "sdk-only");
        assert_eq!(contract["effectInvariants"]["authorizationEffects"], 0);
        assert_eq!(contract["effectInvariants"]["sdkExecutorEffects"], 1);
        assert_eq!(
            contract["effectInvariants"]["receiptPersistenceRequiredForSuccess"],
            true
        );
        assert_eq!(contract["retainedFeatures"].as_array().unwrap().len(), 10);
    }

    #[test]
    fn side_effect_free_decision_contract_is_embedded_and_strict() {
        let contract: Value = serde_json::from_str(SIDE_EFFECT_FREE_DECISION_CONTRACT).unwrap();
        assert_eq!(contract["schemaVersion"], 1);
        assert_eq!(contract["feature"], "WP-06.2");
        assert_eq!(contract["decisionWireContract"], DECISION_CONTRACT);
        assert_eq!(contract["executionEvidenceContract"], EXECUTION_CONTRACT);
        assert_eq!(contract["decision"]["upstreamEffects"], 0);
        assert_eq!(
            contract["decision"]["sdkFallbackToServerExecutionAllowed"],
            false
        );
        assert_eq!(
            contract["litePosture"]["rejectBeforeUpstream"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert_eq!(contract["retainedFeatures"].as_array().unwrap().len(), 9);
    }

    #[test]
    fn atomic_tool_call_batch_contract_is_embedded_and_strict() {
        let contract: Value =
            serde_json::from_str(ATOMIC_TOOL_CALL_BATCH_CONTRACT_DOCUMENT).unwrap();
        assert_eq!(contract["schemaVersion"], 1);
        assert_eq!(contract["feature"], "WP-06.3");
        assert_eq!(contract["contract"], ATOMIC_TOOL_CALL_BATCH_CONTRACT);
        assert_eq!(contract["decisionWireContract"], DECISION_CONTRACT);
        assert_eq!(
            contract["envelope"]["method"],
            ATOMIC_TOOL_CALL_BATCH_METHOD
        );
        assert_eq!(contract["constraints"]["maximumCalls"], 128);
        assert_eq!(contract["releaseBoundary"]["partialReleaseAllowed"], false);
        assert_eq!(contract["retainedFeatures"].as_array().unwrap().len(), 8);
    }

    #[test]
    fn stable_request_identity_contract_is_embedded_and_strict() {
        let contract: Value = serde_json::from_str(STABLE_REQUEST_IDENTITY_CONTRACT).unwrap();
        assert_eq!(contract["schemaVersion"], 1);
        assert_eq!(contract["feature"], "WP-06.4");
        assert_eq!(contract["contract"], "clavenar.stable-request-identity/v1");
        assert_eq!(contract["identity"]["createdBeforeNetwork"], true);
        assert_eq!(contract["identity"]["networkGeneratedOrReplaced"], false);
        assert_eq!(
            contract["preparedRequests"]["invalidRequestNetworkAttempts"],
            0
        );
        assert_eq!(
            contract["retryBehavior"]["sameIdentityAndPayloadUpstreamEffects"],
            0
        );
        assert_eq!(contract["retainedFeatures"].as_array().unwrap().len(), 7);
    }

    #[test]
    fn durable_execution_outbox_contract_is_embedded_and_strict() {
        let contract: Value = serde_json::from_str(DURABLE_EXECUTION_OUTBOX_CONTRACT).unwrap();
        assert_eq!(contract["schemaVersion"], 1);
        assert_eq!(contract["feature"], "WP-06.5");
        assert_eq!(contract["contract"], DURABLE_EXECUTION_OUTBOX_WIRE_CONTRACT);
        assert_eq!(
            contract["failClosed"]["durableStoreRequiredBeforeNetwork"],
            true
        );
        assert_eq!(contract["intent"]["committedBeforeExecutor"], true);
        assert_eq!(contract["completion"]["atomicStoreAndEnqueue"], true);
        assert_eq!(contract["outbox"]["toolReexecutionAllowed"], false);
        assert_eq!(contract["retainedFeatures"].as_array().unwrap().len(), 6);
    }

    #[test]
    fn pending_authorization_contract_is_embedded_and_strict() {
        let contract: Value =
            serde_json::from_str(PENDING_AUTHORIZATION_CONTRACT_DOCUMENT).unwrap();
        assert_eq!(contract["schemaVersion"], 1);
        assert_eq!(contract["feature"], "WP-06.6");
        assert_eq!(contract["contract"], PENDING_AUTHORIZATION_CONTRACT);
        assert_eq!(contract["pending"]["httpStatus"], 202);
        assert_eq!(contract["pending"]["upstreamEffects"], 0);
        assert_eq!(contract["resume"]["modelReplacementCallAllowed"], false);
        assert_eq!(contract["singleUse"]["durableAtomicClaimRequired"], true);
        assert_eq!(contract["retainedFeatures"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn uncertain_effect_reconciliation_contract_is_embedded_and_strict() {
        let contract: Value =
            serde_json::from_str(UNCERTAIN_EFFECT_RECONCILIATION_CONTRACT).unwrap();
        assert_eq!(contract["schemaVersion"], 1);
        assert_eq!(contract["feature"], "WP-06.7");
        assert_eq!(contract["contract"], UNCERTAIN_EFFECT_CONTRACT);
        assert_eq!(
            contract["durableStore"]["capabilityRequiredBeforeDecisionNetwork"],
            true
        );
        assert_eq!(
            contract["durableStore"]["atomicBoundary"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            contract["automaticReexecution"]["afterExecutorErrorOrLostResponse"],
            false
        );
        assert_eq!(
            contract["reconciliation"]["executorInvocationAllowed"],
            false
        );
        assert_eq!(contract["outbox"]["receiptDeliveryMayRetry"], true);
        assert_eq!(contract["retainedFeatures"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn prepared_requests_are_validated_and_round_trip_with_the_same_identity() {
        assert!(PreparedToolRequest::new("", json!({})).is_err());
        assert!(PreparedToolBatch::new(Vec::new()).is_err());

        let request =
            PreparedToolRequest::new("payments.lookup", json!({"account": "one"})).unwrap();
        let encoded = serde_json::to_string(&request).unwrap();
        let restored: PreparedToolRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(restored, request);
        assert_eq!(restored.idempotency_id(), request.idempotency_id());

        let batch = PreparedToolBatch::new(vec![ModelToolCall {
            id: "call-a".into(),
            name: "payments.lookup".into(),
            arguments: json!({"account": "one"}),
        }])
        .unwrap();
        let encoded = serde_json::to_string(&batch).unwrap();
        let restored: PreparedToolBatch = serde_json::from_str(&encoded).unwrap();
        assert_eq!(restored, batch);
        assert_eq!(restored.idempotency_id(), batch.idempotency_id());
    }
}

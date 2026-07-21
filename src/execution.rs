//! SDK-governed execution contract.
//!
//! Proxy authorizes an exact, canonical JSON-RPC payload without invoking the
//! upstream. The SDK invokes its registered executor with those signed bytes,
//! then signs and submits a terminal receipt with the private P-256 key for
//! the same mTLS SVID. Whole-batch decisions share this path; durable intent,
//! uncertain-effect recovery, automatic retry, and non-Rust SDK parity remain
//! part of the later executor migration.

use std::{collections::HashSet, fmt, future::Future, pin::Pin, sync::Arc};

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
type ToolExecutorCallback = dyn Fn(Value) -> ToolExecutorFuture + Send + Sync + 'static;

#[derive(Clone)]
pub(crate) struct RegisteredToolExecutor {
    callback: Arc<ToolExecutorCallback>,
}

impl RegisteredToolExecutor {
    pub(crate) fn new<F, Fut>(executor: F) -> Self
    where
        F: Fn(Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ExecutionEffect, ClavenarError>> + Send + 'static,
    {
        Self {
            callback: Arc::new(move |payload| Box::pin(executor(payload))),
        }
    }

    async fn execute(&self, payload: Value) -> Result<ExecutionEffect, ClavenarError> {
        (self.callback)(payload).await
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

#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionEffect {
    pub result: Value,
    pub effect_id: String,
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

#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionOutcome {
    pub receipt: ReceiptRecorded,
    pub result: Value,
    pub effect_id: String,
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
        let body = json!({
            "jsonrpc": "2.0",
            "id": idempotency_id.to_string(),
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        });
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
        let (executor, signing_key) = self.execution_dependencies()?;
        let authorization = self.authorize_tool(idempotency_id, name, arguments).await?;
        self.execute_authorization(executor, signing_key, authorization)
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
        let (executor, signing_key) = self.execution_dependencies()?;
        let authorization = self.authorize_tool_batch(idempotency_id, calls).await?;
        self.execute_authorization(executor, signing_key, authorization)
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

    async fn authorize_payload(
        &self,
        idempotency_id: Uuid,
        body: &Value,
    ) -> Result<SignedAuthorization, ClavenarError> {
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
        if let Auth::Bearer(token) = &self.auth {
            request = request.bearer_auth(token);
        }
        let response = request.send().await?;
        let status = response.status();
        let raw = response.text().await?;
        if status != StatusCode::OK {
            return execution_http_error(status, raw);
        }
        let authorization: SignedAuthorization = serde_json::from_str(&raw)?;
        validate_authorization(&authorization, idempotency_id)?;
        Ok(authorization)
    }

    fn execution_dependencies(
        &self,
    ) -> Result<(&RegisteredToolExecutor, &SigningKey), ClavenarError> {
        let executor = self.tool_executor.as_ref().ok_or_else(|| {
            ClavenarError::InvalidConfig(
                "tool_executor is required for SDK-governed execution".into(),
            )
        })?;
        let signing_key = self.execution_signing_key.as_ref().ok_or_else(|| {
            ClavenarError::InvalidConfig(
                "execution_signing_key is required for SDK-governed execution".into(),
            )
        })?;
        Ok((executor, signing_key))
    }

    async fn execute_authorization(
        &self,
        executor: &RegisteredToolExecutor,
        signing_key: &SigningKey,
        authorization: SignedAuthorization,
    ) -> Result<ExecutionOutcome, ClavenarError> {
        let effect = executor
            .execute(authorization.authorization.execution_payload.clone())
            .await?;
        if effect.effect_id.is_empty() || effect.effect_id.len() > 256 {
            return Err(ClavenarError::InvalidConfig(
                "execution effect_id must contain 1..=256 characters".into(),
            ));
        }
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
        let canonical_unsigned = canonical_json(&unsigned)?;
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
            result_sha256,
            effect_id: effect.effect_id.clone(),
            workload_signature: WorkloadSignature {
                algorithm: "ES256".into(),
                credential_fingerprint: claims.credential_fingerprint.clone(),
                value: general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            },
        };
        let recorded = self.record_receipt(&receipt).await?;
        Ok(ExecutionOutcome {
            receipt: recorded,
            result: effect.result,
            effect_id: effect.effect_id,
        })
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

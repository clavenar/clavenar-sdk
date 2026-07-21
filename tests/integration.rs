//! Integration tests against a tokio-spawned axum stub.
//!
//! We spin up a real HTTP server inside each test rather than mocking
//! at a trait layer, so the full reqwest -> response decoder path is
//! exercised. Each test gets its own server bound to port 0 (kernel
//! picks a free port) and tears it down via a oneshot channel on exit.
//!
//! Coverage:
//! * happy path `call_tool` — 200 + JSON body
//! * structured-JSON veto from `clavenar-lite`
//! * plain-text veto from full-edition `clavenar-proxy`
//! * 401 → `ClavenarError::Unauthorized`
//! * 400 → `ClavenarError::BadRequest`
//! * `LedgerClient::audit_correlation` — typed `LedgerEntry` decode
//! * `LedgerClient::verify` — typed `VerifyResult` decode
//! * bearer header is forwarded

use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use tokio::sync::oneshot;

use base64::{Engine as _, engine::general_purpose};
use clavenar_sdk::{
    ATOMIC_TOOL_CALL_BATCH_CONTRACT, ATOMIC_TOOL_CALL_BATCH_METHOD, ATOMIC_TOOL_CALL_BATCH_NAME,
    AuditFilterParams, Auth, ClavenarClient, ClavenarError, DECISION_CONTRACT,
    DECISION_CONTRACT_HEADER, EXECUTION_CONTRACT, EXECUTION_CONTRACT_HEADER, ExecutionEffect,
    ExportOutcome, IDEMPOTENCY_ID_HEADER, LedgerClient, ModelToolCall,
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use axum::extract::Query;
use std::collections::HashMap;

/// One-shot fixture: spawn `router` on a fresh port; return the URL
/// (e.g. `http://127.0.0.1:54321`) plus a sender that drops the
/// server when the test ends.
async fn spawn(router: Router) -> (String, oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        // `with_graceful_shutdown` runs until `rx` resolves. Drop on
        // the test side ends the server cleanly.
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .expect("serve");
    });
    (format!("http://{addr}"), tx)
}

#[derive(Clone)]
struct ExecutionStub {
    authorization: Value,
    verifying_key: VerifyingKey,
}

fn model_batch() -> Vec<ModelToolCall> {
    vec![
        ModelToolCall {
            id: "call-a".into(),
            name: "payments.lookup".into(),
            arguments: json!({"account": "one"}),
        },
        ModelToolCall {
            id: "call-b".into(),
            name: "payments.transfer".into(),
            arguments: json!({"amount": 20}),
        },
    ]
}

fn batch_authorization(execution_payload: Value, modified: bool) -> Value {
    let fixture: Value = serde_json::from_str(include_str!(
        "../contracts/execution-receipt-v1.fixture.json"
    ))
    .unwrap();
    let mut signed = fixture["authorization"].clone();
    let claims = signed["authorization"].as_object_mut().unwrap();
    let idempotency_id = execution_payload["id"].clone();
    claims.insert("idempotency_id".into(), idempotency_id);
    claims.insert("method".into(), json!(ATOMIC_TOOL_CALL_BATCH_METHOD));
    claims.insert("tool_name".into(), json!(ATOMIC_TOOL_CALL_BATCH_NAME));
    claims.insert(
        "payload_sha256".into(),
        json!(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                canonical_json_value(&execution_payload).as_bytes()
            ))
        )),
    );
    claims.insert("execution_payload".into(), execution_payload);
    claims.insert(
        "modification_diff".into(),
        if modified {
            json!({"kind": "replace", "path": "/params/arguments/calls/1/arguments/amount"})
        } else {
            Value::Null
        },
    );
    signed
}

#[tokio::test]
async fn execute_tool_authorizes_exact_payload_and_signs_terminal_receipt() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../contracts/execution-receipt-v1.fixture.json"
    ))
    .unwrap();
    let signing_key = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
    let state = ExecutionStub {
        authorization: fixture["authorization"].clone(),
        verifying_key: *signing_key.verifying_key(),
    };
    let effects = Arc::new(AtomicUsize::new(0));
    let executor_effects = Arc::clone(&effects);
    let app = Router::new()
        .route(
            "/mcp",
            post(
                |State(state): State<ExecutionStub>,
                 headers: HeaderMap,
                 Json(body): Json<Value>| async move {
                    assert_eq!(
                        headers
                            .get(DECISION_CONTRACT_HEADER)
                            .and_then(|value| value.to_str().ok()),
                        Some(DECISION_CONTRACT)
                    );
                    assert!(headers.get(EXECUTION_CONTRACT_HEADER).is_none());
                    assert_eq!(
                        headers
                            .get(IDEMPOTENCY_ID_HEADER)
                            .and_then(|value| value.to_str().ok()),
                        Some("cfcc8767-4c73-41cc-8ece-b855863924c4")
                    );
                    assert_eq!(
                        body,
                        state.authorization["authorization"]["execution_payload"]
                    );
                    (StatusCode::OK, Json(state.authorization)).into_response()
                },
            ),
        )
        .route(
            "/execution-receipts",
            post(
                |State(state): State<ExecutionStub>, Json(receipt): Json<Value>| async move {
                    assert_eq!(receipt["stage"], "execution.completed");
                    assert_eq!(
                        receipt["result_sha256"],
                        "sha256:0e7557119350c8bbaee392bf4b64ba8dfe63cae8555ec686bd4937d2e0c3c7f7"
                    );
                    let signature = receipt["workload_signature"]["value"].as_str().unwrap();
                    let signature = general_purpose::URL_SAFE_NO_PAD.decode(signature).unwrap();
                    let signature = Signature::from_slice(&signature).unwrap();
                    let mut unsigned = receipt.clone();
                    unsigned
                        .as_object_mut()
                        .unwrap()
                        .remove("workload_signature");
                    let canonical = canonical_json(&unsigned);
                    state
                        .verifying_key
                        .verify(canonical.as_bytes(), &signature)
                        .unwrap();
                    (
                        StatusCode::CREATED,
                        Json(json!({
                            "status": "recorded",
                            "contract": EXECUTION_CONTRACT,
                            "stage": "execution.completed",
                            "authorization_id": receipt["authorization_id"],
                            "receipt_sha256": format!(
                                "sha256:{}",
                                hex::encode(Sha256::digest(canonical.as_bytes()))
                            )
                        })),
                    )
                        .into_response()
                },
            ),
        )
        .with_state(state);
    let (url, shutdown) = spawn(app).await;
    let client = ClavenarClient::builder(&url)
        .unwrap()
        .execution_signing_key(signing_key)
        .tool_executor(move |payload| {
            let effects = Arc::clone(&executor_effects);
            async move {
                assert_eq!(payload["params"]["arguments"]["amount"], 100);
                effects.fetch_add(1, Ordering::SeqCst);
                Ok(ExecutionEffect {
                    result: json!({"ok": true, "source": "registered-executor"}),
                    effect_id: "provider-operation-123".into(),
                })
            }
        })
        .build()
        .unwrap();
    let idempotency_id = Uuid::parse_str("cfcc8767-4c73-41cc-8ece-b855863924c4").unwrap();
    client
        .authorize_tool(idempotency_id, "payments.transfer", json!({"amount": 100}))
        .await
        .unwrap();
    assert_eq!(effects.load(Ordering::SeqCst), 0);

    let outcome = client
        .clone()
        .execute_tool(idempotency_id, "payments.transfer", json!({"amount": 100}))
        .await
        .unwrap();
    assert_eq!(
        outcome.result,
        json!({"ok": true, "source": "registered-executor"})
    );
    assert_eq!(outcome.effect_id, "provider-operation-123");
    assert_eq!(outcome.receipt.stage, "execution.completed");
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    drop(shutdown);
}

#[tokio::test]
async fn atomic_batch_is_fully_authorized_before_one_executor_invocation() {
    let signing_key = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
    let effects = Arc::new(AtomicUsize::new(0));
    let executor_effects = Arc::clone(&effects);
    let app = Router::new()
        .route(
            "/mcp",
            post(|headers: HeaderMap, Json(body): Json<Value>| async move {
                assert_eq!(
                    headers
                        .get(DECISION_CONTRACT_HEADER)
                        .and_then(|value| value.to_str().ok()),
                    Some(DECISION_CONTRACT)
                );
                assert_eq!(body["method"], ATOMIC_TOOL_CALL_BATCH_METHOD);
                assert_eq!(body["params"]["name"], ATOMIC_TOOL_CALL_BATCH_NAME);
                assert_eq!(
                    body["params"]["arguments"]["contract"],
                    ATOMIC_TOOL_CALL_BATCH_CONTRACT
                );
                assert_eq!(
                    body["params"]["arguments"]["calls"]
                        .as_array()
                        .unwrap()
                        .len(),
                    2
                );
                (StatusCode::OK, Json(batch_authorization(body, false)))
            }),
        )
        .route(
            "/execution-receipts",
            post(|Json(receipt): Json<Value>| async move {
                assert_eq!(receipt["stage"], "execution.completed");
                assert_eq!(
                    receipt["authorization"]["authorization"]["method"],
                    ATOMIC_TOOL_CALL_BATCH_METHOD
                );
                (
                    StatusCode::CREATED,
                    Json(json!({
                        "status": "recorded",
                        "contract": EXECUTION_CONTRACT,
                        "stage": "execution.completed",
                        "authorization_id": receipt["authorization_id"],
                        "receipt_sha256": "sha256:batch"
                    })),
                )
            }),
        );
    let (url, shutdown) = spawn(app).await;
    let client = ClavenarClient::builder(&url)
        .unwrap()
        .execution_signing_key(signing_key)
        .tool_executor(move |payload| {
            let effects = Arc::clone(&executor_effects);
            async move {
                assert_eq!(effects.fetch_add(1, Ordering::SeqCst), 0);
                let calls = payload["params"]["arguments"]["calls"].as_array().unwrap();
                assert_eq!(calls.len(), 2);
                assert_eq!(calls[0]["id"], "call-a");
                assert_eq!(calls[1]["id"], "call-b");
                Ok(ExecutionEffect {
                    result: json!([{"id": "call-a", "result": "found"}, {"id": "call-b", "result": "sent"}]),
                    effect_id: "provider-batch-123".into(),
                })
            }
        })
        .build()
        .unwrap();
    let outcome = client
        .execute_tool_batch(
            Uuid::parse_str("cfcc8767-4c73-41cc-8ece-b855863924c4").unwrap(),
            model_batch(),
        )
        .await
        .unwrap();
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_eq!(outcome.result.as_array().unwrap().len(), 2);
    assert_eq!(outcome.effect_id, "provider-batch-123");
    drop(shutdown);
}

#[tokio::test]
async fn modified_atomic_batch_preserves_all_sibling_identity_before_execution() {
    let effects = Arc::new(AtomicUsize::new(0));
    let executor_effects = Arc::clone(&effects);
    let app = Router::new()
        .route(
            "/mcp",
            post(|Json(mut body): Json<Value>| async move {
                body["params"]["arguments"]["calls"][1]["arguments"]["amount"] = json!(25);
                (StatusCode::OK, Json(batch_authorization(body, true)))
            }),
        )
        .route(
            "/execution-receipts",
            post(|Json(receipt): Json<Value>| async move {
                (
                    StatusCode::CREATED,
                    Json(json!({
                        "status": "recorded",
                        "contract": EXECUTION_CONTRACT,
                        "stage": "execution.completed",
                        "authorization_id": receipt["authorization_id"],
                        "receipt_sha256": "sha256:modified-batch"
                    })),
                )
            }),
        );
    let (url, shutdown) = spawn(app).await;
    let client = ClavenarClient::builder(&url)
        .unwrap()
        .execution_signing_key(p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap())
        .tool_executor(move |payload| {
            let effects = Arc::clone(&executor_effects);
            async move {
                effects.fetch_add(1, Ordering::SeqCst);
                let calls = payload["params"]["arguments"]["calls"].as_array().unwrap();
                assert_eq!(calls[0]["id"], "call-a");
                assert_eq!(calls[1]["id"], "call-b");
                assert_eq!(calls[1]["arguments"]["amount"], 25);
                Ok(ExecutionEffect {
                    result: json!({"modified": true}),
                    effect_id: "provider-modified-batch".into(),
                })
            }
        })
        .build()
        .unwrap();
    client
        .execute_tool_batch(
            Uuid::parse_str("cfcc8767-4c73-41cc-8ece-b855863924c4").unwrap(),
            model_batch(),
        )
        .await
        .unwrap();
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    drop(shutdown);
}

#[tokio::test]
async fn nonapproval_and_invalid_batches_release_zero_siblings() {
    let requests = Arc::new(AtomicUsize::new(0));
    let server_requests = Arc::clone(&requests);
    let app = Router::new().route(
        "/mcp",
        post(move || {
            let requests = Arc::clone(&server_requests);
            async move {
                let index = requests.fetch_add(1, Ordering::SeqCst);
                [
                    StatusCode::FORBIDDEN,
                    StatusCode::ACCEPTED,
                    StatusCode::GONE,
                    StatusCode::CONFLICT,
                    StatusCode::PRECONDITION_FAILED,
                ][index]
            }
        }),
    );
    let (url, shutdown) = spawn(app).await;
    let effects = Arc::new(AtomicUsize::new(0));
    let executor_effects = Arc::clone(&effects);
    let client = ClavenarClient::builder(&url)
        .unwrap()
        .execution_signing_key(p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap())
        .tool_executor(move |_| {
            let effects = Arc::clone(&executor_effects);
            async move {
                effects.fetch_add(1, Ordering::SeqCst);
                Ok(ExecutionEffect {
                    result: Value::Null,
                    effect_id: "unexpected".into(),
                })
            }
        })
        .build()
        .unwrap();
    for _ in 0..5 {
        assert!(
            client
                .execute_tool_batch(Uuid::new_v4(), model_batch())
                .await
                .is_err()
        );
    }
    let mut duplicate = model_batch();
    duplicate[1].id = duplicate[0].id.clone();
    assert!(
        client
            .execute_tool_batch(Uuid::new_v4(), duplicate)
            .await
            .is_err()
    );
    assert_eq!(requests.load(Ordering::SeqCst), 5);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    drop(shutdown);
}

#[tokio::test]
async fn governed_execution_requires_registered_executor_before_network() {
    let requests = Arc::new(AtomicUsize::new(0));
    let server_requests = Arc::clone(&requests);
    let app = Router::new().route(
        "/mcp",
        post(move || {
            let requests = Arc::clone(&server_requests);
            async move {
                requests.fetch_add(1, Ordering::SeqCst);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }),
    );
    let (url, shutdown) = spawn(app).await;
    let client = ClavenarClient::builder(&url)
        .unwrap()
        .execution_signing_key(p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap())
        .build()
        .unwrap();
    let error = client
        .execute_tool(Uuid::new_v4(), "payments.transfer", json!({"amount": 100}))
        .await
        .unwrap_err();
    assert!(
        matches!(error, ClavenarError::InvalidConfig(message) if message.contains("tool_executor"))
    );
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    drop(shutdown);
}

#[tokio::test]
async fn denied_authorization_never_invokes_registered_executor() {
    let effects = Arc::new(AtomicUsize::new(0));
    let executor_effects = Arc::clone(&effects);
    let app = Router::new().route("/mcp", post(|| async { (StatusCode::FORBIDDEN, "denied") }));
    let (url, shutdown) = spawn(app).await;
    let client = ClavenarClient::builder(&url)
        .unwrap()
        .execution_signing_key(p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap())
        .tool_executor(move |_| {
            let effects = Arc::clone(&executor_effects);
            async move {
                effects.fetch_add(1, Ordering::SeqCst);
                Ok(ExecutionEffect {
                    result: json!({"unexpected": true}),
                    effect_id: "unexpected".into(),
                })
            }
        })
        .build()
        .unwrap();
    assert!(
        client
            .execute_tool(Uuid::new_v4(), "payments.transfer", json!({"amount": 100}))
            .await
            .is_err()
    );
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    drop(shutdown);
}

#[tokio::test]
async fn receipt_failure_does_not_report_governed_execution_success() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../contracts/execution-receipt-v1.fixture.json"
    ))
    .unwrap();
    let effects = Arc::new(AtomicUsize::new(0));
    let executor_effects = Arc::clone(&effects);
    let app = Router::new()
        .route(
            "/mcp",
            post(move || {
                let authorization = fixture["authorization"].clone();
                async move { (StatusCode::OK, Json(authorization)) }
            }),
        )
        .route(
            "/execution-receipts",
            post(|| async { (StatusCode::SERVICE_UNAVAILABLE, "receipt unavailable") }),
        );
    let (url, shutdown) = spawn(app).await;
    let client = ClavenarClient::builder(&url)
        .unwrap()
        .execution_signing_key(p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap())
        .tool_executor(move |_| {
            let effects = Arc::clone(&executor_effects);
            async move {
                effects.fetch_add(1, Ordering::SeqCst);
                Ok(ExecutionEffect {
                    result: json!({"ok": true}),
                    effect_id: "provider-operation-123".into(),
                })
            }
        })
        .build()
        .unwrap();
    let error = client
        .execute_tool(
            Uuid::parse_str("cfcc8767-4c73-41cc-8ece-b855863924c4").unwrap(),
            "payments.transfer",
            json!({"amount": 100}),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, ClavenarError::Server { status, .. } if status == StatusCode::SERVICE_UNAVAILABLE)
    );
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    drop(shutdown);
}

fn canonical_json<T: Serialize>(value: &T) -> String {
    canonical_json_value(&serde_json::to_value(value).unwrap())
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

#[tokio::test]
async fn call_tool_happy_path_returns_upstream_json() {
    let app = Router::new().route(
        "/mcp",
        post(|Json(body): Json<Value>| async move {
            // Echo the JSON-RPC id back so we can assert the SDK
            // populated it.
            let id = body.get("id").cloned().unwrap_or(Value::Null);
            (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {"content": [{"type": "text", "text": "ok"}]},
                })),
            )
                .into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let client = ClavenarClient::builder(&url).unwrap().build().unwrap();
    let reply = client
        .call_tool("search", json!({"q": "rust async"}))
        .await
        .expect("happy path");
    assert_eq!(reply["jsonrpc"], "2.0");
    assert_eq!(reply["result"]["content"][0]["text"], "ok");
    drop(shutdown);
}

#[tokio::test]
async fn call_tool_structured_veto_parses_fields() {
    // Mirrors clavenar-lite's `DenyResponse` shape.
    let app = Router::new().route(
        "/mcp",
        post(|| async {
            (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "verdict": "denied",
                    "layer": "policy",
                    "error": "security_violation",
                    "reasons": ["Direct execution of SQL queries is prohibited."],
                    "review_reasons": [],
                    "intent_category": "DangerousTool",
                    "correlation_id": "a1b2c3d4-0000-4000-8000-000000000099",
                })),
            )
                .into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let client = ClavenarClient::builder(&url).unwrap().build().unwrap();
    let err = client
        .call_tool("sql_execute", json!({"query": "DROP TABLE x"}))
        .await
        .expect_err("expected veto");
    match err {
        ClavenarError::Veto {
            intent_category,
            reasons,
            review_reasons,
            correlation_id,
            raw,
        } => {
            assert_eq!(intent_category, "DangerousTool");
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("SQL"));
            assert!(review_reasons.is_empty());
            assert_eq!(
                correlation_id.as_deref(),
                Some("a1b2c3d4-0000-4000-8000-000000000099")
            );
            assert!(raw.contains("security_violation"));
        }
        other => panic!("expected Veto, got {other:?}"),
    }
    drop(shutdown);
}

#[tokio::test]
async fn call_tool_plain_text_veto_keeps_body_in_raw() {
    // Mirrors what full-edition clavenar-proxy returns today.
    let app = Router::new().route(
        "/mcp",
        post(|| async {
            (
                StatusCode::FORBIDDEN,
                "Security Violation: shell_exec is denied for this agent",
            )
                .into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let client = ClavenarClient::builder(&url).unwrap().build().unwrap();
    let err = client
        .call_tool("shell_exec", json!({"cmd": "rm -rf /"}))
        .await
        .expect_err("expected veto");
    match err {
        ClavenarError::Veto {
            intent_category,
            reasons,
            review_reasons,
            correlation_id,
            raw,
        } => {
            // No structured fields, but the raw body is preserved.
            assert!(intent_category.is_empty());
            assert!(reasons.is_empty());
            assert!(review_reasons.is_empty());
            assert!(correlation_id.is_none());
            assert!(raw.starts_with("Security Violation"));
        }
        other => panic!("expected Veto, got {other:?}"),
    }
    drop(shutdown);
}

#[tokio::test]
async fn unauthorized_response_maps_to_unauthorized_error() {
    let app = Router::new().route(
        "/mcp",
        post(|| async {
            (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let client = ClavenarClient::builder(&url).unwrap().build().unwrap();
    let err = client
        .call_tool("search", json!({}))
        .await
        .expect_err("expected unauthorized");
    match err {
        ClavenarError::Unauthorized(body) => assert!(body.contains("bearer")),
        other => panic!("expected Unauthorized, got {other:?}"),
    }
    drop(shutdown);
}

#[tokio::test]
async fn bad_request_maps_to_bad_request_error() {
    let app = Router::new().route(
        "/mcp",
        post(|| async {
            (
                StatusCode::BAD_REQUEST,
                "invalid JSON-RPC body: missing field `method`",
            )
                .into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let client = ClavenarClient::builder(&url).unwrap().build().unwrap();
    let err = client
        .call_tool("search", json!({}))
        .await
        .expect_err("expected bad request");
    match err {
        ClavenarError::BadRequest(body) => assert!(body.contains("method")),
        other => panic!("expected BadRequest, got {other:?}"),
    }
    drop(shutdown);
}

#[tokio::test]
async fn bearer_token_is_forwarded_in_authorization_header() {
    // The handler asserts the header is present; if not, returns 401
    // and the SDK surfaces it as `Unauthorized`. So a successful
    // `call_tool` here proves the SDK forwarded the token.
    let app = Router::new().route(
        "/mcp",
        post(|headers: HeaderMap| async move {
            let got = headers
                .get("authorization")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            if got == "Bearer secret-token" {
                (
                    StatusCode::OK,
                    Json(json!({"jsonrpc":"2.0","id":1,"result":"ok"})),
                )
                    .into_response()
            } else {
                (StatusCode::UNAUTHORIZED, format!("got: {got}")).into_response()
            }
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let client = ClavenarClient::builder(&url)
        .unwrap()
        .auth(Auth::Bearer("secret-token".into()))
        .build()
        .unwrap();
    let reply = client
        .call_tool("search", json!({}))
        .await
        .expect("token should be accepted");
    assert_eq!(reply["result"], "ok");
    drop(shutdown);
}

#[tokio::test]
async fn client_preserves_path_prefix_in_base_url() {
    // Operator behind a reverse proxy at /clavenar/ prefix: every request
    // must carry that prefix. RFC 3986 reference resolution drops it
    // unless the base URL ends with `/`, so the SDK normalizes for us.
    let app = Router::new().route(
        "/clavenar/mcp",
        post(|| async {
            (
                StatusCode::OK,
                Json(json!({"jsonrpc":"2.0","id":1,"result":"ok"})),
            )
                .into_response()
        }),
    );
    let (origin, shutdown) = spawn(app).await;

    // No trailing slash, has a path component — the case that used to break.
    let prefixed = format!("{origin}/clavenar");
    let client = ClavenarClient::builder(&prefixed).unwrap().build().unwrap();
    let reply = client
        .call_tool("search", json!({}))
        .await
        .expect("prefix preserved");
    assert_eq!(reply["result"], "ok");
    drop(shutdown);
}

#[tokio::test]
async fn audit_correlation_decodes_ledger_entries() {
    let app = Router::new().route(
        "/audit/correlation/{cid}",
        get(|Path(cid): Path<String>| async move {
            // Two rows per request — what the chain actually carries.
            let row = |seq: i64, layer: &str| {
                json!({
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "timestamp": "2026-05-02T12:34:56Z",
                    "agent_id": "demo-bot",
                    "method": format!("tools/call:{layer}"),
                    "intent_category": "BenignTool",
                    "authorized": true,
                    "reasoning": format!("layer={layer}"),
                    "policy_decision": null,
                    "seq": seq,
                    "prev_hash": "0".repeat(64),
                    "entry_hash": "a".repeat(64),
                    "correlation_id": cid,
                })
            };
            Json(json!([row(1, "proxy"), row(2, "policy")])).into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let ledger = LedgerClient::new(&url).unwrap();
    let rows = ledger
        .audit_correlation("3f4b8c2a-9e1d-47fa-8a6c-c0a8d8888c8c")
        .await
        .expect("audit");
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.correlation_id.is_some()));
    assert_eq!(rows[0].seq, 1);
    assert_eq!(rows[1].seq, 2);
    drop(shutdown);
}

#[tokio::test]
async fn verify_decodes_chain_status() {
    let app = Router::new().route(
        "/verify",
        get(|| async {
            Json(json!({
                "valid": true,
                "entries_checked": 47,
                "first_invalid_seq": null
            }))
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let ledger = LedgerClient::new(&url).unwrap();
    let v = ledger.verify().await.expect("verify");
    assert!(v.valid);
    assert_eq!(v.entries_checked, 47);
    assert!(v.first_invalid_seq.is_none());
    drop(shutdown);
}

#[tokio::test]
async fn audit_correlation_percent_encodes_path() {
    // Hit a server that only matches the encoded path, to confirm
    // we're escaping characters that would otherwise reroute the
    // request. A correlation_id with a `/` in it would otherwise
    // hit a different route.
    let app = Router::new().route(
        // Axum captures the literal "a%2Fb" segment because we
        // declare the path that way; with a naive (non-encoded)
        // SDK, the request would hit /audit/correlation/a/b instead
        // and 404. Confirms the encoder is on the request path.
        "/audit/correlation/{cid}",
        get(|Path(cid): Path<String>| async move {
            // axum decodes percent escapes before handing us `cid`,
            // so we see "a/b" here, and we rely on the route not
            // having matched something else first.
            assert_eq!(cid, "a/b");
            Json(json!([])).into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let ledger = LedgerClient::new(&url).unwrap();
    let rows = ledger.audit_correlation("a/b").await.expect("audit");
    assert!(rows.is_empty());
    drop(shutdown);
}

#[tokio::test]
async fn audit_agent_paged_forwards_limit_and_offset() {
    // Server captures the query string into a HashMap so we can assert
    // the SDK puts the right values on the wire. Returning a constant
    // body keeps the test focused on URL construction.
    let app = Router::new().route(
        "/audit/{agent_id}",
        get(
            |Path(_aid): Path<String>, Query(q): Query<HashMap<String, String>>| async move {
                assert_eq!(q.get("limit").map(String::as_str), Some("25"));
                assert_eq!(q.get("offset").map(String::as_str), Some("50"));
                Json(json!([])).into_response()
            },
        ),
    );
    let (url, shutdown) = spawn(app).await;

    let ledger = LedgerClient::new(&url).unwrap();
    let rows = ledger
        .audit_agent_paged("demo-bot", 25, 50)
        .await
        .expect("paged");
    assert!(rows.is_empty());
    drop(shutdown);
}

#[tokio::test]
async fn audit_agent_filtered_forwards_deep_review_filters() {
    let app = Router::new()
        .route(
            "/audit/{agent_id}",
            get(
                |Path(_aid): Path<String>, Query(q): Query<HashMap<String, String>>| async move {
                    assert_eq!(q.get("limit").map(String::as_str), Some("25"));
                    assert_eq!(q.get("before").map(String::as_str), Some("900"));
                    assert_eq!(
                        q.get("methods").map(String::as_str),
                        Some("deep_review_finding,deep_review_failed")
                    );
                    assert_eq!(q.get("seq_from").map(String::as_str), Some("100"));
                    assert_eq!(q.get("seq_to").map(String::as_str), Some("900"));
                    assert_eq!(
                        q.get("original_method").map(String::as_str),
                        Some("read_file")
                    );
                    assert_eq!(q.get("reason").map(String::as_str), Some("rate_limited"));
                    assert_eq!(q.get("verdict").map(String::as_str), Some("Red"));
                    assert_eq!(q.get("brain_delta").map(String::as_str), Some("Escalated"));
                    Json(json!([])).into_response()
                },
            ),
        )
        .route(
            "/audit/{agent_id}/count",
            get(|Query(q): Query<HashMap<String, String>>| async move {
                assert_eq!(
                    q.get("methods").map(String::as_str),
                    Some("deep_review_finding,deep_review_failed")
                );
                assert_eq!(q.get("seq_from").map(String::as_str), Some("100"));
                assert_eq!(q.get("seq_to").map(String::as_str), Some("900"));
                Json(json!({ "count": 7 }))
            }),
        );
    let (url, shutdown) = spawn(app).await;

    let ledger = LedgerClient::new(&url).unwrap();
    let filter = AuditFilterParams {
        seq_from: Some(100),
        seq_to: Some(900),
        methods: vec!["deep_review_finding".into(), "deep_review_failed".into()],
        original_method: Some("read_file".into()),
        reason: Some("rate_limited".into()),
        verdict: Some("Red".into()),
        brain_delta: Some("Escalated".into()),
        ..AuditFilterParams::default()
    };
    let rows = ledger
        .audit_agent_paged_before_filtered("demo-bot", 25, 900, &filter)
        .await
        .expect("filtered page");
    assert!(rows.is_empty());
    let count = ledger
        .audit_agent_count_filtered("demo-bot", &filter)
        .await
        .expect("filtered count");
    assert_eq!(count, 7);
    drop(shutdown);
}

#[tokio::test]
async fn audit_agent_count_decodes_count_field() {
    let app = Router::new().route(
        "/audit/{agent_id}/count",
        get(|Path(aid): Path<String>| async move {
            assert_eq!(aid, "demo-bot");
            Json(json!({ "count": 1234 }))
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let ledger = LedgerClient::new(&url).unwrap();
    let n = ledger.audit_agent_count("demo-bot").await.expect("count");
    assert_eq!(n, 1234);
    drop(shutdown);
}

#[tokio::test]
async fn trigger_export_decodes_outcome() {
    let app = Router::new().route(
        "/export",
        post(|| async {
            Json(json!({
                "Wrote": {
                    "snapshot_id": "550e8400-e29b-41d4-a716-446655440000",
                    "written_at": "2026-05-04T08:00:00Z",
                    "data_uri": "file:///snap/v2.parquet",
                    "manifest_uri": "file:///snap/v2.metadata.json",
                    "data_sha256": "f".repeat(64),
                    "byte_size": 2048,
                    "row_count": 100,
                    "seq_lo": 51,
                    "seq_hi": 150
                }
            }))
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let ledger = LedgerClient::new(&url).unwrap();
    match ledger.trigger_export().await.expect("export outcome") {
        ExportOutcome::Wrote(row) => {
            assert_eq!(row.row_count, 100);
            assert_eq!(row.seq_hi, 150);
        }
        ExportOutcome::NothingToExport => panic!("expected Wrote"),
    }
    drop(shutdown);
}

#[tokio::test]
async fn list_exports_decodes_export_records() {
    // Mirror the ledger's GET /exports payload — newest-first array
    // of ExportRecord objects. Confirms the wire-mirror struct on the
    // SDK side decodes cleanly against a real HTTP response.
    let app = Router::new().route(
        "/exports",
        get(|| async {
            Json(json!([
                {
                    "snapshot_id": "550e8400-e29b-41d4-a716-446655440000",
                    "written_at": "2026-05-04T08:00:00Z",
                    "data_uri": "file:///snap/v2.parquet",
                    "manifest_uri": "file:///snap/v2.manifest.json",
                    "data_sha256": "f".repeat(64),
                    "byte_size": 2048,
                    "row_count": 100,
                    "seq_lo": 51,
                    "seq_hi": 150
                },
                {
                    "snapshot_id": "660f9511-f3ac-52e5-b827-557766551111",
                    "written_at": "2026-05-03T08:00:00Z",
                    "data_uri": "file:///snap/v1.parquet",
                    "manifest_uri": "file:///snap/v1.manifest.json",
                    "data_sha256": "e".repeat(64),
                    "byte_size": 1024,
                    "row_count": 50,
                    "seq_lo": 1,
                    "seq_hi": 50
                }
            ]))
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let ledger = LedgerClient::new(&url).unwrap();
    let rows = ledger.list_exports().await.expect("exports");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].row_count, 100);
    assert_eq!(rows[0].seq_lo, 51);
    assert_eq!(rows[1].row_count, 50);
    drop(shutdown);
}

// ── PoliciesClient (clavenar-specs/TECH_SPEC.md
//    #console-policy-management) ───────────────────────────────────────

#[tokio::test]
async fn policies_list_decodes_into_typed_rows() {
    use clavenar_sdk::PoliciesClient;
    let app = Router::new().route(
        "/policies",
        get(|| async {
            (
                StatusCode::OK,
                Json(json!({
                    "policies": [
                        {
                            "name": "governance.rego",
                            "content_type": "rego",
                            "active": true,
                            "current_version": 3,
                            "deleted_at": null,
                            "created_at": "2026-05-08T00:00:00Z",
                            "updated_at": "2026-05-08T01:00:00Z"
                        },
                        {
                            "name": "attestation_allowlist.json",
                            "content_type": "json",
                            "active": true,
                            "current_version": 1,
                            "deleted_at": null,
                            "created_at": "2026-05-08T00:00:00Z",
                            "updated_at": "2026-05-08T00:00:00Z"
                        }
                    ]
                })),
            )
                .into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;
    let client = PoliciesClient::new(&url).unwrap();
    let rows = client.list(false).await.expect("list");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].name, "governance.rego");
    assert_eq!(rows[0].current_version, 3);
    assert_eq!(rows[1].content_type, "json");
    drop(shutdown);
}

#[tokio::test]
async fn policies_create_round_trips_typed_request_and_response() {
    use clavenar_sdk::{CreatePolicyRequest, PoliciesClient};
    let app = Router::new().route(
        "/policies",
        post(|Json(body): Json<Value>| async move {
            // Assert the SDK serialised every field correctly so a
            // future server-side rename surfaces here.
            assert_eq!(body["name"], "extra.rego");
            assert_eq!(body["content_type"], "rego");
            assert_eq!(body["reason"], "test");
            assert_eq!(body["actor_sub"], "alice");
            assert_eq!(body["actor_idp"], "oidc:test");
            (
                StatusCode::CREATED,
                Json(json!({
                    "name": "extra.rego",
                    "version": 1,
                    "body_sha256": "deadbeef",
                    "current_version": 1,
                    "active": true,
                    "event_kind": "policy.created"
                })),
            )
                .into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;
    let client = PoliciesClient::new(&url).unwrap();
    let resp = client
        .create(&CreatePolicyRequest {
            name: "extra.rego",
            content_type: "rego",
            body: "package clavenar.authz\nimport rego.v1\ndefault allow := false",
            reason: "test",
            actor_sub: "alice",
            actor_idp: "oidc:test",
            active: None,
        })
        .await
        .expect("create");
    assert_eq!(resp.event_kind, "policy.created");
    assert_eq!(resp.version, 1);
    drop(shutdown);
}

#[tokio::test]
async fn policies_update_409_carries_conflict_response() {
    use clavenar_sdk::{PoliciesClient, UpdatePolicyRequest};
    let app = Router::new().route(
        "/policies/{name}",
        axum::routing::put(|Path(_n): Path<String>| async {
            (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "version_conflict",
                    "policy": {
                        "name": "governance.rego",
                        "content_type": "rego",
                        "active": true,
                        "current_version": 7,
                        "deleted_at": null,
                        "created_at": "2026-05-08T00:00:00Z",
                        "updated_at": "2026-05-08T05:00:00Z"
                    }
                })),
            )
                .into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;
    let client = PoliciesClient::new(&url).unwrap();
    // `ClavenarClient` doesn't impl `Debug`, so `expect_err` would
    // need a `Debug` bound on the success arm. The `match` form is
    // both `Debug`-free and clippy-happy.
    let result = client
        .update(
            "governance.rego",
            &UpdatePolicyRequest {
                body: "package clavenar.authz\ndefault allow := false",
                reason: "test",
                actor_sub: "alice",
                actor_idp: "oidc:test",
                expected_current_version: 1,
            },
        )
        .await;
    let err = match result {
        Ok(_) => panic!("expected 409"),
        Err(e) => e,
    };
    let ClavenarError::Server { status, body } = err else {
        panic!("expected Server, got {err}");
    };
    assert_eq!(status, StatusCode::CONFLICT);
    let conflict = PoliciesClient::parse_conflict(&body).expect("parse_conflict");
    assert_eq!(conflict.error, "version_conflict");
    assert_eq!(conflict.policy.current_version, 7);
    drop(shutdown);
}

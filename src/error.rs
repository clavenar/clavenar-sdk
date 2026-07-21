//! Crate-level error type.
//!
//! `ClavenarError` covers the four wire outcomes a caller actually has to
//! distinguish — security veto, auth failure, transport failure, and
//! "anything else from the server" — plus an explicit `Decode` arm for
//! cases where the server returned a status we expect to be parseable
//! but the body wasn't.

use thiserror::Error;

/// All errors a `ClavenarClient` or `LedgerClient` call can return.
///
/// Match arms a caller will typically care about:
///
/// * [`ClavenarError::Veto`] — the security pipeline rejected the
///   request. The structured fields mirror the shared 403 envelope
///   (`{ layer, error, reasons, review_reasons, intent_category,
///   correlation_id }`) emitted by both `clavenar-lite` and
///   full-edition `clavenar-proxy`. `raw` is the full body verbatim —
///   set on every veto, and the *only* populated field when an older
///   server returns a non-JSON 403.
/// * [`ClavenarError::Unauthorized`] — bearer token missing or wrong
///   (HTTP 401). Carries the server's body string for diagnostics.
/// * [`ClavenarError::BadRequest`] — the request didn't parse as
///   JSON-RPC on the server side (HTTP 400). Almost always a caller
///   bug, not a runtime condition.
/// * [`ClavenarError::Server`] — anything else: 5xx, 503, an unexpected
///   status. Carries status + body so the caller can decide whether to
///   retry.
/// * [`ClavenarError::Transport`] / [`ClavenarError::Decode`] — the request
///   never made it to a verdict, or the response body didn't match the
///   shape we expect for that status. A decision request can be retried with
///   its retained identity; an executor attempt must follow the explicit
///   uncertain-effect reconciliation path instead.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClavenarError {
    /// Security pipeline rejected the request (HTTP 403).
    ///
    /// Populated from the structured 403 body emitted by both
    /// `clavenar-lite` and full-edition `clavenar-proxy`:
    /// ```json
    /// { "verdict": "denied", "layer": "policy",
    ///   "error": "security_violation",
    ///   "reasons": [...], "review_reasons": [...],
    ///   "intent_category": "...", "correlation_id": "..." }
    /// ```
    /// `correlation_id` is the join key for pulling the matching ledger
    /// row; it is `None` when an older server emits a non-JSON 403 — in
    /// that case only `raw` is meaningful. The deny `layer` and machine
    /// `error` code are also in the envelope; read them off `raw` when
    /// needed (kept out of the typed fields to bound the error size).
    #[error("clavenar veto ({intent_category}): {raw}")]
    Veto {
        intent_category: String,
        reasons: Vec<String>,
        review_reasons: Vec<String>,
        /// Proxy-stamped join key for the audit row, when present.
        correlation_id: Option<String>,
        /// Full 403 body verbatim. Always set so callers don't lose
        /// information when the server emits a non-JSON 403.
        raw: String,
    },

    /// Bearer token missing or invalid (HTTP 401).
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Server rejected the request as malformed (HTTP 400).
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Any other non-success status from the server.
    #[error("server returned {status}: {body}")]
    Server {
        status: reqwest::StatusCode,
        body: String,
    },

    /// Transport-level failure: DNS, TCP, TLS, timeout, etc.
    /// `?` on a `reqwest::Error` produces this variant via `#[from]`.
    #[error(transparent)]
    Transport(#[from] reqwest::Error),

    /// Response body didn't match the expected shape for its status.
    /// E.g. 403 with a JSON body that didn't contain `error` /
    /// `reasons` — we fall back to `Veto { raw }` rather than this
    /// variant in that case, but a malformed audit response would
    /// surface here.
    #[error(transparent)]
    Decode(#[from] serde_json::Error),

    /// A durable effect attempt began, but its exact result is not trusted.
    /// This handle cannot authorize another executor invocation; pass it to
    /// `ClavenarClient::reconcile_uncertain_effect` or surface it for human
    /// handling.
    #[error("execution effect is uncertain: {0:?}")]
    ExecutionUncertain(Box<crate::execution::UncertainExecution>),

    /// The durable store reports that this authorization already completed.
    /// The SDK will not invoke the executor again.
    #[error(
        "authorization {authorization_id} for idempotency request {idempotency_id} is already durably completed"
    )]
    ExecutionAlreadyCompleted {
        authorization_id: uuid::Uuid,
        idempotency_id: uuid::Uuid,
    },

    /// Caller-side construction failure — e.g. the `base_url` passed to
    /// `ClavenarClient::builder` wasn't a valid URL.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

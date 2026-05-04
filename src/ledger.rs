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
//!
//! # Rust idioms in this file (additions to lib.rs's list)
//!
//! * `Vec<T>` + `Json<Vec<T>>` server-side maps to `serde_json` decode
//!   on a `Vec<T>` here — no special handling for the array shape.
//! * `chrono::serde` brings the `DateTime<Utc>` (de)serializer into
//!   scope automatically because we enabled the `serde` feature in
//!   `Cargo.toml`. The wire shape is the standard ISO-8601 `chrono`
//!   default — same as warden-ledger's own `LedgerEntry`.
//! * `Uuid` deserializes from the canonical hyphenated form by default
//!   (e.g. `"3f4b...8c"`), matching what the server emits.

use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::WardenError;

/// One row from the ledger's hash chain. Fields and ordering mirror
/// the server-side `warden_ledger::LedgerEntry`. `correlation_id` is
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
    /// `x-warden-source` request header was set. `Some("simulator")` for
    /// warden-simulator-driven traffic, `None` for real agents and for
    /// rows produced by publishers that don't yet stamp the field
    /// (policy engine, HIL — these inherit the request's source via
    /// `correlation_id` join, not via this column). UI affordance, not
    /// a security claim — see the warning in `warden_ledger`.
    #[serde(default)]
    pub source: Option<String>,
}

fn default_chain_version() -> i64 {
    1
}

/// One bookkeeping row from the ledger's `exports` table. Mirrors the
/// server-side `warden_ledger::export::ExportRecord`. Each row records
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

/// Outcome of a chain re-hash. Mirrors `warden_ledger::VerifyResult`.
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
}

/// Async client for the ledger HTTP surface.
///
/// Cheap to clone (the inner `reqwest::Client` is `Arc`-based).
#[derive(Debug, Clone)]
pub struct LedgerClient {
    base_url: Url,
    http: Client,
}

impl LedgerClient {
    /// Build a client against `base_url` (e.g. `http://localhost:8083`).
    /// Returns `InvalidConfig` if the URL is malformed.
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, WardenError> {
        let url = Url::parse(base_url.as_ref())
            .map_err(|e| WardenError::InvalidConfig(format!("base_url: {e}")))?;
        let http = Client::builder().build().map_err(WardenError::Transport)?;
        Ok(Self { base_url: url, http })
    }

    /// Inject a pre-configured `reqwest::Client`. Same use case as
    /// `WardenClientBuilder::http_client`.
    pub fn with_http_client(mut self, client: Client) -> Self {
        self.http = client;
        self
    }

    /// `GET /audit/correlation/{id}` — every chain entry sharing this
    /// correlation id, oldest first. Empty vec on an unknown id.
    pub async fn audit_correlation(
        &self,
        correlation_id: &str,
    ) -> Result<Vec<LedgerEntry>, WardenError> {
        // `Url::join` doesn't percent-encode path segments — we have
        // to do it ourselves so a correlation_id with a `/` or `?` in
        // it doesn't reroute the request. UUIDs are hex-only, so the
        // encode is a no-op for the common case but defensive in
        // general.
        let path = format!(
            "audit/correlation/{}",
            percent_encode(correlation_id)
        );
        self.get_json(&path).await
    }

    /// `GET /audit/{agent_id}` — every chain entry naming `agent_id`,
    /// oldest first. Empty vec on an unknown agent.
    pub async fn audit_agent(
        &self,
        agent_id: &str,
    ) -> Result<Vec<LedgerEntry>, WardenError> {
        let path = format!("audit/{}", percent_encode(agent_id));
        self.get_json(&path).await
    }

    /// `GET /audit/{agent_id}?limit=N&offset=M` — newest-first slice
    /// of size `N` skipping `M` rows. Backward-compatible companion to
    /// [`audit_agent`]: the legacy ASC-ordered, full-chain shape stays
    /// addressable via that method, while UI callers (the warden-console
    /// audit page) hit this one so memory and bandwidth scale with
    /// `per_page` instead of chain depth.
    pub async fn audit_agent_paged(
        &self,
        agent_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<LedgerEntry>, WardenError> {
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

    /// `GET /audit/{agent_id}/count` — total chain rows naming
    /// `agent_id`. The console uses this with `audit_agent_paged` to
    /// compute total-pages without paying for the full row read. Cheap
    /// (`COUNT(*)` against the indexed column).
    pub async fn audit_agent_count(&self, agent_id: &str) -> Result<usize, WardenError> {
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

    /// `GET /verify` — re-hash every entry and check the chain. Cheap
    /// for a few thousand entries; not intended to be called on a
    /// hot path.
    pub async fn verify(&self) -> Result<VerifyResult, WardenError> {
        self.get_json("verify").await
    }

    /// `GET /exports` — bookkeeping list of cold-tier snapshots, newest
    /// first. Empty vec when the export sweeper has never run (or when
    /// the sink isn't configured — the table exists either way, the
    /// rows are just absent). Cheap call: it's a `SELECT *` over what
    /// is typically a small bookkeeping table.
    pub async fn list_exports(&self) -> Result<Vec<ExportRecord>, WardenError> {
        self.get_json("exports").await
    }

    /// Internal: GET `<base_url>/<path>` and decode JSON. Returns
    /// `Server { status, body }` for any non-2xx; transport / decode
    /// errors flow through `?`.
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, WardenError> {
        let endpoint = self
            .base_url
            .join(path)
            .map_err(|e| WardenError::InvalidConfig(format!("join {path}: {e}")))?;
        let resp = self.http.get(endpoint).send().await?;
        let status = resp.status();
        let raw = resp.text().await?;
        if status == StatusCode::OK {
            serde_json::from_str(&raw).map_err(WardenError::Decode)
        } else {
            Err(WardenError::Server { status, body: raw })
        }
    }
}

/// Minimal percent-encoder for path segments. We only need to escape
/// the characters that would change the URL's structure (`/`, `?`,
/// `#`) plus space and the percent itself; everything else can ride
/// through. Pulling in `percent-encoding` for one site felt heavier
/// than this.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            // Unreserved per RFC 3986 + a few common safe chars. Anything
            // outside this set gets `%HH`'d.
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            other => {
                use std::fmt::Write;
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_passes_unreserved() {
        assert_eq!(percent_encode("abc-XYZ_0.9~"), "abc-XYZ_0.9~");
    }

    #[test]
    fn percent_encode_escapes_path_specials() {
        assert_eq!(percent_encode("a/b?c#d"), "a%2Fb%3Fc%23d");
        assert_eq!(percent_encode("hello world"), "hello%20world");
    }

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
    }
}

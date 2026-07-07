//! Signed governance policy packs (Policy Exchange).
//!
//! A pack is a directory of `*.rego` files plus a `pack.json` manifest
//! committing to each file's `sha256`, and a detached `pack.sig`
//! (raw Ed25519 hex over `sha256(canonical pack.json with signature
//! blanked to null)`). The signing protocol mirrors the regulatory
//! export manifest verbatim (`clavenar-ledger/src/regulatory.rs`): the
//! signature commits to every entry transitively, so tampering with any
//! `.rego` body breaks both its `body_sha256` and the signature.
//!
//! Signing rides clavenar-identity's `POST /sign/blob` (audience
//! `policy-pack`) through [`PackSigner`]; verification is a pure Ed25519
//! check ([`verify_pack`]) against a key resolved from the issuer JWKS
//! or an operator-pinned SPKI PEM. No new crypto — the same `ed25519`
//! primitive the chain signatures use.

use base64::Engine;
pub use ed25519_dalek::VerifyingKey;
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ClavenarError;

/// Manifest schema version. Bumped on any incompatible layout change.
pub const PACK_MANIFEST_SCHEMA_VERSION: &str = "1";
/// Canonical manifest filename inside a pack directory.
pub const PACK_MANIFEST_FILENAME: &str = "pack.json";
/// Detached-signature sidecar filename.
pub const PACK_SIGNATURE_SIDECAR: &str = "pack.sig";
/// Audience tag for the `/sign/blob` call. Matches identity's
/// `[a-z0-9-]` validator.
pub const PACK_AUDIENCE: &str = "policy-pack";

/// One policy file in a pack, committed by content hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackEntry {
    /// Filename inside the pack directory, e.g. `money_moves.rego`.
    pub path: String,
    /// `rego` today; carried so a future pack can mix content types.
    pub content_type: String,
    /// `sha256(file bytes)`, hex. Verified against the on-disk file.
    pub body_sha256: String,
}

/// Detached-signature envelope. Same shape as the regulatory
/// `SignatureRef`: the raw bytes live in the `pack.sig` sidecar.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackSignatureRef {
    pub sidecar: String,
    pub algorithm: String,
    pub digest_alg: String,
    pub key_id: String,
    pub signed_at: chrono::DateTime<chrono::Utc>,
}

/// Pack manifest. Field order is the canonical serialization order
/// (declaration order); `signature` is blanked to `null` for the signed
/// digest, exactly like the regulatory manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackManifest {
    pub schema_version: String,
    pub name: String,
    pub version: String,
    pub entries: Vec<PackEntry>,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub signature: Option<PackSignatureRef>,
}

impl PackManifest {
    /// Canonical bytes the signature commits to: the manifest serialized
    /// with `signature` forced to `null`, pretty-printed (matching the
    /// regulatory manifest's `to_vec_pretty` convention). Verifiers
    /// reproduce by reading `pack.json`, blanking `signature`, and
    /// re-serializing.
    pub fn canonical_unsigned(&self) -> Result<Vec<u8>, ClavenarError> {
        let mut clone = self.clone();
        clone.signature = None;
        serde_json::to_vec_pretty(&clone).map_err(ClavenarError::Decode)
    }

    /// `sha256(canonical_unsigned())` — the digest handed to
    /// `/sign/blob` and re-derived on verify.
    pub fn digest_hex(&self) -> Result<String, ClavenarError> {
        Ok(hex::encode(Sha256::digest(self.canonical_unsigned()?)))
    }
}

/// Outcome of [`verify_pack`].
#[derive(Debug, PartialEq, Eq)]
pub enum PackVerifyOutcome {
    Valid,
    /// Manifest carries no signature block.
    Unsigned,
    /// Signature present but verification failed.
    Forged(String),
    /// Could not attempt verification (bad PEM/JWKS/hex/base64).
    Malformed(String),
}

/// Verify a pack manifest's detached signature against a public key.
/// `sig_hex` is the `pack.sig` sidecar contents (whitespace trimmed).
pub fn verify_pack(
    manifest: &PackManifest,
    sig_hex: &str,
    key: &VerifyingKey,
) -> PackVerifyOutcome {
    if manifest.signature.is_none() {
        return PackVerifyOutcome::Unsigned;
    }
    let digest = match manifest.canonical_unsigned() {
        Ok(c) => Sha256::digest(c),
        Err(e) => return PackVerifyOutcome::Malformed(format!("canonical: {e}")),
    };
    let raw = match hex::decode(sig_hex.trim()) {
        Ok(b) => b,
        Err(e) => return PackVerifyOutcome::Malformed(format!("signature hex: {e}")),
    };
    let sig = match Signature::from_slice(&raw) {
        Ok(s) => s,
        Err(e) => return PackVerifyOutcome::Malformed(format!("signature bytes: {e}")),
    };
    // Identity signs the decoded 32 digest bytes (see /sign/blob), so we
    // verify over the digest, not its hex.
    match key.verify(digest.as_slice(), &sig) {
        Ok(()) => PackVerifyOutcome::Valid,
        Err(_) => PackVerifyOutcome::Forged("ed25519 verification failed".to_string()),
    }
}

/// Resolve an Ed25519 verifying key from an SPKI PEM (operator-pinned).
pub fn verifying_key_from_pem(pem: &str) -> Result<VerifyingKey, ClavenarError> {
    VerifyingKey::from_public_key_pem(pem)
        .map_err(|e| ClavenarError::InvalidConfig(format!("public key PEM: {e}")))
}

/// Resolve an Ed25519 verifying key from a JWKS document by `kid`. Reads
/// the OKP/Ed25519 `x` coordinate (base64url, no pad).
pub fn verifying_key_from_jwks(
    jwks: &serde_json::Value,
    key_id: &str,
) -> Result<VerifyingKey, ClavenarError> {
    let keys = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| ClavenarError::InvalidConfig("jwks: missing `keys` array".into()))?;
    let jwk = keys
        .iter()
        .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(key_id))
        .ok_or_else(|| ClavenarError::InvalidConfig(format!("jwks: no key with kid={key_id}")))?;
    let x_b64 = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ClavenarError::InvalidConfig("jwks: key missing `x`".into()))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|e| ClavenarError::InvalidConfig(format!("jwks: x base64url: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ClavenarError::InvalidConfig("jwks: x is not 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| ClavenarError::InvalidConfig(format!("jwks: invalid ed25519 key: {e}")))
}

/// Client for clavenar-identity's `POST /sign/blob`, used to sign a pack
/// manifest digest. Mirrors the ledger's `HttpManifestSigner` but lives
/// in the SDK so any caller (the CLI today, the console later) shares one
/// `/sign/blob` client.
#[derive(Debug, Clone)]
pub struct PackSigner {
    http: reqwest::Client,
    base_url: String,
    caller_spiffe: String,
}

/// One `/sign/blob` response.
#[derive(Debug, Clone)]
pub struct PackSignature {
    pub signature_hex: String,
    pub key_id: String,
    pub algorithm: String,
    pub signed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
struct SignBlobRequest<'a> {
    digest_sha256: &'a str,
    audience: &'a str,
}

#[derive(Debug, Deserialize)]
struct SignBlobResponse {
    signature: String,
    key_id: String,
    algorithm: String,
    signed_at: chrono::DateTime<chrono::Utc>,
}

impl PackSigner {
    pub fn new(base_url: impl Into<String>, caller_spiffe: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into(),
            caller_spiffe: caller_spiffe.into(),
        }
    }

    /// Sign a manifest digest (hex of the 32-byte sha256). The audience
    /// is pinned to [`PACK_AUDIENCE`] so a pack signature can't be
    /// repurposed for the regulatory-export audience.
    pub async fn sign(&self, digest_sha256_hex: &str) -> Result<PackSignature, ClavenarError> {
        let url = format!("{}/sign/blob", self.base_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .header("X-Caller-Spiffe", &self.caller_spiffe)
            .json(&SignBlobRequest {
                digest_sha256: digest_sha256_hex,
                audience: PACK_AUDIENCE,
            })
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClavenarError::Server { status, body });
        }
        let parsed: SignBlobResponse = resp.json().await?;
        Ok(PackSignature {
            signature_hex: parsed.signature,
            key_id: parsed.key_id,
            algorithm: parsed.algorithm,
            signed_at: parsed.signed_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::{Signer, SigningKey};

    fn manifest() -> PackManifest {
        PackManifest {
            schema_version: PACK_MANIFEST_SCHEMA_VERSION.to_string(),
            name: "acme-finance".to_string(),
            version: "3".to_string(),
            entries: vec![PackEntry {
                path: "money_moves.rego".to_string(),
                content_type: "rego".to_string(),
                body_sha256: "a".repeat(64),
            }],
            generated_at: chrono::DateTime::parse_from_rfc3339("2026-06-07T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            signature: None,
        }
    }

    fn signed(m: &PackManifest, key: &SigningKey) -> String {
        let digest = Sha256::digest(m.canonical_unsigned().unwrap());
        hex::encode(key.sign(digest.as_slice()).to_bytes())
    }

    #[test]
    fn canonical_form_ignores_signature_block() {
        let mut a = manifest();
        let b = a.clone();
        a.signature = Some(PackSignatureRef {
            sidecar: PACK_SIGNATURE_SIDECAR.to_string(),
            algorithm: "ed25519".to_string(),
            digest_alg: "sha256".to_string(),
            key_id: "k".to_string(),
            signed_at: a.generated_at,
        });
        // Blanking the signature yields the same digest with or without it.
        assert_eq!(a.digest_hex().unwrap(), b.digest_hex().unwrap());
    }

    #[test]
    fn verify_round_trips_and_detects_tamper() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut m = manifest();
        let sig_hex = signed(&m, &key);
        m.signature = Some(PackSignatureRef {
            sidecar: PACK_SIGNATURE_SIDECAR.to_string(),
            algorithm: "ed25519".to_string(),
            digest_alg: "sha256".to_string(),
            key_id: "clavenar-identity:v3".to_string(),
            signed_at: m.generated_at,
        });
        let vk = key.verifying_key();
        assert_eq!(verify_pack(&m, &sig_hex, &vk), PackVerifyOutcome::Valid);

        // Tamper an entry hash → digest changes → verification fails.
        let mut tampered = m.clone();
        tampered.entries[0].body_sha256 = "b".repeat(64);
        assert!(matches!(
            verify_pack(&tampered, &sig_hex, &vk),
            PackVerifyOutcome::Forged(_)
        ));
    }

    #[test]
    fn unsigned_manifest_reports_unsigned() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let m = manifest(); // signature: None
        assert_eq!(
            verify_pack(&m, &"00".repeat(64), &key.verifying_key()),
            PackVerifyOutcome::Unsigned
        );
    }

    #[test]
    fn jwks_and_pem_resolve_the_same_key() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let vk = key.verifying_key();
        let pem = vk.to_public_key_pem(Default::default()).unwrap();
        let from_pem = verifying_key_from_pem(&pem).unwrap();

        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vk.to_bytes());
        let jwks = serde_json::json!({
            "keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": x}]
        });
        let from_jwks = verifying_key_from_jwks(&jwks, "k1").unwrap();
        assert_eq!(from_pem.to_bytes(), from_jwks.to_bytes());
        assert_eq!(from_jwks.to_bytes(), vk.to_bytes());
    }
}

//! Reusable, rotation-safe secure HTTP transport for every SDK client.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Certificate, Client, Identity, Proxy};

use crate::{ClavenarError, HttpProvider};

/// Source used to acquire the bearer token for a transport snapshot.
pub enum TokenSource {
    /// Do not attach bearer authorization.
    None,
    /// Read and trim an owner-protected token file during every reload.
    File(PathBuf),
    /// Invoke application-owned acquisition during every reload.
    Callback(Arc<dyn Fn() -> Result<Option<String>, ClavenarError> + Send + Sync>),
}

impl fmt::Debug for TokenSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::File(path) => f.debug_tuple("File").field(path).finish(),
            Self::Callback(_) => f.write_str("Callback(<redacted>)"),
        }
    }
}

/// Ambient proxy behavior is never implicit.
#[derive(Debug, Clone)]
pub enum ProxyPolicy {
    /// Ignore all proxy environment variables.
    Direct,
    /// Use reqwest's standard proxy environment resolution.
    Environment,
    /// Route HTTP and HTTPS requests through one validated proxy URL.
    Explicit(String),
}

/// Immutable inputs used to build complete replacement transport snapshots.
pub struct SecureTransportConfig {
    pub ca_bundle_path: PathBuf,
    pub client_certificate_path: PathBuf,
    pub private_key_path: PathBuf,
    pub token_source: TokenSource,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub proxy: ProxyPolicy,
}

impl fmt::Debug for SecureTransportConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureTransportConfig")
            .field("ca_bundle_path", &self.ca_bundle_path)
            .field("client_certificate_path", &self.client_certificate_path)
            .field("private_key_path", &self.private_key_path)
            .field("token_source", &self.token_source)
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("proxy", &self.proxy)
            .finish()
    }
}

/// One reusable profile shared by all service clients.
///
/// `reload` builds and validates the entire replacement before taking the
/// write lock. In-flight requests keep their prior `Arc<Client>` while later
/// requests receive the new certificate, key, CA, token, timeout, and proxy
/// snapshot together.
pub struct SecureTransportProfile {
    config: SecureTransportConfig,
    current: RwLock<Arc<Client>>,
}

impl fmt::Debug for SecureTransportProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureTransportProfile")
            .field("config", &self.config)
            .field("current", &"<redacted transport snapshot>")
            .finish()
    }
}

impl SecureTransportProfile {
    /// Load every credential and create the initial validated snapshot.
    pub fn new(config: SecureTransportConfig) -> Result<Self, ClavenarError> {
        let client = build_client(&config)?;
        Ok(Self {
            config,
            current: RwLock::new(Arc::new(client)),
        })
    }

    /// Atomically publish a complete replacement credential snapshot.
    pub fn reload(&self) -> Result<(), ClavenarError> {
        let replacement = Arc::new(build_client(&self.config)?);
        let mut current = self
            .current
            .write()
            .map_err(|_| ClavenarError::InvalidConfig("transport profile lock poisoned".into()))?;
        *current = replacement;
        Ok(())
    }
}

impl HttpProvider for SecureTransportProfile {
    fn client(&self) -> Arc<Client> {
        self.current
            .read()
            .expect("secure transport profile lock poisoned")
            .clone()
    }
}

fn build_client(config: &SecureTransportConfig) -> Result<Client, ClavenarError> {
    if config.connect_timeout.is_zero() || config.request_timeout.is_zero() {
        return Err(ClavenarError::InvalidConfig(
            "secure transport timeouts must be positive".into(),
        ));
    }

    let ca_pem = read_nonempty(&config.ca_bundle_path, "CA bundle")?;
    let cert_pem = read_nonempty(&config.client_certificate_path, "client certificate")?;
    let key_pem = read_nonempty(&config.private_key_path, "private key")?;
    let mut identity_pem = cert_pem;
    if !identity_pem.ends_with(b"\n") {
        identity_pem.push(b'\n');
    }
    identity_pem.extend_from_slice(&key_pem);

    let root = Certificate::from_pem(&ca_pem)
        .map_err(|e| invalid_source("CA bundle", &config.ca_bundle_path, e))?;
    let identity = Identity::from_pem(&identity_pem)
        .map_err(|e| invalid_source("client identity", &config.client_certificate_path, e))?;

    let mut headers = HeaderMap::new();
    if let Some(token) = load_token(&config.token_source)? {
        let value = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
            ClavenarError::InvalidConfig("token source produced invalid header bytes".into())
        })?;
        headers.insert(AUTHORIZATION, value);
    }

    let mut builder = Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(root)
        .identity(identity)
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout)
        .default_headers(headers);

    builder = match &config.proxy {
        ProxyPolicy::Direct => builder.no_proxy(),
        ProxyPolicy::Environment => builder,
        ProxyPolicy::Explicit(url) => builder.proxy(Proxy::all(url).map_err(|e| {
            ClavenarError::InvalidConfig(format!("invalid explicit proxy URL: {e}"))
        })?),
    };

    builder.build().map_err(ClavenarError::Transport)
}

fn load_token(source: &TokenSource) -> Result<Option<String>, ClavenarError> {
    let token = match source {
        TokenSource::None => None,
        TokenSource::File(path) => Some(
            String::from_utf8(read_nonempty(path, "token")?)
                .map_err(|_| ClavenarError::InvalidConfig("token file is not UTF-8".into()))?,
        ),
        TokenSource::Callback(callback) => callback()?,
    };
    token
        .map(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Err(ClavenarError::InvalidConfig(
                    "token source returned an empty token".into(),
                ))
            } else {
                Ok(trimmed.to_owned())
            }
        })
        .transpose()
}

fn read_nonempty(path: &Path, label: &str) -> Result<Vec<u8>, ClavenarError> {
    let bytes = std::fs::read(path).map_err(|e| {
        ClavenarError::InvalidConfig(format!("cannot read {label} {}: {e}", path.display()))
    })?;
    if bytes.is_empty() {
        return Err(ClavenarError::InvalidConfig(format!(
            "{label} {} is empty",
            path.display()
        )));
    }
    Ok(bytes)
}

fn invalid_source(label: &str, path: &Path, error: impl fmt::Display) -> ClavenarError {
    ClavenarError::InvalidConfig(format!("invalid {label} {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_timeout_fails_before_reading_secrets() {
        let config = SecureTransportConfig {
            ca_bundle_path: "missing-ca".into(),
            client_certificate_path: "missing-cert".into(),
            private_key_path: "missing-key".into(),
            token_source: TokenSource::None,
            connect_timeout: Duration::ZERO,
            request_timeout: Duration::from_secs(1),
            proxy: ProxyPolicy::Direct,
        };
        let error = SecureTransportProfile::new(config).unwrap_err();
        assert!(error.to_string().contains("timeouts must be positive"));
    }

    #[test]
    fn debug_never_contains_callback_or_snapshot_secrets() {
        let source = TokenSource::Callback(Arc::new(|| Ok(Some("secret-token".into()))));
        assert_eq!(format!("{source:?}"), "Callback(<redacted>)");
    }
}

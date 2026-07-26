use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clavenar_sdk::{
    ClavenarClient, HttpProvider, ProxyPolicy, SecureTransportConfig, SecureTransportProfile,
    TokenSource,
};
use serde_json::json;

#[tokio::test]
async fn real_mtls_and_certificate_token_rotation() {
    let Ok(endpoint) = std::env::var("CLAVENAR_SECURE_TRANSPORT_ENDPOINT") else {
        return;
    };
    let cert = required("CLAVENAR_SECURE_TRANSPORT_CLIENT_CERT");
    let key = required("CLAVENAR_SECURE_TRANSPORT_CLIENT_KEY");
    let generation = Arc::new(AtomicUsize::new(0));
    let token_generation = Arc::clone(&generation);
    let profile = Arc::new(
        SecureTransportProfile::new(SecureTransportConfig {
            ca_bundle_path: required("CLAVENAR_SECURE_TRANSPORT_CA"),
            client_certificate_path: cert.clone(),
            private_key_path: key.clone(),
            token_source: TokenSource::Callback(Arc::new(move || {
                let generation = token_generation.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(Some(format!("matrix-token-{generation}")))
            })),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            proxy: ProxyPolicy::Direct,
        })
        .unwrap(),
    );
    let provider: Arc<dyn HttpProvider> = profile.clone();
    let client = ClavenarClient::builder(endpoint)
        .unwrap()
        .http_provider(provider)
        .build()
        .unwrap();
    client.call_tool("matrix_probe", json!({})).await.unwrap();

    std::fs::copy(required("CLAVENAR_SECURE_TRANSPORT_NEXT_CERT"), &cert).unwrap();
    std::fs::copy(required("CLAVENAR_SECURE_TRANSPORT_NEXT_KEY"), &key).unwrap();
    profile.reload().unwrap();
    client.call_tool("matrix_probe", json!({})).await.unwrap();
    assert_eq!(generation.load(Ordering::SeqCst), 2);
}

fn required(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{name} is required"))
}

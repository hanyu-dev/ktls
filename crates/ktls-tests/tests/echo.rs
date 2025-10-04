//! Test: echo server

use std::time::Duration;

use ktls_tests::{init_logger, test_echo_async, Termination};
use rustls::CipherSuite;
use tokio::time::timeout;

#[test_case::test_matrix(
    [
        Termination::Client,
        Termination::Server,
    ],
    [
        None,
        Some(CipherSuite::TLS13_AES_128_GCM_SHA256),
        Some(CipherSuite::TLS13_AES_256_GCM_SHA384),
        Some(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
        Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
        Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
        Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
    ]
)]
#[tokio::test(flavor = "multi_thread")]
async fn test_echo(termination: Termination, cipher: Option<CipherSuite>) {
    init_logger();

    timeout(
        Duration::from_secs(15),
        test_echo_async(termination, cipher),
    )
    .await
    .expect("test_echo_async timeout")
    .expect("test_echo_async failed");

    tracing::info!("test_echo_async completed successfully");
}

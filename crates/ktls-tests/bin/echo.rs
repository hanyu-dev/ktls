//! Tests

use ktls_tests::{test_echo_async, Termination};

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("TRACE"))
        .pretty()
        .try_init();

    test_echo_async(Termination::Client)
        .await
        .expect("test_echo_async failed");

    test_echo_async(Termination::Server)
        .await
        .expect("test_echo_async failed");

    tracing::info!("Test finished");
}

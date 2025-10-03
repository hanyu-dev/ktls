//! Test: echo server

use ktls_tests::{test_echo_async, Termination};

#[test_case::test_matrix(
    [
        Termination::Client,
        Termination::Server,
    ]
)]
#[tokio::test(flavor = "multi_thread")]
async fn test_echo(termination: Termination) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("TRACE"))
        .pretty()
        .try_init();

    test_echo_async(termination)
        .await
        .expect("test_echo_async failed");
}

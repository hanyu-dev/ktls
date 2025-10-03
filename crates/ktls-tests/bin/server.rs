//! Example: TLS server using `ktls`.

use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("TRACE"))
        .pretty()
        .try_init();

    let listener = TcpListener::bind("0.0.0.0:8443")
        .await
        .expect("Bind error");

    let acceptor = ktls_tests::acceptor();

    tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received Ctrl + C...");
        }
        _ = ktls_tests::echo_server_loop(
            listener, acceptor, ktls_tests::Termination::Client, None
        ) => {}
    }

    Ok(())
}

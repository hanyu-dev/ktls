//! Example: TLS server using `ktls`.

use anyhow::Result;
use ktls_tests::{acceptor_full, init_logger, EchoServer};

#[tokio::main]
async fn main() -> Result<()> {
    init_logger();

    tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received Ctrl + C...");

            Ok(())
        }
        ret = async {
            let echo_server = EchoServer::new(acceptor_full()).await?;

            echo_server.accept_loop().await
        } => {
            ret
        }
    }
}

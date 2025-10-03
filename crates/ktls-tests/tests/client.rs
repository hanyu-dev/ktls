//! Test: client connect to real world websites.

use std::io;
use std::num::NonZeroUsize;
use std::os::fd::AsFd;
use std::time::Duration;

use anyhow::{Context, Result};
use ktls_core::TlsSession;
use ktls_stream::Stream;
use ktls_tests::cached_connector;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

#[test_case::test_matrix(
    [
        "www.google.com", // Google CDN
        "www.bing.com", // Azure CDN
        // "github.com", // Azure CDN
        "www.baidu.com", // Baidu CDN
        "stackoverflow.com", // Cloudflare CDN
        "fastly.com", // Fastly CDN,
        "www.apple.com",
    ]
)]
#[tokio::test]
async fn test_connecct_sites(server_name: &'static str) -> Result<()> {
    timeout(
        Duration::from_secs(10),
        test_connecct_sites_impl(server_name),
    )
    .await
    .unwrap_or_else(|_e| {
        tracing::error!("Timeout testing {server_name}");

        Ok(())
    })
}

async fn test_connecct_sites_impl(server_name: &'static str) -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("TRACE"))
        .pretty()
        .try_init();

    let Ok(Ok(socket)) = timeout(
        Duration::from_secs(1),
        TcpStream::connect(format!("{server_name}:443")),
    )
    .await
    else {
        tracing::warn!("Failed to connect to {server_name}, skipped.");

        return Ok(());
    };

    let connector = cached_connector();

    let mut ktls_stream = connector
        .try_connect(socket, server_name.try_into()?)
        .await
        .context("kTLS error")?;

    // Test 1
    tracing::info!("First request to {server_name}");
    http_request(&mut ktls_stream, server_name).await?;

    // Test 2
    tracing::info!("Second request to {server_name}");
    http_request(&mut ktls_stream, server_name).await?;

    Ok(())
}

async fn http_request<S, C>(ktls_stream: &mut Stream<S, C>, server_name: &str) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + AsFd + Unpin,
    C: TlsSession,
{
    // Write HTTP/1.1 request
    {
        ktls_stream
            .write_all(
                format!(
                    "GET / HTTP/1.1\r\nHost: {server_name}\r\nconnection: keep-alive\r\naccept-encoding: \
                     identity\r\ntransfer-encoding: identity\r\n\r\n"
                )
                .as_bytes(),
            )
            .await?;

        tracing::debug!("Request sent to {server_name}");

        // Read response
        let mut response = Vec::new();

        let mut buf_stream = tokio::io::BufStream::new(ktls_stream);

        let mut content_length = None;

        loop {
            let total_has_read = response.len();

            let has_read = buf_stream
                .read_until(b'\n', &mut response)
                .await?;

            if has_read == 0 || response.ends_with(b"\r\n\r\n") {
                break;
            }

            let has_read_bytes = &response[total_has_read..];
            tracing::trace!(
                "Received from {server_name}: {}",
                String::from_utf8_lossy(has_read_bytes)
            );

            #[allow(clippy::items_after_statements)]
            const PREFIX: &[u8; 16] = b"content-length: ";

            if has_read_bytes
                .get(..PREFIX.len()).is_some_and(|v| v.eq_ignore_ascii_case(PREFIX))
            {
                let v = std::str::from_utf8(&has_read_bytes[PREFIX.len()..])
                    .expect("content length should be a number string")
                    .trim()
                    .parse::<usize>()
                    .expect("content length should be a number");

                content_length = Some(v);
            }
        }

        // Read body
        {
            let Some(Some(content_length)) = content_length.map(NonZeroUsize::new) else {
                tracing::warn!("No body found in response from {server_name}, skipped.");

                return Ok(());
            };

            tracing::debug!(
                "Headers received from {server_name}, reading body ({content_length} bytes)..."
            );

            response.reserve(content_length.get());

            #[allow(unsafe_code)]
            // Safety: we have reserved enough space above.
            buf_stream
                .read_exact(unsafe {
                    std::slice::from_raw_parts_mut(
                        response
                            .as_mut_ptr()
                            .add(response.len()),
                        content_length.get(),
                    )
                })
                .await?;

            #[allow(unsafe_code)]
            // Safety: we just initialized the buffer above.
            unsafe {
                response.set_len(response.len() + content_length.get());
            }
        }

        let response = String::from_utf8_lossy(&response);

        tracing::info!("Got response from {server_name}");

        tracing::trace!(
            "Response from {server_name}: {:#?} (...)",
            &response[..64.min(response.len())]
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_tls_resumption() -> Result<()> {
    timeout(
        Duration::from_secs(120),
        test_tls_resumption_impl("www.apple.com"),
    )
    .await
    .unwrap_or_else(|_e| {
        tracing::error!("Timeout testing");

        Ok(())
    })
}

async fn test_tls_resumption_impl(server_name: &'static str) -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("TRACE"))
        .pretty()
        .try_init();

    {
        let Ok(Ok(socket)) = timeout(
            Duration::from_secs(1),
            TcpStream::connect(format!("{server_name}:443")),
        )
        .await
        else {
            tracing::warn!("Failed to connect to {server_name}, skipped.");

            return Ok(());
        };

        let connector = cached_connector();

        let mut ktls_stream = connector
            .try_connect(socket, server_name.try_into()?)
            .await
            .context("kTLS error")?;

        // First connection
        tracing::info!("First connection to {server_name}");
        http_request(&mut ktls_stream, server_name).await?;
    }

    sleep(Duration::from_secs(5)).await;

    {
        let Ok(Ok(socket)) = timeout(
            Duration::from_secs(1),
            TcpStream::connect(format!("{server_name}:443")),
        )
        .await
        else {
            tracing::warn!("Failed to connect to {server_name}, skipped.");

            return Ok(());
        };

        let connector = cached_connector();

        let mut ktls_stream = connector
            .try_connect(socket, server_name.try_into()?)
            .await
            .context("kTLS error")?;

        // Second connection
        tracing::info!("Second connection to {server_name}");
        http_request(&mut ktls_stream, server_name).await?;

        assert_eq!(
            ktls_stream.handshake_kind,
            Some(rustls::HandshakeKind::Resumed),
            "Session was not resumed for {server_name}",
        );
    }

    Ok(())
}

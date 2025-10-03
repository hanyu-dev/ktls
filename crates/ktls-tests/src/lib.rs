#![doc = include_str!("../README.md")]

use std::future::pending;
use std::io;
use std::os::fd::AsFd;
use std::process::exit;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use ktls_core::probe::Compatibilities;
use ktls_core::TlsSession;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::crypto::CryptoProvider;
use rustls::kernel::KernelConnection;
use rustls::pki_types::{PrivateKeyDer, ServerName};
use rustls::{CipherSuite, ServerConfig, SupportedCipherSuite, SupportedProtocolVersion};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::time::sleep;

pub mod common;
pub mod error;

static COMPATIBILITIES: LazyLock<Compatibilities> = LazyLock::new(|| {
    let Some(compatibility) = Compatibilities::probe()
        .inspect_err(|e| {
            println!("Failed to probe ktls compatibility: {e:?}");
        })
        .expect("Failed to probe ktls compatibility")
    else {
        println!("ktls is not supported by the current kernel, exiting...");

        exit(0);
    };

    compatibility
});

static CRYPTO_PROVIDER: LazyLock<CryptoProvider> = LazyLock::new(|| {
    let mut provider = rustls::crypto::ring::default_provider();

    provider
        .cipher_suites
        .retain(|cipher_suite| {
            let suite = match cipher_suite {
                SupportedCipherSuite::Tls12(tls12_cipher_suite) => {
                    if COMPATIBILITIES.tls12.is_unsupported() {
                        return false;
                    }

                    tls12_cipher_suite.common.suite
                }
                SupportedCipherSuite::Tls13(tls13_cipher_suite) => {
                    if COMPATIBILITIES.tls13.is_unsupported() {
                        return false;
                    }

                    tls13_cipher_suite.common.suite
                }
            };

            // Just check ECDHE_RSA / ECDHE_ECDSA here.
            match suite {
                CipherSuite::TLS13_AES_128_GCM_SHA256 => COMPATIBILITIES.tls13.aes_128_gcm(),
                CipherSuite::TLS13_AES_256_GCM_SHA384 => COMPATIBILITIES.tls13.aes_256_gcm(),
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => COMPATIBILITIES
                    .tls13
                    .chacha20_poly1305(),
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                | CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
                    COMPATIBILITIES.tls12.aes_128_gcm()
                }
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
                    COMPATIBILITIES.tls12.aes_256_gcm()
                }
                CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                | CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => COMPATIBILITIES
                    .tls12
                    .chacha20_poly1305(),
                _ => false,
            }
        });

    provider
});

static PROTOCOL_VERSIONS: LazyLock<&'static [&'static SupportedProtocolVersion]> =
    LazyLock::new(|| {
        match (
            !COMPATIBILITIES.tls12.is_unsupported(),
            !COMPATIBILITIES.tls13.is_unsupported(),
        ) {
            (true, true) => rustls::DEFAULT_VERSIONS,
            // The first element is TLS 1.3
            (false, true) => &rustls::DEFAULT_VERSIONS[..1],
            // The first element is TLS 1.2 (maybe, but empty slice is OK, let the caller handle
            // it)
            (true, false) => &rustls::DEFAULT_VERSIONS[1..],
            // No supported versions
            (false, false) => panic!("No supported TLS versions"),
        }
    });

static PROTOCOL_VERSIONS_TLS12: LazyLock<&'static [&'static SupportedProtocolVersion]> =
    LazyLock::new(|| &rustls::DEFAULT_VERSIONS[1..]);

/// Return an `Acceptor` for tests.
pub fn acceptor() -> common::Acceptor {
    let subject_alt_names = vec!["localhost".to_string()];

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(subject_alt_names).unwrap();

    let mut config = ServerConfig::builder_with_provider(Arc::new(CRYPTO_PROVIDER.clone()))
        .with_protocol_versions(PROTOCOL_VERSIONS.as_ref())
        .expect("invalid protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::try_from(signing_key.serialized_der())
                .expect("invalid key")
                .clone_key(),
        )
        .expect("invalid certificate/key");

    config.enable_secret_extraction = true;

    common::Acceptor::new(Arc::new(config))
}

/// Return an `Acceptor` for tests.
pub fn acceptor_single_protocol<const TLS12_ONLY: bool>(
    target_cipher: CipherSuite,
) -> common::Acceptor {
    let subject_alt_names = vec!["localhost".to_string()];

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(subject_alt_names).unwrap();

    let mut provider = CRYPTO_PROVIDER.clone();

    provider
        .cipher_suites
        .retain(|v| v.suite() == target_cipher);

    tracing::trace!("Using cipher suites: {:#?}", provider.cipher_suites);

    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(if TLS12_ONLY {
            PROTOCOL_VERSIONS_TLS12.as_ref()
        } else {
            PROTOCOL_VERSIONS.as_ref()
        })
        .expect("invalid protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::try_from(signing_key.serialized_der())
                .expect("invalid key")
                .clone_key(),
        )
        .expect("invalid certificate/key");

    config.enable_secret_extraction = true;

    common::Acceptor::new(Arc::new(config))
}

/// Return an `Acceptor` for tests.
pub fn cached_acceptor() -> common::Acceptor {
    static ACCEPTOR: OnceLock<common::Acceptor> = OnceLock::new();

    ACCEPTOR.get_or_init(acceptor).clone()
}

/// Return a `Connector` for tests.
pub fn connector() -> common::Connector {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(CRYPTO_PROVIDER.clone()))
        .with_protocol_versions(PROTOCOL_VERSIONS.as_ref())
        .expect("invalid protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(common::NoopVerifier::new())
        .with_no_client_auth();

    config.enable_secret_extraction = true;

    common::Connector::new(Arc::new(config))
}

/// Return a `Connector` for tests.
///
/// This function caches the connector, so it can be called multiple times
/// without creating a new one each time.
pub fn cached_connector() -> common::Connector {
    static CONNECTOR: OnceLock<common::Connector> = OnceLock::new();

    CONNECTOR.get_or_init(connector).clone()
}

// === Tests ===

/// Server name for tests.
pub static SERVER_NAME: LazyLock<ServerName<'static>> =
    LazyLock::new(|| ServerName::try_from("localhost").expect("invalid DNS name"));

#[tracing::instrument(err)]
/// Test: echo (async)
pub async fn test_echo_async(
    termination: Termination,
    target_cipher: Option<CipherSuite>,
) -> Result<()> {
    let send_back_data_notify = Arc::new(Notify::new());

    let (server_addr, server_handle) = {
        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .context("Bind error")?;

        let server_addr = listener
            .local_addr()
            .context("Cannot get local_addr")?;

        let acceptor = match target_cipher {
            Some(cipher)
                if cipher
                    .as_str()
                    .unwrap()
                    .starts_with("TLS13") =>
            {
                acceptor_single_protocol::<false>(cipher)
            }
            Some(cipher) => acceptor_single_protocol::<true>(cipher),
            None => acceptor(),
        };

        let handle = tokio::spawn(echo_server(
            listener,
            acceptor,
            termination,
            Some(send_back_data_notify.clone()),
        ));

        (server_addr, handle)
    };

    let stream = TcpStream::connect(server_addr)
        .await
        .context("Connect error")?;

    let mut stream = connector()
        .try_connect(stream, SERVER_NAME.clone())
        .await
        .context("kTLS offload error")?;

    let test_data = test_data();

    // Test: poll_flush but no data
    {
        stream
            .flush()
            .await
            .context("Flush error")?;
    }

    // Test: poll_write, poll_read
    {
        stream
            .write_all(&test_data[..4096])
            .await
            .context("Write error")?;

        stream
            .flush()
            .await
            .context("Flush error")?;

        stream
            .write_all(&test_data[4096..])
            .await
            .context("Write error")?;

        let mut received = vec![0u8; test_data.len()];

        stream
            .read_exact(&mut received)
            .await
            .context("Read error")?;

        assert_eq!(
            received, test_data,
            "Received data does not match sent data"
        );
    }

    // Test: poll_write_vectored
    {
        let bufs: Vec<_> = test_data
            .chunks(17)
            .map(io::IoSlice::new)
            .take(5)
            .collect();

        let written = stream
            .write_vectored(&bufs)
            .await
            .context("Write vectored error")?;

        let mut received = vec![0u8; written];

        stream
            .read_exact(&mut received)
            .await
            .context("Read error")?;

        assert_eq!(
            test_data[..written],
            received,
            "Received data does not match sent data"
        );
    }

    // Test: shutdown
    match termination {
        Termination::Server => {
            // Drop the server
            {
                tracing::info!("Terminating server...");

                let _ = server_handle.abort();

                while !server_handle.is_finished() {
                    tracing::info!("Terminating server...");

                    tokio::task::yield_now().await;
                }

                sleep(Duration::from_millis(1000)).await;

                tracing::info!("Server terminated, continue testing...");
            }

            // Try to read, should get EOF
            {
                let mut buf = [0u8; 1];

                let n = stream
                    .read(&mut buf)
                    .await
                    .context("Read after server termination error")?;

                assert_eq!(n, 0, "Expected EOF after server termination");
            }

            // Try to write
            {
                let _n = stream
                    .write(&[0u8; 1])
                    .await
                    .context("Write after server termination error")?;

                // For TLS 1.3, the write may succeed, but the read should still
                // return EOF. assert_eq!(n, 0, "Expected EOF
                // after server termination");
            }

            // Try flush, should not failed
            {
                stream
                    .flush()
                    .await
                    .context("Flush after server termination error")?;
            }

            // Try shutdown, should not failed
            {
                stream
                    .shutdown()
                    .await
                    .context("Shutdown after server termination error")?;
            }
        }
        Termination::Client => {
            drop(stream);

            // Notify the server to send back data
            {
                send_back_data_notify.notify_one();
            }

            // Wait for the server to terminate
            {
                let _ = server_handle
                    .await
                    .context("Wait for server termination error")?;
            }
        }
    }

    Ok(())
}

/// Return a static buffer of random data for tests.
pub fn test_data() -> &'static [u8] {
    static BUFFER: OnceLock<Vec<u8>> = OnceLock::new();

    BUFFER.get_or_init(|| {
        let mut v = vec![0; u16::MAX as usize + 1];

        v.fill_with(rand::random);

        v
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Termination behaviour of the connection.
pub enum Termination {
    /// The server actively closes the connection with `shutdown`.
    Server,

    /// The client actively closes the connection with `shutdown`.
    Client,
}

#[tracing::instrument(
    skip(acceptor, send_back_data_notify),
    fields(listen = ?listener.local_addr()),
)]
/// A simple echo server (async)
pub async fn echo_server_loop(
    listener: TcpListener,
    acceptor: common::Acceptor,
    termination: Termination,
    send_back_data_notify: Option<Arc<Notify>>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, remote_addr)) => {
                tracing::info!(?remote_addr, "Client connected");

                match acceptor.try_accept(stream).await {
                    Ok(stream) => {
                        tokio::spawn(tls_server_accepted_loop(
                            stream,
                            termination,
                            send_back_data_notify.clone(),
                        ));
                    }
                    Err(e) => {
                        tracing::error!(?remote_addr, "Failed to accept connection: {e:#?}");
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to accept connection: {e:#?}");
            }
        }
    }
}

#[tracing::instrument(
    skip(acceptor, send_back_data_notify),
    fields(listen = ?listener.local_addr()),
)]
/// A simple echo server (async)
pub async fn echo_server(
    listener: TcpListener,
    acceptor: common::Acceptor,
    termination: Termination,
    send_back_data_notify: Option<Arc<Notify>>,
) {
    tracing::warn!("Echo server started");

    match listener.accept().await {
        Ok((stream, remote_addr)) => {
            tracing::info!(?remote_addr, "Client connected");

            match acceptor.try_accept(stream).await {
                Ok(stream) => {
                    tls_server_accepted_loop(stream, termination, send_back_data_notify.clone())
                        .await;
                }
                Err(e) => {
                    tracing::error!(?remote_addr, "Failed to accept connection: {e:#?}");
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to accept connection: {e:#?}");
        }
    }

    tracing::warn!("Echo server exiting");
}

/// A simple TLS server (async)
pub async fn tls_server_accepted_loop<S, Data>(
    mut stream: common::StreamExt<S, Data>,
    termination: Termination,
    mut send_back_data_notify: Option<Arc<Notify>>,
) where
    S: AsyncRead + AsyncWrite + AsFd + Unpin,
    KernelConnection<Data>: TlsSession,
{
    tracing::info!("TLS Connection established");

    let mut buf = [0u8; 1024];

    loop {
        tokio::select! {
            ret = stream.read(&mut buf) => {
                match ret {
                    Ok(0) => {
                        tracing::info!("Read EOF, client closed connection");

                        break;
                    }
                    Ok(n) => {
                        tracing::trace!("Received {n} bytes");

                        if let Err(e) = stream.write_all(&buf[..n]).await {
                            tracing::error!(
                                "Failed to write to stream: {e:#?}"
                            );

                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to read from stream: {e:#?}");

                        break;
                    }
                }
            }
            _ = async {
                if let Some(send_back_data_notify) = send_back_data_notify.as_mut() {
                    let _ = send_back_data_notify.notified().await;
                } else {
                    pending::<()>().await;
                }
            } => {
                tracing::info!("Received signal to send back data");

                let test_data = test_data();

                match stream.write_all(test_data).await {
                    Ok(()) => {
                        tracing::info!("Server sent test data");
                    }
                    Err(e) if e.kind() == io::ErrorKind::WriteZero && termination == Termination::Client => {
                        tracing::info!("Client closed connection, cannot send test data, ideally");
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to write test data to stream: {e:#?}"
                        );

                        break;
                    }
                }

                let mut buf = vec![0u8; test_data.len()];

                match stream.read_exact(&mut buf).await {
                    Ok(read) => {
                        tracing::info!("Server received {read} bytes of echoed test data");

                        assert_eq!(
                            buf, test_data,
                            "Received data does not match sent data"
                        );
                    }
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && termination == Termination::Client => {
                        tracing::info!("Client closed connection, cannot receive echoed test data, ideally");
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to read echoed test data from stream: {e:#?}"
                        );

                        break;
                    }
                }

                break;
            }
        }
    }

    tracing::warn!("TLS Connection dropped");
}

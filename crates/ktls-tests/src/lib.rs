#![doc = include_str!("../README.md")]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]

use std::future::pending;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::process::exit;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ktls_core::probe::Compatibilities;
use ktls_core::TlsSession;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::crypto::CryptoProvider;
use rustls::kernel::KernelConnection;
use rustls::pki_types::{PrivateKeyDer, ServerName};
use rustls::{
    CipherSuite, ProtocolVersion, ServerConfig, SupportedCipherSuite, SupportedProtocolVersion,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::Instrument;

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

/// Helper function to create a [`ServerConfig`]
pub fn rustls_server_config<const TLS12_ONLY: bool>(
    target_cipher: Option<CipherSuite>,
) -> Option<ServerConfig> {
    let subject_alt_names = vec!["localhost".to_string()];

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(subject_alt_names).unwrap();

    let mut provider = CRYPTO_PROVIDER.clone();

    if let Some(target_cipher) = target_cipher {
        provider
            .cipher_suites
            .retain(|v| v.suite() == target_cipher);

        if provider.cipher_suites.is_empty() {
            tracing::warn!(
                "No supported cipher suites for {target_cipher:?}, the current kernel may not \
                 support it."
            );

            return None;
        }

        tracing::trace!("Using cipher suites: {:#?}", provider.cipher_suites);
    }

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
    config.max_early_data_size = u32::MAX;

    Some(config)
}

/// Return an `Acceptor` for tests, with all supported protocols and cipher
/// suites.
pub fn acceptor_full() -> common::Acceptor {
    rustls_server_config::<false>(None)
        .map(Arc::new)
        .map(common::Acceptor::new)
        .unwrap()
}

/// Return an `Acceptor` for tests, cached.
///
/// See [`acceptor_full`] for details.
pub fn cached_acceptor_full() -> common::Acceptor {
    static ACCEPTOR: OnceLock<common::Acceptor> = OnceLock::new();

    ACCEPTOR
        .get_or_init(acceptor_full)
        .clone()
}

/// Return an `Acceptor` for tests.
pub fn acceptor<const TLS12_ONLY: bool>(
    target_cipher: Option<CipherSuite>,
) -> Option<common::Acceptor> {
    rustls_server_config::<TLS12_ONLY>(target_cipher)
        .map(Arc::new)
        .map(common::Acceptor::new)
}

/// Helper function to create a [`rustls::ClientConfig`]
pub fn rustls_client_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(CRYPTO_PROVIDER.clone()))
        .with_protocol_versions(PROTOCOL_VERSIONS.as_ref())
        .expect("invalid protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(common::NoopVerifier::new())
        .with_no_client_auth();

    config.enable_early_data = true;
    config.enable_secret_extraction = true;

    config
}

/// Return a `Connector` for tests.
#[must_use]
pub fn connector() -> common::Connector {
    common::Connector::new(Arc::new(rustls_client_config()))
}

/// Return a `Connector` for tests.
///
/// This function caches the connector, so it can be called multiple times
/// without creating a new one each time.
pub fn cached_connector() -> common::Connector {
    static CONNECTOR: OnceLock<common::Connector> = OnceLock::new();

    CONNECTOR.get_or_init(connector).clone()
}

/// Inits tracing-subscriber.
pub fn init_logger() {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let _ = tracing_subscriber::registry()
        // .with(console_subscriber::spawn())
        .with(
            tracing_subscriber::fmt::layer()
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_target(false)
                .with_level(true)
                .with_line_number(true)
                .with_file(true)
                .with_ansi(true)
                .pretty(),
        )
        .with(tracing_subscriber::filter::LevelFilter::TRACE)
        .try_init();
}

#[derive(Debug)]
/// A simple echo server instance.
pub struct EchoServer {
    // The TCP listener.
    listener: TcpListener,

    // The local address the server is bound to.
    local_addr: SocketAddr,

    // kTLS server acceptor
    acceptor: common::Acceptor,
}

impl EchoServer {
    #[tracing::instrument(name = "EchoServer::new", skip(acceptor), err)]
    /// Creates a new `EchoServer` instance, binding to a random port.
    ///
    /// Returns the `EchoServer` instance and the bound `SocketAddr`.
    pub async fn new(acceptor: common::Acceptor) -> Result<Self> {
        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .context("Bind error")?;

        let local_addr = listener
            .local_addr()
            .context("Cannot get local_addr")?;

        tracing::info!("Echo server listening on {local_addr}");

        Ok(Self {
            listener,
            local_addr,
            acceptor,
        })
    }

    #[tracing::instrument(
        name = "EchoServer::accept_loop",
        skip(self),
        fields(local_addr = ?self.local_addr),
        err
    )]
    /// Dead loop accepting connections and spawning echo server tasks.
    pub async fn accept_loop(self) -> Result<()> {
        loop {
            let (stream, peer_addr) = self
                .listener
                .accept()
                .await
                .context("Accept error")?;

            let Ok(accepted) = self
                .acceptor
                .try_accept(stream)
                .await
                .inspect_err(|e| {
                    tracing::error!(?peer_addr, "kTLS accept error: {e:?}");
                })
            else {
                continue;
            };

            tokio::spawn(Self::echo_server_task(accepted, None, None).instrument(
                tracing::info_span!("echo_server_task", local_addr = ?self.local_addr, ?peer_addr),
            ));
        }
    }

    #[tracing::instrument(
        name = "EchoServer::accept_pair",
        skip(self),
        fields(local_addr = ?self.local_addr),
        err
    )]
    /// Accepts a new TLS connection.
    pub async fn accept_pair(&self) -> Result<Accepted> {
        let ((accepted, _), connected) = tokio::try_join! {
            biased;
            async {
                self.listener
                    .accept()
                    .await
                    .context("Accept error")
            },
            async {
                TcpStream::connect(self.local_addr)
                    .await
                    .context("Connect error")
            }
        }?;

        let acceptor = self.acceptor.clone();
        let (termination_signal_tx, termination_signal_rx) = mpsc::channel(2);
        let (key_update_signal_tx, key_update_signal_rx) = mpsc::channel(1);

        let server_handle = tokio::spawn(async move {
            let accepted = acceptor
                .try_accept(accepted)
                .await
                .context("kTLS accept error")?;

            Self::echo_server_task(
                accepted,
                Some(termination_signal_rx),
                Some(key_update_signal_rx),
            )
            .await
        });

        Ok(Accepted {
            connected,
            termination_signal_tx,
            key_update_signal_tx,
            server_handle,
        })
    }

    #[tracing::instrument(skip_all, err)]
    async fn echo_server_task<S, Data>(
        mut stream: common::StreamExt<S, Data>,
        mut termination_signal: Option<mpsc::Receiver<Termination>>,
        mut key_update_signal: Option<mpsc::Receiver<()>>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + AsFd + Unpin,
        KernelConnection<Data>: TlsSession,
    {
        let mut buf = [0u8; 1024];

        let mut termination_signal = termination_signal.as_mut();
        let mut key_update_signal = key_update_signal.as_mut();

        tokio::select! {
            ret = async {
                loop {
                    if let Some(key_update_signal) = key_update_signal.as_mut() {
                        if let Ok(()) = key_update_signal.try_recv() {
                            tracing::info!("Received key update signal, updating keys...");

                            // Only Linux 6.16+ supports, not test it here
                            // stream
                            //     .refresh_traffic_keys()
                            //     .context("Key update error")?;

                            tracing::info!("Key update done.");
                        }
                    }

                    match stream.read(&mut buf).await.context("Read data error")? {
                        0 => {
                            tracing::info!("Read EOF, client closed connection (?)");

                            break Ok(())
                        },
                        n => {
                            stream.write_all(&buf[..n]).await.context("Write back data error")?;
                        }
                    }
                }
            } => {
                ret
            }
            ret = async {
                if let Some(signal) = termination_signal.as_deref_mut() {
                    signal.recv().await.context("Signal receive error")
                } else {
                    pending().await
                }
            } => {
                let termination = ret.context("Signal error")?;

                if termination == Termination::Server {
                    tracing::info!("Received signal to terminate connection by server");

                    return Ok(())
                }

                tracing::info!("Received signal to send back data");

                termination_signal.unwrap().recv().await.context("Signal receive error")?;

                tracing::info!("Client is shutdown, test sending back test data...");

                match stream.write_all(test_data()).await {
                    // Ok(()) if stream.protocol_version == ProtocolVersion::TLSv1_2 => {
                    //     bail!("Server sent test data successfully, but client should have closed the connection.");
                    // }
                    Ok(()) => {
                        // For TLS 1.3, server can send data even if client has sent a close_notify,
                        // but does not shutdown the physical connection.
                        tracing::info!("Server sent test data");
                    }
                    Err(e) if e.kind() == io::ErrorKind::WriteZero => {
                        tracing::info!("Client closed connection, cannot send test data, ideally");
                    }
                    ret @ Err(_) => {
                        ret.context("Write test data unexpected error")?;
                    }
                }

                match stream.read(&mut buf).await {
                    Ok(0) => {
                        tracing::info!("Read EOF, client closed connection");
                    }
                    Err(e) if e.kind() == io::ErrorKind::BrokenPipe || e.kind() == io::ErrorKind::ConnectionReset => {
                        tracing::info!("Client closed connection, cannot receive echoed test data, ideally");
                    }
                    ret => {
                        bail!("Unexpected read result: {ret:?}");
                    }
                }

                Ok(())
            }
        }
    }
}

#[non_exhaustive]
#[derive(Debug)]
/// Accepted connection and its server task handle.
pub struct Accepted {
    /// The connected stream.
    pub connected: TcpStream,

    /// The termination signal sender to the server task.
    pub termination_signal_tx: mpsc::Sender<Termination>,

    /// The key update signal sender to the server task.
    pub key_update_signal_tx: mpsc::Sender<()>,

    /// The server task handle.
    pub server_handle: JoinHandle<Result<()>>,
}

// === Tests ===

/// Server name for tests.
pub static SERVER_NAME: LazyLock<ServerName<'static>> =
    LazyLock::new(|| ServerName::try_from("localhost").expect("invalid DNS name"));

#[allow(clippy::too_many_lines)]
#[tracing::instrument(err)]
/// Test: echo (async)
pub async fn test_echo_async(
    termination: Termination,
    target_cipher: Option<CipherSuite>,
) -> Result<()> {
    let Some(acceptor) = (match target_cipher {
        Some(cipher)
            if cipher
                .as_str()
                .unwrap()
                .starts_with("TLS13") =>
        {
            acceptor::<false>(Some(cipher))
        }
        Some(cipher) => acceptor::<true>(Some(cipher)),
        None => acceptor::<false>(None),
    }) else {
        return Ok(());
    };

    // Shared client config
    let client_config = Arc::new(rustls_client_config());

    // Create the echo server
    let echo_server = EchoServer::new(acceptor).await?;

    macro_rules! test_read_write {
        ($stream:expr) => {{
            $stream
                .write_all(&test_data()[..4096])
                .await
                .context("Write error")?;

            $stream
                .flush()
                .await
                .context("Flush error")?;

            $stream
                .write_all(&test_data()[4096..])
                .await
                .context("Write error")?;

            $stream
                .flush()
                .await
                .context("Flush error")?;

            let mut received = vec![0u8; test_data().len()];

            $stream
                .read_exact(&mut received)
                .await
                .context("Read error")?;

            if received != test_data() {
                bail!("Received data does not match sent one");
            }
        }};
    }

    // Test 1: client (kTLS offloaded) <-> server (kTLS offloaded)
    {
        // Accept a connection in background.
        let Accepted {
            connected,
            termination_signal_tx,
            key_update_signal_tx: _,
            server_handle,
        } = echo_server.accept_pair().await?;

        let mut stream = common::Connector::new(client_config.clone())
            .try_connect(connected, SERVER_NAME.clone())
            .await
            .context("kTLS offload error")?;

        // Test: poll_flush but no data
        {
            stream
                .flush()
                .await
                .context("Flush error")?;
        }

        test_read_write!(stream);

        // Only Linux 6.16+ supports, not test it here
        // Test: Key update (client)
        // {
        //     tracing::info!("Testing key update (client trigger)...");

        //     stream
        //         .refresh_traffic_keys()
        //         .context("Key update error")?;

        //     test_read_write!(stream);

        //     // FIXME: Currently the key update from server is not working, cause
        //     // the program to hang.

        //     // tracing::info!("Testing key update (server trigger)...");

        //     // key_update_signal_tx
        //     //     .send(())
        //     //     .await
        //     //     .expect("Send key update signal error");

        //     // stream.flush().await?;

        //     // tracing::info!("Key update triggered by server");

        //     // test_read_write!(stream);
        // }

        // Test: poll_write_vectored, the default implementation is to call poll_write
        // on the first non-empty buffer.
        {
            let bufs: Vec<_> = test_data()
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

            if received != test_data()[..written] {
                bail!("Received data does not match sent one");
            }
        }

        // Test: shutdown
        match termination {
            Termination::Server => {
                // Drop the server
                {
                    termination_signal_tx
                        .send(termination)
                        .await
                        .expect("Send signal error");

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

                    if n != 0 {
                        bail!("Read expected EOF after server termination, got {n} bytes");
                    }
                }

                // Try to write
                {
                    let _n = stream
                        .write(&[0u8; 1])
                        .await
                        .context("Write after server termination error")?;

                    // FIXME: Truncation is acceptable
                    // if stream.protocol_version == ProtocolVersion::TLSv1_2 &&
                    // n != 0 {     bail!("Write expected
                    // EOF after server termination, got {n} bytes");
                    // } else {
                    //     // For TLS 1.3, the write may succeed, but the read
                    //     // should still return EOF.
                    // }
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
                // Shutdown the client.
                {
                    termination_signal_tx
                        .send(termination)
                        .await
                        .expect("Send signal error");

                    sleep(Duration::from_millis(1000)).await;

                    stream.shutdown().await?;

                    tracing::info!(
                        "Client is shutdown, waiting for server to test sending back data..."
                    );

                    sleep(Duration::from_millis(1000)).await;

                    let _ = termination_signal_tx
                        .send(termination)
                        .await;
                }

                server_handle
                    .await
                    .context("Wait for server termination error")?
                    .context("Server handle return error")?;
            }
        }
    }

    // Test 2: client (tokio-rustls) <-> server (kTLS offloaded)
    {
        // Accept a connection in background.
        let Accepted {
            connected,
            termination_signal_tx,
            key_update_signal_tx: _,
            server_handle,
        } = echo_server.accept_pair().await?;

        let mut stream = tokio_rustls::TlsConnector::from(client_config.clone())
            .early_data(true)
            .connect(SERVER_NAME.clone(), connected)
            .await
            .context("tokio-rustls connect error")?;

        // Test: TLS 1.3 early-data
        if target_cipher.is_some_and(|c| c.as_str().unwrap().starts_with("TLS13"))
            || stream.get_ref().1.protocol_version() == Some(ProtocolVersion::TLSv1_3)
        {
            tracing::info!("Testing TLS 1.3 early-data...");

            let early_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
            stream.write_all(early_data).await?;
            stream.flush().await?;

            if !stream
                .get_ref()
                .1
                .is_early_data_accepted()
            {
                bail!("Early data was not accepted, server may not support it");
            }

            let mut buf = vec![0u8; early_data.len()];

            // Here the server must have handshaked.
            stream.read_exact(&mut buf).await?;

            if buf != early_data {
                bail!("Received data does not match sent one");
            }
        }

        test_read_write!(stream);

        // Only Linux 6.16+ supports, not test it here
        // // Test: Key update (client)
        // if stream.get_ref().1.protocol_version() == Some(ProtocolVersion::TLSv1_3) {
        //     tracing::info!("Testing key update (client trigger)...");

        //     stream
        //         .get_mut()
        //         .1
        //         .refresh_traffic_keys()
        //         .context("Key update error")?;

        //     test_read_write!(stream);

        //     tracing::info!("Testing key update (server trigger)...");

        //     key_update_signal_tx
        //         .send(())
        //         .await
        //         .expect("Send key update signal error");

        //     test_read_write!(stream);
        // }

        // Test: shutdown
        match termination {
            Termination::Server => {
                // Drop the server
                {
                    termination_signal_tx
                        .send(termination)
                        .await
                        .expect("Send signal error");

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

                    if n != 0 {
                        bail!("Read expected EOF after server termination, got {n} bytes");
                    }
                }

                // Try to write
                {
                    let _n = stream
                        .write(&[0u8; 1])
                        .await
                        .context("Write after server termination error")?;

                    // FIXME: Truncation is acceptable
                    // if stream
                    //     .get_ref()
                    //     .1
                    //     .protocol_version()
                    //     .expect("Handshake should have been done")
                    //     == ProtocolVersion::TLSv1_2
                    //     && n != 0
                    // {
                    //     bail!("Write expected EOF after server termination,
                    // got {n} bytes"); } else {
                    //     // For TLS 1.3, the write may succeed, but the read
                    //     // should still return EOF.
                    // }
                }

                // Try shutdown, should failed
                {
                    let ret = stream.shutdown().await;

                    if !matches!(
                        &ret,
                        Err(e)
                            if e.kind() == io::ErrorKind::BrokenPipe
                                || e.kind() == io::ErrorKind::ConnectionReset
                    ) {
                        bail!("Expected BrokenPipe or ConnectionReset, got {ret:?}");
                    }
                }
            }
            Termination::Client => {
                // Shutdown the client.
                {
                    termination_signal_tx
                        .send(termination)
                        .await
                        .expect("Send signal error");

                    sleep(Duration::from_millis(1000)).await;

                    stream.shutdown().await?;

                    tracing::info!(
                        "Client is shutdown, waiting for server to test sending back data..."
                    );

                    sleep(Duration::from_millis(1000)).await;

                    let _ = termination_signal_tx
                        .send(termination)
                        .await;
                }

                server_handle
                    .await
                    .context("Wait for server termination error")?
                    .context("Server handle return error")?;
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

#[allow(clippy::exhaustive_enums)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Termination behaviour of the connection.
pub enum Termination {
    /// The server actively closes the connection with `shutdown`.
    Server,

    /// The client actively closes the connection with `shutdown`.
    Client,
}

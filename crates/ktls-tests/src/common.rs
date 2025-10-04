//! Components for building kTLS offload enabled TLS clients and servers.

use std::future::poll_fn;
use std::os::fd::AsFd;
use std::pin::Pin;
use std::sync::Arc;
use std::{io, ops};

use ktls_core::utils::Buffer;
use ktls_core::{setup_ulp, TlsSession};
use ktls_stream::Stream;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ClientConnectionData, UnbufferedClientConnection};
use rustls::kernel::KernelConnection;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{ConnectionState, EncodeError, UnbufferedStatus};
use rustls::{ClientConfig, DigitallySignedStruct, HandshakeKind, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::error::Error;

/// Stream with some other information.
pub struct StreamExt<S, Data>
where
    S: AsFd,
    KernelConnection<Data>: TlsSession,
{
    inner: Stream<S, KernelConnection<Data>>,

    /// The negotiated protocol version.
    pub protocol_version: rustls::ProtocolVersion,

    /// The handshake type used in the connection, if applicable.
    pub handshake_kind: Option<HandshakeKind>,
}

impl<S, Data> ops::Deref for StreamExt<S, Data>
where
    S: AsFd,
    KernelConnection<Data>: TlsSession,
{
    type Target = Stream<S, KernelConnection<Data>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S, Data> ops::DerefMut for StreamExt<S, Data>
where
    S: AsFd,
    KernelConnection<Data>: TlsSession,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[derive(Debug, Clone)]
/// A TLS acceptor with kTLS offload support.
///
/// TODO: add fallback mechanism (but rustls' API design does not support so)
pub struct Acceptor {
    config: Arc<ServerConfig>,
}

impl Acceptor {
    #[must_use]
    /// Create a new [`Acceptor`] with the given [`ServerConfig`].
    pub const fn new(config: Arc<ServerConfig>) -> Self {
        Self { config }
    }

    /// Accepts a TLS connection on the given socket.
    ///
    /// ## Errors
    ///
    /// [`Error`]. This may contain the original socket if the setup failed
    /// and the caller can fallback to normal TLS acceptor implementation.
    pub async fn try_accept<S>(
        &self,
        socket: S,
    ) -> Result<StreamExt<S, ServerConnectionData>, Error>
    where
        S: AsyncRead + AsyncWrite + AsFd + Unpin,
    {
        setup_ulp(&socket)?;

        self.internal_try_accept(socket).await
    }

    async fn internal_try_accept<S>(
        &self,
        mut socket: S,
    ) -> Result<StreamExt<S, ServerConnectionData>, Error>
    where
        S: AsyncWrite + AsyncRead + AsFd + Unpin,
    {
        let mut conn =
            UnbufferedServerConnection::new(self.config.clone()).map_err(Error::Config)?;

        let mut incoming = Vec::with_capacity(u16::MAX as usize + 5);
        let mut outgoing = Vec::with_capacity(u16::MAX as usize + 5);
        let mut outgoing_used = 0usize;
        let mut early_data_received = Vec::new();

        loop {
            let UnbufferedStatus { mut discard, state } = conn.process_tls_records(&mut incoming);

            let state = state.map_err(Error::Handshake)?;

            match state {
                ConnectionState::BlockedHandshake => {
                    read_record(&mut socket, &mut incoming).await?;
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => {
                    return Err(Error::ConnectionClosedBeforeHandshakeCompleted);
                }
                ConnectionState::ReadEarlyData(mut data) => {
                    while let Some(record) = data.next_record() {
                        let record = record.map_err(Error::Handshake)?;

                        discard += record.discard;

                        early_data_received.extend_from_slice(record.payload);
                    }
                }
                ConnectionState::EncodeTlsData(mut state) => {
                    match state.encode(&mut outgoing[outgoing_used..]) {
                        Ok(count) => outgoing_used += count,
                        Err(EncodeError::AlreadyEncoded) => unreachable!(),
                        Err(EncodeError::InsufficientSize(e)) => {
                            outgoing.resize(outgoing_used + e.required_size, 0u8);

                            match state.encode(&mut outgoing[outgoing_used..]) {
                                Ok(count) => outgoing_used += count,
                                Err(e) => unreachable!("encode failed after resizing buffer: {e}"),
                            }
                        }
                    }
                }
                ConnectionState::TransmitTlsData(data) => {
                    socket
                        .write_all(&outgoing[..outgoing_used])
                        .await
                        .map_err(Error::IO)?;
                    outgoing_used = 0;
                    data.done();
                }
                ConnectionState::WriteTraffic(_) => {
                    incoming.drain(..discard);
                    break;
                }
                ConnectionState::ReadTraffic(_) => unreachable!(
                    "ReadTraffic should not be encountered during the handshake process"
                ),
                _ => unreachable!("unexpected connection state"),
            }

            incoming.drain(..discard);
        }

        let protocol_version = conn
            .protocol_version()
            .expect("Handshake should have been done");
        let handshake_kind = conn.handshake_kind();

        let (secrets, session) = conn
            .dangerous_into_kernel_connection()
            .map_err(Error::ExtractSecrets)?;

        Ok(StreamExt {
            inner: Stream::from(
                socket,
                secrets,
                session,
                Some(Buffer::new(early_data_received)),
            )
            .map_err(Error::Ktls)?,
            protocol_version,
            handshake_kind,
        })
    }
}

#[derive(Debug, Clone)]
/// A TLS connector with kTLS offload support.
pub struct Connector {
    config: Arc<ClientConfig>,
}

impl Connector {
    #[must_use]
    /// Create a new [`Connector`] with the given [`ClientConfig`].
    pub const fn new(config: Arc<ClientConfig>) -> Self {
        Self { config }
    }

    #[tracing::instrument(skip_all)]
    /// Connects to a TLS server using the given socket and server name.
    ///
    /// ## Errors
    ///
    /// [`Error`]. This may contain the original socket if the setup failed
    /// and the caller can fallback to normal TLS connector implementation.
    pub async fn try_connect<S>(
        &self,
        socket: S,
        server_name: ServerName<'static>,
    ) -> Result<StreamExt<S, ClientConnectionData>, Error>
    where
        S: AsyncRead + AsyncWrite + AsFd + Unpin,
    {
        setup_ulp(&socket)?;

        self.internal_try_connect(socket, server_name)
            .await
    }

    // `rustls` has poor support for async/await...
    async fn internal_try_connect<S>(
        &self,
        mut socket: S,
        server_name: ServerName<'static>,
    ) -> Result<StreamExt<S, ClientConnectionData>, Error>
    where
        S: AsyncRead + AsyncWrite + AsFd + Unpin,
    {
        let mut conn = UnbufferedClientConnection::new(self.config.clone(), server_name)
            .map_err(Error::Config)?;

        let mut incoming = Vec::with_capacity(u16::MAX as usize + 5);
        let mut outgoing = Vec::with_capacity(u16::MAX as usize + 5);
        let mut outgoing_used = 0usize;

        loop {
            let UnbufferedStatus { discard, state } = conn.process_tls_records(&mut incoming);

            let state = state.map_err(Error::Handshake)?;

            match state {
                ConnectionState::BlockedHandshake => {
                    read_record(&mut socket, &mut incoming).await?;
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => {
                    return Err(Error::ConnectionClosedBeforeHandshakeCompleted);
                }
                ConnectionState::EncodeTlsData(mut state) => {
                    match state.encode(&mut outgoing[outgoing_used..]) {
                        Ok(count) => outgoing_used += count,
                        Err(EncodeError::AlreadyEncoded) => unreachable!(),
                        Err(EncodeError::InsufficientSize(e)) => {
                            outgoing.resize(outgoing_used + e.required_size, 0u8);

                            match state.encode(&mut outgoing[outgoing_used..]) {
                                Ok(count) => outgoing_used += count,
                                Err(e) => unreachable!("encode failed after resizing buffer: {e}"),
                            }
                        }
                    }
                }
                ConnectionState::TransmitTlsData(data) => {
                    // FIXME: may_encrypt_app_data to check if we can send early data?

                    socket
                        .write_all(&outgoing[..outgoing_used])
                        .await
                        .map_err(Error::IO)?;
                    outgoing_used = 0;
                    data.done();
                }
                ConnectionState::WriteTraffic(_) => {
                    // Handshake is done
                    incoming.drain(..discard);

                    break;
                }
                ConnectionState::ReadTraffic(_) => unreachable!(
                    "ReadTraffic should not be encountered during the handshake process"
                ),
                _ => unreachable!("unexpected connection state"),
            }

            incoming.drain(..discard);
        }

        let protocol_version = conn
            .protocol_version()
            .expect("Handshake should have been done");
        let handshake_kind = conn.handshake_kind();

        let (secrets, session) = conn
            .dangerous_into_kernel_connection()
            .map_err(Error::ExtractSecrets)?;

        Ok(StreamExt {
            inner: Stream::from(socket, secrets, session, None).map_err(Error::Ktls)?,
            protocol_version,
            handshake_kind,
        })
    }
}

#[allow(clippy::exhaustive_structs)]
#[derive(Debug, Clone, Copy)]
/// A no-op certificate verifier that does not perform any verification.
pub struct NoopVerifier;

impl NoopVerifier {
    #[must_use]
    /// Create a new [`NoopVerifier`].
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl ServerCertVerifier for NoopVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

const RECORD_HDR_SIZE: usize = 5;

/// Read a single TLS record from the socket into the incoming buffer.
pub(crate) async fn read_record<S>(socket: &mut S, incoming: &mut Vec<u8>) -> io::Result<usize>
where
    S: AsyncRead + Unpin,
{
    let mut socket = Pin::new(socket);

    // Read the record header

    incoming.reserve(RECORD_HDR_SIZE);

    let mut record_hdr = ReadBuf::uninit(&mut incoming.spare_capacity_mut()[..RECORD_HDR_SIZE]);

    let record_hdr = {
        while record_hdr.remaining() > 0 {
            poll_fn(|cx| {
                socket
                    .as_mut()
                    .poll_read(cx, &mut record_hdr)
            })
            .await?;
        }

        record_hdr.filled()
    };

    let payload_length = u16::from_be_bytes([record_hdr[3], record_hdr[4]]) as usize;

    // Read the payload

    incoming.reserve(payload_length);

    let mut payload = ReadBuf::uninit(
        &mut incoming.spare_capacity_mut()[RECORD_HDR_SIZE..RECORD_HDR_SIZE + payload_length],
    );

    while payload.remaining() > 0 {
        poll_fn(|cx| {
            socket
                .as_mut()
                .poll_read(cx, &mut payload)
        })
        .await?;
    }

    let bytes_read = RECORD_HDR_SIZE + payload_length;

    #[allow(unsafe_code)]
    // Safety: We have just read data into the space we reserved.
    unsafe {
        incoming.set_len(incoming.len() + bytes_read);
    }

    Ok(bytes_read)
}

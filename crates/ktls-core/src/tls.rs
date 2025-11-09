//! Shim layer for TLS protocol implementations.

use std::io;

use crate::error::{Error, InvalidMessage, Result};
use crate::setup::{TlsCryptoInfoRx, TlsCryptoInfoTx};

#[derive(zeroize_derive::ZeroizeOnDrop)]
/// An AEAD key with fixed size.
///
/// This is a low-level structure, usually you don't need to use it directly
/// unless you are implementing a higher-level abstraction.
pub struct AeadKey<const N: usize>(pub(crate) [u8; N]);

impl<const N: usize> core::fmt::Debug for AeadKey<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AeadKey").finish()
    }
}

impl<const N: usize> AeadKey<N> {
    /// Create a new AEAD key from a byte array.
    #[must_use]
    pub const fn new(inner: [u8; N]) -> Self {
        Self(inner)
    }
}

impl<const N: usize> From<[u8; N]> for AeadKey<N> {
    fn from(arr: [u8; N]) -> Self {
        Self::new(arr)
    }
}

#[non_exhaustive]
/// Secrets used to encrypt/decrypt data in a TLS session.
///
/// This is a low-level structure, usually you don't need to use it directly
/// unless you are implementing a higher-level abstraction.
pub enum ConnectionTrafficSecrets {
    /// Secrets for the `AES_128_GCM` AEAD algorithm
    Aes128Gcm {
        /// AEAD Key
        key: AeadKey<{ libc::TLS_CIPHER_AES_GCM_128_KEY_SIZE }>,

        /// Initialization vector
        iv: [u8; libc::TLS_CIPHER_AES_GCM_128_IV_SIZE],

        /// Salt
        salt: [u8; libc::TLS_CIPHER_AES_GCM_128_SALT_SIZE],
    },

    /// Secrets for the `AES_256_GCM` AEAD algorithm
    Aes256Gcm {
        /// AEAD Key
        key: AeadKey<{ libc::TLS_CIPHER_AES_GCM_256_KEY_SIZE }>,

        /// Initialization vector
        iv: [u8; libc::TLS_CIPHER_AES_GCM_256_IV_SIZE],

        /// Salt
        salt: [u8; libc::TLS_CIPHER_AES_GCM_256_SALT_SIZE],
    },

    /// Secrets for the `CHACHA20_POLY1305` AEAD algorithm
    Chacha20Poly1305 {
        /// AEAD Key
        key: AeadKey<{ libc::TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE }>,

        /// Initialization vector
        iv: [u8; libc::TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE],

        /// Salt (not used)
        salt: [u8; libc::TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE],
    },

    /// Secrets for the `AES_128_CCM` AEAD algorithm
    Aes128Ccm {
        /// AEAD Key
        key: AeadKey<{ libc::TLS_CIPHER_AES_CCM_128_KEY_SIZE }>,

        /// Initialization vector
        iv: [u8; libc::TLS_CIPHER_AES_CCM_128_IV_SIZE],

        /// Salt
        salt: [u8; libc::TLS_CIPHER_AES_CCM_128_SALT_SIZE],
    },

    /// Secrets for the `SM4_GCM` AEAD algorithm
    Sm4Gcm {
        /// AEAD Key
        key: AeadKey<{ libc::TLS_CIPHER_SM4_GCM_KEY_SIZE }>,

        /// Initialization vector
        iv: [u8; libc::TLS_CIPHER_SM4_GCM_IV_SIZE],

        /// Salt
        salt: [u8; libc::TLS_CIPHER_SM4_GCM_SALT_SIZE],
    },

    /// Secrets for the `SM4_CCM` AEAD algorithm
    Sm4Ccm {
        /// AEAD Key
        key: AeadKey<{ libc::TLS_CIPHER_SM4_CCM_KEY_SIZE }>,

        /// Initialization vector
        iv: [u8; libc::TLS_CIPHER_SM4_CCM_IV_SIZE],

        /// Salt
        salt: [u8; libc::TLS_CIPHER_SM4_CCM_SALT_SIZE],
    },

    /// Secrets for the `ARIA_GCM_128` AEAD algorithm
    Aria128Gcm {
        /// AEAD Key
        key: AeadKey<{ libc::TLS_CIPHER_ARIA_GCM_128_KEY_SIZE }>,

        /// Initialization vector
        iv: [u8; libc::TLS_CIPHER_ARIA_GCM_128_IV_SIZE],

        /// Salt
        salt: [u8; libc::TLS_CIPHER_ARIA_GCM_128_SALT_SIZE],
    },

    /// Secrets for the `ARIA_GCM_256` AEAD algorithm
    Aria256Gcm {
        /// AEAD Key
        key: AeadKey<{ libc::TLS_CIPHER_ARIA_GCM_256_KEY_SIZE }>,

        /// Initialization vector
        iv: [u8; libc::TLS_CIPHER_ARIA_GCM_256_IV_SIZE],

        /// Salt
        salt: [u8; libc::TLS_CIPHER_ARIA_GCM_256_SALT_SIZE],
    },
}

#[allow(clippy::exhaustive_structs)]
/// Secrets for transmitting/receiving data over a TLS session.
///
/// After performing a handshake with rustls, these secrets can be extracted
/// to configure kTLS for a socket, and have the kernel take over encryption
/// and/or decryption.
///
/// This is a low-level structure, usually you don't need to use it directly
/// unless you are implementing a higher-level abstraction.
///
/// This is copied from rustls.
pub struct ExtractedSecrets {
    /// sequence number and secrets for the "tx" (transmit) direction
    pub tx: (u64, ConnectionTrafficSecrets),

    /// sequence number and secrets for the "rx" (receive) direction
    pub rx: (u64, ConnectionTrafficSecrets),
}

/// A macro which defines an enum type.
///
/// This is copied from rustls.
macro_rules! enum_builder {
    (
        $(#[doc = $comment:literal])*
        #[repr($uint:ty)]
        $enum_vis:vis enum $enum_name:ident
        {
          $(
              $(#[doc = $enum_comment:literal])*
              $enum_var:ident => $enum_val:literal
          ),*
          $(,)?
          $(
              !Debug:
              $(
                  $(#[doc = $enum_comment_no_debug:literal])*
                  $enum_var_no_debug:ident => $enum_val_no_debug:literal
              ),*
              $(,)?
          )?
        }
    ) => {
        $(#[doc = $comment])*
        #[non_exhaustive]
        #[allow(missing_docs)]
        #[derive(PartialEq, Eq, Clone, Copy)]
        $enum_vis enum $enum_name {
            $(
                $(#[doc = $enum_comment])*
                $enum_var
            ),*
            $(
                ,
                $(
                    $(#[doc = $enum_comment_no_debug])*
                    $enum_var_no_debug
                ),*
            )?
            ,Unknown($uint)
        }

        impl $enum_name {
            // NOTE(allow) generated irrespective if there are callers
            #[allow(dead_code)]
            pub(crate) const fn to_array(self) -> [u8; core::mem::size_of::<$uint>()] {
                self.to_int().to_be_bytes()
            }

            // NOTE(allow) generated irrespective if there are callers
            #[allow(dead_code)]
            pub(crate) const fn as_str(&self) -> Option<&'static str> {
                match self {
                    $( $enum_name::$enum_var => Some(stringify!($enum_var))),*
                    $(, $( $enum_name::$enum_var_no_debug => Some(stringify!($enum_var_no_debug))),* )?
                    ,$enum_name::Unknown(_) => None,
                }
            }

            #[allow(dead_code)]
            pub(crate) const fn from_int(x: $uint) -> Self {
                match x {
                    $($enum_val => $enum_name::$enum_var),*
                    $(, $($enum_val_no_debug => $enum_name::$enum_var_no_debug),* )?
                    , x => $enum_name::Unknown(x),
                }
            }

            #[allow(dead_code)]
            pub(crate) const fn to_int(self) -> $uint {
                match self {
                    $( $enum_name::$enum_var => $enum_val),*
                    $(, $( $enum_name::$enum_var_no_debug => $enum_val_no_debug),* )?
                    ,$enum_name::Unknown(x) => x
                }
            }
        }

        impl From<$uint> for $enum_name {
            fn from(x: $uint) -> Self {
                Self::from_int(x)
            }
        }

        impl From<$enum_name> for $uint {
            fn from(value: $enum_name) -> Self {
                value.to_int()
            }
        }

        impl core::fmt::Debug for $enum_name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    $( $enum_name::$enum_var => f.write_str(stringify!($enum_var)), )*
                    _ => write!(f, "{}(0x{:x?})", stringify!($enum_name), <$uint>::from(*self)),
                }
            }
        }
    };
}

enum_builder! {
    /// The `AlertLevel` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub(crate) enum AlertLevel {
        Warning => 0x01,
        Fatal => 0x02,
    }
}

enum_builder! {
    /// The `AlertDescription` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub enum AlertDescription {
        CloseNotify => 0x00,
        UnexpectedMessage => 0x0a,
        BadRecordMac => 0x14,
        DecryptionFailed => 0x15,
        RecordOverflow => 0x16,
        DecompressionFailure => 0x1e,
        HandshakeFailure => 0x28,
        NoCertificate => 0x29,
        BadCertificate => 0x2a,
        UnsupportedCertificate => 0x2b,
        CertificateRevoked => 0x2c,
        CertificateExpired => 0x2d,
        CertificateUnknown => 0x2e,
        IllegalParameter => 0x2f,
        UnknownCa => 0x30,
        AccessDenied => 0x31,
        DecodeError => 0x32,
        DecryptError => 0x33,
        ExportRestriction => 0x3c,
        ProtocolVersion => 0x46,
        InsufficientSecurity => 0x47,
        InternalError => 0x50,
        InappropriateFallback => 0x56,
        UserCanceled => 0x5a,
        NoRenegotiation => 0x64,
        MissingExtension => 0x6d,
        UnsupportedExtension => 0x6e,
        CertificateUnobtainable => 0x6f,
        UnrecognizedName => 0x70,
        BadCertificateStatusResponse => 0x71,
        BadCertificateHashValue => 0x72,
        UnknownPskIdentity => 0x73,
        CertificateRequired => 0x74,
        NoApplicationProtocol => 0x78,
        EncryptedClientHelloRequired => 0x79, // https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18#section-11.2
    }
}

enum_builder! {
    /// The `ContentType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub enum ContentType {
        ChangeCipherSpec => 0x14,
        Alert => 0x15,
        Handshake => 0x16,
        ApplicationData => 0x17,
        Heartbeat => 0x18,
    }
}

enum_builder! {
    /// The `KeyUpdateRequest` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub(crate) enum KeyUpdateRequest {
        UpdateNotRequested => 0x00,
        UpdateRequested => 0x01,
    }
}

enum_builder! {
    /// The `HandshakeType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub(crate) enum HandshakeType {
        HelloRequest => 0x00,
        ClientHello => 0x01,
        ServerHello => 0x02,
        HelloVerifyRequest => 0x03,
        NewSessionTicket => 0x04,
        EndOfEarlyData => 0x05,
        HelloRetryRequest => 0x06,
        EncryptedExtensions => 0x08,
        Certificate => 0x0b,
        ServerKeyExchange => 0x0c,
        CertificateRequest => 0x0d,
        ServerHelloDone => 0x0e,
        CertificateVerify => 0x0f,
        ClientKeyExchange => 0x10,
        Finished => 0x14,
        CertificateURL => 0x15,
        CertificateStatus => 0x16,
        KeyUpdate => 0x18,
        CompressedCertificate => 0x19,
        MessageHash => 0xfe,
    }
}

enum_builder! {
    /// The `ProtocolVersion` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u16)]
    pub enum ProtocolVersion {
        SSLv2 => 0x0002,
        SSLv3 => 0x0300,
        TLSv1_0 => 0x0301,
        TLSv1_1 => 0x0302,
        TLSv1_2 => 0x0303,
        TLSv1_3 => 0x0304,
        DTLSv1_0 => 0xFEFF,
        DTLSv1_2 => 0xFEFD,
        DTLSv1_3 => 0xFEFC,
    }
}

#[allow(clippy::exhaustive_enums)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The peer in a TLS connection: client or server.
pub enum Peer {
    /// The client.
    Client,

    /// The server.
    Server,
}

/// TLS session context abstraction.
///
/// The kernel only handles TLS encryption and decryption, while the TLS
/// implementation should provide the necessary TLS session context management,
/// including key updates and handling of `NewSessionTicket` messages.
pub trait TlsSession {
    /// Retrieves which peer this session represents (client or server).
    fn peer(&self) -> Peer;

    /// Retrieves the protocol version agreed with the peer.
    fn protocol_version(&self) -> ProtocolVersion;

    /// Update the traffic secret used for encrypting messages sent to the peer.
    ///
    /// Returns the new traffic secret and initial sequence number to use.
    ///
    /// This method is called once we send a TLS 1.3 key update message to the
    /// peer.
    ///
    /// # Errors
    ///
    /// Various errors may be returned depending on the implementation.
    fn update_tx_secret(&mut self) -> Result<TlsCryptoInfoTx>;

    /// Update the traffic secret used for decrypting messages received from the
    /// peer.
    ///
    /// Returns the new traffic secret and initial sequence number to use.
    ///
    /// This method is called once we receive a TLS 1.3 key update message from
    /// the peer.
    ///
    /// # Errors
    ///
    /// Various errors may be returned depending on the implementation.
    fn update_rx_secret(&mut self) -> Result<TlsCryptoInfoRx>;

    /// Handles a `NewSessionTicket` message received from the peer.
    ///
    /// This method expects to be passed the inner payload of the handshake
    /// message. This means that you will need to parse the header of the
    /// handshake message in order to determine the correct payload to pass in.
    /// The message format is described in [RFC 8446 section 4]. `payload`
    /// should not include the `msg_type` or `length` fields.
    ///
    /// [RFC 8446 section 4]: https://datatracker.ietf.org/doc/html/rfc8446#section-4
    ///
    /// # Errors
    ///
    /// Various errors may be returned depending on the implementation.
    fn handle_new_session_ticket(&mut self, _payload: &[u8]) -> Result<()>;

    #[inline]
    /// Handles the message with unknown content type received from the peer.
    ///
    /// By default, this method returns an
    /// [`InvalidContentType`](InvalidMessage::InvalidContentType) error.
    ///
    /// # Errors
    ///
    /// Various errors may be returned depending on the implementation.
    fn handle_unknown_message(&mut self, _content_type: u8, _payload: &[u8]) -> Result<()> {
        Err(Error::InvalidMessage(InvalidMessage::InvalidContentType))
    }
}

#[derive(Debug, Clone, Copy)]
/// A dummy TLS session implementation which does nothing.
pub struct DummyTlsSession {
    peer: Peer,
    protocol_version: ProtocolVersion,
}

/// See [`DummyTlsSession`].
pub static DUMMY_TLS_13_SESSION_CLIENT: DummyTlsSession = DummyTlsSession {
    peer: Peer::Client,
    protocol_version: ProtocolVersion::TLSv1_3,
};

/// See [`DummyTlsSession`].
pub static DUMMY_TLS_13_SESSION_SERVER: DummyTlsSession = DummyTlsSession {
    peer: Peer::Server,
    protocol_version: ProtocolVersion::TLSv1_3,
};

/// See [`DummyTlsSession`].
pub static DUMMY_TLS_12_SESSION_CLIENT: DummyTlsSession = DummyTlsSession {
    peer: Peer::Client,
    protocol_version: ProtocolVersion::TLSv1_2,
};

/// See [`DummyTlsSession`].
pub static DUMMY_TLS_12_SESSION_SERVER: DummyTlsSession = DummyTlsSession {
    peer: Peer::Server,
    protocol_version: ProtocolVersion::TLSv1_2,
};

impl TlsSession for DummyTlsSession {
    fn peer(&self) -> Peer {
        self.peer
    }

    fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    fn update_tx_secret(&mut self) -> Result<TlsCryptoInfoTx> {
        Err(Error::KeyUpdateFailed(io::Error::other(
            "Dummy TLS session does not support key updates",
        )))
    }

    fn update_rx_secret(&mut self) -> Result<TlsCryptoInfoRx> {
        Err(Error::KeyUpdateFailed(io::Error::other(
            "Dummy TLS session does not support key updates",
        )))
    }

    fn handle_new_session_ticket(&mut self, _payload: &[u8]) -> Result<()> {
        Err(Error::HandleNewSessionTicketFailed(io::Error::other(
            "Dummy TLS session does not support new session tickets",
        )))
    }
}

#[cfg(feature = "_shim")]
mod shim {
    #[allow(clippy::wildcard_imports)]
    use super::*;

    #[cfg(feature = "shim-rustls")]
    impl TlsSession for rustls::kernel::KernelConnection<rustls::client::ClientConnectionData> {
        fn peer(&self) -> Peer {
            Peer::Client
        }

        fn protocol_version(&self) -> ProtocolVersion {
            self.protocol_version().into()
        }

        #[track_caller]
        fn update_tx_secret(&mut self) -> Result<TlsCryptoInfoTx> {
            let (seq, secrets) = self
                .update_tx_secret()
                .map_err(|e| Error::KeyUpdateFailed(io::Error::other(e)))?;

            TlsCryptoInfoTx::new(
                self.protocol_version().into(),
                ConnectionTrafficSecrets::try_from(secrets)?,
                seq,
            )
        }

        #[track_caller]
        fn update_rx_secret(&mut self) -> Result<TlsCryptoInfoRx> {
            let (seq, secrets) = self
                .update_rx_secret()
                .map_err(|e| Error::KeyUpdateFailed(io::Error::other(e)))?;

            TlsCryptoInfoRx::new(
                self.protocol_version().into(),
                ConnectionTrafficSecrets::try_from(secrets)?,
                seq,
            )
        }

        #[track_caller]
        fn handle_new_session_ticket(&mut self, payload: &[u8]) -> Result<()> {
            self.handle_new_session_ticket(payload)
                .map_err(|e| Error::HandleNewSessionTicketFailed(io::Error::other(e)))
        }
    }

    #[cfg(feature = "shim-rustls")]
    impl TlsSession for rustls::kernel::KernelConnection<rustls::server::ServerConnectionData> {
        fn peer(&self) -> Peer {
            Peer::Server
        }

        fn protocol_version(&self) -> ProtocolVersion {
            self.protocol_version().into()
        }

        #[track_caller]
        fn update_tx_secret(&mut self) -> Result<TlsCryptoInfoTx> {
            let (seq, secrets) = self
                .update_tx_secret()
                .map_err(|e| Error::KeyUpdateFailed(io::Error::other(e)))?;

            TlsCryptoInfoTx::new(
                self.protocol_version().into(),
                ConnectionTrafficSecrets::try_from(secrets)?,
                seq,
            )
        }

        #[track_caller]
        fn update_rx_secret(&mut self) -> Result<TlsCryptoInfoRx> {
            let (seq, secrets) = self
                .update_rx_secret()
                .map_err(|e| Error::KeyUpdateFailed(io::Error::other(e)))?;

            TlsCryptoInfoRx::new(
                self.protocol_version().into(),
                ConnectionTrafficSecrets::try_from(secrets)?,
                seq,
            )
        }

        fn handle_new_session_ticket(&mut self, _payload: &[u8]) -> Result<()> {
            Err(Error::HandleNewSessionTicketFailed(io::Error::other(
                "Server should not receive new session ticket",
            )))
        }
    }

    #[cfg(feature = "shim-rustls")]
    impl From<rustls::ProtocolVersion> for ProtocolVersion {
        fn from(value: rustls::ProtocolVersion) -> Self {
            Self::from_int(value.into())
        }
    }

    #[cfg(feature = "shim-rustls")]
    impl TryFrom<rustls::ExtractedSecrets> for ExtractedSecrets {
        type Error = Error;

        /// The secrets and context must be extracted from a
        /// [`rustls::client::UnbufferedClientConnection`] or
        /// [`rustls::client::UnbufferedClientConnection`]. See
        /// [`rustls::kernel`] module documentation for more details.
        fn try_from(secrets: rustls::ExtractedSecrets) -> Result<Self, Self::Error> {
            let rustls::ExtractedSecrets {
                tx: (seq_tx, secrets_tx),
                rx: (seq_rx, secrets_rx),
            } = secrets;

            Ok(Self {
                tx: (seq_tx, ConnectionTrafficSecrets::try_from(secrets_tx)?),
                rx: (seq_rx, ConnectionTrafficSecrets::try_from(secrets_rx)?),
            })
        }
    }

    #[cfg(feature = "shim-rustls")]
    impl TryFrom<rustls::ConnectionTrafficSecrets> for ConnectionTrafficSecrets {
        type Error = Error;

        #[track_caller]
        fn try_from(value: rustls::ConnectionTrafficSecrets) -> Result<Self, Self::Error> {
            match value {
                rustls::ConnectionTrafficSecrets::Aes128Gcm { key, iv } => Ok(Self::Aes128Gcm {
                    key: AeadKey::new(
                        key.as_ref()
                            .try_into()
                            .expect("key length mismatch"),
                    ),
                    iv: iv.as_ref()[4..]
                        .try_into()
                        .expect("iv length mismatch"),
                    salt: iv.as_ref()[..4]
                        .try_into()
                        .expect("salt length mismatch"),
                }),
                rustls::ConnectionTrafficSecrets::Aes256Gcm { key, iv } => Ok(Self::Aes256Gcm {
                    key: AeadKey::new(
                        key.as_ref()
                            .try_into()
                            .expect("key length mismatch"),
                    ),
                    iv: iv.as_ref()[4..]
                        .try_into()
                        .expect("iv length mismatch"),
                    salt: iv.as_ref()[..4]
                        .try_into()
                        .expect("salt length mismatch"),
                }),
                rustls::ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                    Ok(Self::Chacha20Poly1305 {
                        key: AeadKey::new(
                            key.as_ref()
                                .try_into()
                                .expect("key length mismatch"),
                        ),
                        iv: iv
                            .as_ref()
                            .try_into()
                            .expect("iv length mismatch"),
                        salt: [],
                    })
                }
                secrets => Err(Error::CryptoMaterial(io::Error::other(format!(
                    "The given crypto material is not supported by the running kernel: {}",
                    std::any::type_name_of_val(&secrets)
                )))),
            }
        }
    }
}

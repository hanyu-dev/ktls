//! Shim layer for TLS protocol implementations.

use crate::error::Result;
use crate::setup::{TlsCryptoInfoRx, TlsCryptoInfoTx};

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
}

#[derive(zeroize_derive::ZeroizeOnDrop)]
/// An AEAD key of fixed size.
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

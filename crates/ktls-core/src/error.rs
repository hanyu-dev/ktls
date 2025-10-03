//! Error related types and implementations.

use std::fmt::{self, Debug};
use std::io;

use crate::tls::{AlertDescription, ProtocolVersion};

/// Specialized `Result` type for this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[non_exhaustive]
#[derive(Debug)]
/// Unified error type for this crate.
pub enum Error {
    /// Setting up TLS ULP failed.
    Ulp(io::Error),

    /// Unsupported TLS protocol version.
    UnsupportedProtocolVersion(ProtocolVersion),

    /// Invalid crypto material (TX), this is likely caused by a older kernel
    /// which doesn't support the requested TLS version or cipher suite.
    CryptoMaterialTx(io::Error),

    /// Invalid crypto material (RX), this is likely caused by a older kernel
    /// which doesn't support the requested TLS version or cipher suite.
    CryptoMaterialRx(io::Error),

    /// The peer sent us a TLS message with invalid contents.
    InvalidMessage(InvalidMessage),

    /// The peer deviated from the standard TLS protocol.
    /// The parameter gives a hint where.
    PeerMisbehaved(PeerMisbehaved),

    /// The TLS library failed to handle the key update request.
    KeyUpdateFailed(io::Error),

    /// The TLS library failed to handle the provided session ticket.
    HandleNewSessionTicketFailed(io::Error),

    /// We received a fatal alert.  This means the peer is unhappy.
    AlertReceived(AlertDescription),

    /// General error.
    General(io::Error),
}

impl Error {
    /// Returns `true` if the error indicates that kTLS is totally not supported
    /// by the running kernel (e.g., kernel module `tls` not being enabled or
    /// the kernel version being too old)
    #[must_use]
    pub fn is_ktls_unsupported(&self) -> bool {
        matches!(self, Self::Ulp(e) if e.raw_os_error() == Some(libc::ENOENT))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ulp(e) => {
                write!(f, "Failed to set TLS ULP: {e}")
            }
            Self::UnsupportedProtocolVersion(v) => {
                write!(f, "The given TLS protocol version is not supported: {v:?}")
            }
            Self::CryptoMaterialTx(e) => {
                write!(
                    f,
                    "The given crypto material (TX) is not supported by the running kernel: {e}"
                )
            }
            Self::CryptoMaterialRx(e) => {
                write!(
                    f,
                    "The given crypto material (RX) is not supported by the running kernel: {e}"
                )
            }
            Self::InvalidMessage(e) => write!(f, "Invalid TLS message: {e:?}"),
            Self::PeerMisbehaved(e) => write!(f, "The peer misbehaved: {e:?}"),
            Self::KeyUpdateFailed(e) => write!(f, "Key update failed: {e}"),
            Self::HandleNewSessionTicketFailed(e) => {
                write!(f, "Handling NewSessionTicket failed: {e}")
            }
            Self::AlertReceived(a) => write!(f, "Received fatal alert from the peer: {a:?}"),
            Self::General(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            Self::Ulp(e) => Some(e),
            Self::CryptoMaterialTx(e) => Some(e),
            Self::CryptoMaterialRx(e) => Some(e),
            Self::KeyUpdateFailed(e) => Some(e),
            Self::HandleNewSessionTicketFailed(e) => Some(e),
            Self::General(e) => Some(e),
            _ => None,
        }
    }
}

impl From<InvalidMessage> for Error {
    fn from(error: InvalidMessage) -> Self {
        Self::InvalidMessage(error)
    }
}

impl From<PeerMisbehaved> for Error {
    fn from(error: PeerMisbehaved) -> Self {
        Self::PeerMisbehaved(error)
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::General(error) => error,
            _ => Self::other(error),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
/// A corrupt TLS message payload that resulted in an error.
///
/// (Copied from rustls)
pub enum InvalidMessage {
    /// An unknown content type was encountered during message decoding.
    InvalidContentType,

    /// A peer sent an unexpected key update request.
    InvalidKeyUpdate,

    /// A TLS message payload was larger then allowed by the specification.
    MessageTooLarge,

    /// Message is shorter than the expected length
    MessageTooShort,

    /// A peer sent an unexpected message type.
    UnexpectedMessage(&'static str),
}

impl InvalidMessage {
    pub(crate) const fn description(&self) -> AlertDescription {
        match self {
            Self::InvalidContentType | Self::UnexpectedMessage(_) => {
                AlertDescription::UnexpectedMessage
            }
            _ => AlertDescription::DecodeError,
        }
    }
}

#[allow(missing_docs)]
#[non_exhaustive]
#[derive(Debug, PartialEq, Clone)]
/// The set of cases where we failed to make a connection because we thought
/// the peer was misbehaving.
///
/// This is `non_exhaustive`: we might add or stop using items here in minor
/// versions.  We also don't document what they mean.  Generally a user of
/// rustls shouldn't vary its behaviour on these error codes, and there is
/// nothing it can do to improve matters.
///
/// (Copied from rustls)
pub enum PeerMisbehaved {
    // AttemptedDowngradeToTls12WhenTls13IsSupported,
    // BadCertChainExtensions,
    // DisallowedEncryptedExtension,
    // DuplicateClientHelloExtensions,
    // DuplicateEncryptedExtensions,
    // DuplicateHelloRetryRequestExtensions,
    // DuplicateNewSessionTicketExtensions,
    // DuplicateServerHelloExtensions,
    // DuplicateServerNameTypes,
    // EarlyDataAttemptedInSecondClientHello,
    // EarlyDataExtensionWithoutResumption,
    // EarlyDataOfferedWithVariedCipherSuite,
    // HandshakeHashVariedAfterRetry,
    // IllegalHelloRetryRequestWithEmptyCookie,
    // IllegalHelloRetryRequestWithNoChanges,
    // IllegalHelloRetryRequestWithOfferedGroup,
    // IllegalHelloRetryRequestWithUnofferedCipherSuite,
    // IllegalHelloRetryRequestWithUnofferedNamedGroup,
    // IllegalHelloRetryRequestWithUnsupportedVersion,
    // IllegalHelloRetryRequestWithWrongSessionId,
    // IllegalHelloRetryRequestWithInvalidEch,
    IllegalMiddleboxChangeCipherSpec,
    // IllegalTlsInnerPlaintext,
    // IncorrectBinder,
    // InvalidCertCompression,
    // InvalidMaxEarlyDataSize,
    // InvalidKeyShare,
    KeyEpochWithPendingFragment,
    // KeyUpdateReceivedInQuicConnection,
    // MessageInterleavedWithHandshakeMessage,
    // MissingBinderInPskExtension,
    // MissingKeyShare,
    // MissingPskModesExtension,
    // MissingQuicTransportParameters,
    // NoCertificatesPresented,
    // OfferedDuplicateCertificateCompressions,
    // OfferedDuplicateKeyShares,
    // OfferedEarlyDataWithOldProtocolVersion,
    // OfferedEmptyApplicationProtocol,
    // OfferedIncorrectCompressions,
    // PskExtensionMustBeLast,
    // PskExtensionWithMismatchedIdsAndBinders,
    // RefusedToFollowHelloRetryRequest,
    // RejectedEarlyDataInterleavedWithHandshakeMessage,
    // ResumptionAttemptedWithVariedEms,
    // ResumptionOfferedWithVariedCipherSuite,
    // ResumptionOfferedWithVariedEms,
    // ResumptionOfferedWithIncompatibleCipherSuite,
    // SelectedDifferentCipherSuiteAfterRetry,
    // SelectedInvalidPsk,
    // SelectedTls12UsingTls13VersionExtension,
    // SelectedUnofferedApplicationProtocol,
    // SelectedUnofferedCertCompression,
    // SelectedUnofferedCipherSuite,
    // SelectedUnofferedCompression,
    // SelectedUnofferedKxGroup,
    // SelectedUnofferedPsk,
    // ServerEchoedCompatibilitySessionId,
    // ServerHelloMustOfferUncompressedEcPoints,
    // ServerNameDifferedOnRetry,
    // ServerNameMustContainOneHostName,
    // SignedKxWithWrongAlgorithm,
    // SignedHandshakeWithUnadvertisedSigScheme,
    // TooManyEmptyFragments,
    // TooManyKeyUpdateRequests,
    // TooManyRenegotiationRequests,
    // TooManyWarningAlertsReceived,
    // TooMuchEarlyDataReceived,
    // UnexpectedCleartextExtension,
    // UnsolicitedCertExtension,
    // UnsolicitedEncryptedExtension,
    // UnsolicitedSctList,
    // UnsolicitedServerHelloExtension,
    // WrongGroupForKeyShare,
    // UnsolicitedEchExtension,
}

impl PeerMisbehaved {
    pub(crate) const fn description(&self) -> AlertDescription {
        match self {
            Self::KeyEpochWithPendingFragment | Self::IllegalMiddleboxChangeCipherSpec => {
                AlertDescription::UnexpectedMessage
            }
            #[allow(unreachable_patterns)]
            _ => AlertDescription::InternalError,
        }
    }
}

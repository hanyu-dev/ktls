//! Transport Layer Security (TLS) is a Upper Layer Protocol (ULP) that runs
//! over TCP. TLS provides end-to-end data integrity and confidentiality.
//!
//! Once the TCP connection is established, sets the TLS ULP, which allows us to
//! set/get TLS socket options.
//!
//! This module provides the [`setup_ulp`] function, which sets the ULP (Upper
//! Layer Protocol) to TLS for a TCP socket. The user can also determine whether
//! the kernel supports kTLS with [`setup_ulp`].
//!
//! After the TLS handshake is completed, we have all the parameters required to
//! move the data-path to the kernel. There is a separate socket option for
//! moving the transmit and the receive into the kernel.
//!
//! This module provides the low-level [`setup_tls_params`] function, which sets
//! the Kernel TLS parameters on the TCP socket, allowing the kernel to handle
//! encryption and decryption of the TLS data.

use std::marker::PhantomData;
use std::os::fd::{AsFd, AsRawFd};
use std::{fmt, io, mem};

use nix::sys::socket::{setsockopt, sockopt};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::tls::{AeadKey, ConnectionTrafficSecrets, ProtocolVersion};

/// Sets the TLS Upper Layer Protocol (ULP).
///
/// This should be called before performing any I/O operations on the
/// socket.
///
/// # Errors
///
/// The caller may check if the error is due to the running kernel not
/// supporting kTLS (e.g., kernel module `tls` not being enabled or the
/// kernel version being too old) totally with [`Error::is_ktls_unsupported`].
pub fn setup_ulp<S: AsFd>(socket: &S) -> Result<()> {
    setsockopt(socket, sockopt::TcpUlp::default(), b"tls")
        .map_err(io::Error::from)
        .map_err(Error::Ulp)
}

/// Sets the kTLS parameters on the socket after the TLS handshake is completed.
///
/// This is a low-level function, usually you don't need to call it directly.
///
/// ## Errors
///
/// * Invalid crypto materials.
/// * Syscall error.
pub fn setup_tls_params<S: AsFd>(
    socket: &S,
    tx: TlsCryptoInfoTx,
    rx: TlsCryptoInfoRx,
) -> Result<()> {
    tx.set(socket)?;
    rx.set(socket)?;

    Ok(())
}

/// A wrapper around the `libc::tls12_crypto_info_*` structs, use with setting
/// up the kTLS r/w parameters on the TCP socket.
///
/// This is originated from the `nix` crate, which currently does not support
/// `AES-128-CCM`, `SM4-*` or `ARIA-*`, so we implement our own version here.
pub struct TlsCryptoInfo<D> {
    inner: TlsCryptoInfoImpl,
    _direction: PhantomData<D>,
}

impl fmt::Debug for TlsCryptoInfoImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsCryptoInfo").finish()
    }
}

/// Type alias of [`TlsCryptoInfo`], for transmit direction.
pub type TlsCryptoInfoTx = TlsCryptoInfo<Tx>;

/// Type alias of [`TlsCryptoInfo`], for receive direction.
pub type TlsCryptoInfoRx = TlsCryptoInfo<Rx>;

/// Marker type for the "tx" (transmit) direction.
pub struct Tx;

/// Marker type for the "rx" (receive) direction.
pub struct Rx;

impl<D> TlsCryptoInfo<D> {
    #[inline]
    /// Creates a new [`TlsCryptoInfo`] from the given protocol version and
    /// connection traffic secrets.
    pub fn new(
        protocol_version: ProtocolVersion,
        secrets: ConnectionTrafficSecrets,
        seq: u64,
    ) -> Result<Self> {
        TlsCryptoInfoImpl::new(protocol_version, secrets, seq).map(|inner| Self {
            inner,
            _direction: PhantomData,
        })
    }
}

impl TlsCryptoInfoTx {
    /// Sets the kTLS parameters on the given file descriptor for the transmit
    /// direction.
    ///
    /// This is a low-level function, usually you don't need to call it
    /// directly.
    pub fn set<S: AsFd>(&self, socket: &S) -> Result<()> {
        self.inner
            .set(socket, libc::TLS_TX)
            .map_err(Error::CryptoMaterialTx)
    }
}

impl TlsCryptoInfoRx {
    /// Sets the kTLS parameters on the given file descriptor for the receive
    /// direction.
    ///
    /// This is a low-level function, usually you don't need to call it
    /// directly.
    pub fn set<S: AsFd>(&self, socket: &S) -> Result<()> {
        self.inner
            .set(socket, libc::TLS_RX)
            .map_err(Error::CryptoMaterialRx)
    }
}

#[repr(C)]
enum TlsCryptoInfoImpl {
    AesGcm128(libc::tls12_crypto_info_aes_gcm_128),
    AesGcm256(libc::tls12_crypto_info_aes_gcm_256),
    AesCcm128(libc::tls12_crypto_info_aes_ccm_128),
    Chacha20Poly1305(libc::tls12_crypto_info_chacha20_poly1305),
    Sm4Gcm(libc::tls12_crypto_info_sm4_gcm),
    Sm4Ccm(libc::tls12_crypto_info_sm4_ccm),
    Aria128Gcm(libc::tls12_crypto_info_aria_gcm_128),
    Aria256Gcm(libc::tls12_crypto_info_aria_gcm_256),
}

impl TlsCryptoInfoImpl {
    #[allow(unused_qualifications)]
    #[allow(clippy::cast_possible_truncation)] // Since Rust 2021 doesn't have `size_of_val` included in prelude.
    #[inline]
    /// Sets the kTLS parameters on the given file descriptor.
    fn set<S: AsFd>(&self, socket: &S, direction: libc::c_int) -> io::Result<()> {
        let (ffi_ptr, ffi_len) = match self {
            Self::AesGcm128(crypto_info) => (
                <*const _>::cast(crypto_info),
                mem::size_of_val(crypto_info) as libc::socklen_t,
            ),
            Self::AesGcm256(crypto_info) => (
                <*const _>::cast(crypto_info),
                mem::size_of_val(crypto_info) as libc::socklen_t,
            ),
            Self::AesCcm128(crypto_info) => (
                <*const _>::cast(crypto_info),
                mem::size_of_val(crypto_info) as libc::socklen_t,
            ),
            Self::Chacha20Poly1305(crypto_info) => (
                <*const _>::cast(crypto_info),
                mem::size_of_val(crypto_info) as libc::socklen_t,
            ),
            Self::Sm4Gcm(crypto_info) => (
                <*const _>::cast(crypto_info),
                mem::size_of_val(crypto_info) as libc::socklen_t,
            ),
            Self::Sm4Ccm(crypto_info) => (
                <*const _>::cast(crypto_info),
                mem::size_of_val(crypto_info) as libc::socklen_t,
            ),
            Self::Aria128Gcm(crypto_info) => (
                <*const _>::cast(crypto_info),
                mem::size_of_val(crypto_info) as libc::socklen_t,
            ),
            Self::Aria256Gcm(crypto_info) => (
                <*const _>::cast(crypto_info),
                mem::size_of_val(crypto_info) as libc::socklen_t,
            ),
        };

        #[allow(unsafe_code)]
        // SAFETY: syscall
        let ret = unsafe {
            libc::setsockopt(
                socket.as_fd().as_raw_fd(),
                libc::SOL_TLS,
                direction,
                ffi_ptr,
                ffi_len,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Extract the [`TlsCryptoInfo`] from the given
    /// [`ProtocolVersion`] and [`ConnectionTrafficSecrets`].
    fn new(
        protocol_version: ProtocolVersion,
        secrets: ConnectionTrafficSecrets,
        seq: u64,
    ) -> Result<Self> {
        let version = match protocol_version {
            ProtocolVersion::TLSv1_2 => libc::TLS_1_2_VERSION,
            ProtocolVersion::TLSv1_3 => libc::TLS_1_3_VERSION,
            r => return Err(Error::UnsupportedProtocolVersion(r)),
        };

        let this = match secrets {
            ConnectionTrafficSecrets::Aes128Gcm {
                key: AeadKey(key),
                iv,
                salt,
            } => Self::AesGcm128(libc::tls12_crypto_info_aes_gcm_128 {
                info: libc::tls_crypto_info {
                    version,
                    cipher_type: libc::TLS_CIPHER_AES_GCM_128,
                },
                iv,
                key,
                salt,
                rec_seq: seq.to_be_bytes(),
            }),
            ConnectionTrafficSecrets::Aes256Gcm {
                key: AeadKey(key),
                iv,
                salt,
            } => Self::AesGcm256(libc::tls12_crypto_info_aes_gcm_256 {
                info: libc::tls_crypto_info {
                    version,
                    cipher_type: libc::TLS_CIPHER_AES_GCM_256,
                },
                iv,
                key,
                salt,
                rec_seq: seq.to_be_bytes(),
            }),
            ConnectionTrafficSecrets::Chacha20Poly1305 {
                key: AeadKey(key),
                iv,
                salt,
            } => Self::Chacha20Poly1305(libc::tls12_crypto_info_chacha20_poly1305 {
                info: libc::tls_crypto_info {
                    version,
                    cipher_type: libc::TLS_CIPHER_CHACHA20_POLY1305,
                },
                iv,
                key,
                salt,
                rec_seq: seq.to_be_bytes(),
            }),
            ConnectionTrafficSecrets::Aes128Ccm {
                key: AeadKey(key),
                iv,
                salt,
            } => Self::AesCcm128(libc::tls12_crypto_info_aes_ccm_128 {
                info: libc::tls_crypto_info {
                    version,
                    cipher_type: libc::TLS_CIPHER_AES_CCM_128,
                },
                iv,
                key,
                salt,
                rec_seq: seq.to_be_bytes(),
            }),
            ConnectionTrafficSecrets::Sm4Gcm {
                key: AeadKey(key),
                iv,
                salt,
            } => Self::Sm4Gcm(libc::tls12_crypto_info_sm4_gcm {
                info: libc::tls_crypto_info {
                    version,
                    cipher_type: libc::TLS_CIPHER_SM4_GCM,
                },
                iv,
                key,
                salt,
                rec_seq: seq.to_be_bytes(),
            }),
            ConnectionTrafficSecrets::Sm4Ccm {
                key: AeadKey(key),
                iv,
                salt,
            } => Self::Sm4Ccm(libc::tls12_crypto_info_sm4_ccm {
                info: libc::tls_crypto_info {
                    version,
                    cipher_type: libc::TLS_CIPHER_SM4_CCM,
                },
                iv,
                key,
                salt,
                rec_seq: seq.to_be_bytes(),
            }),
            ConnectionTrafficSecrets::Aria128Gcm {
                key: AeadKey(key),
                iv,
                salt,
            } => Self::Aria128Gcm(libc::tls12_crypto_info_aria_gcm_128 {
                info: libc::tls_crypto_info {
                    version,
                    cipher_type: libc::TLS_CIPHER_ARIA_GCM_128,
                },
                iv,
                key,
                salt,
                rec_seq: seq.to_be_bytes(),
            }),
            ConnectionTrafficSecrets::Aria256Gcm {
                key: AeadKey(key),
                iv,
                salt,
            } => Self::Aria256Gcm(libc::tls12_crypto_info_aria_gcm_256 {
                info: libc::tls_crypto_info {
                    version,
                    cipher_type: libc::TLS_CIPHER_ARIA_GCM_256,
                },
                iv,
                key,
                salt,
                rec_seq: seq.to_be_bytes(),
            }),
        };

        Ok(this)
    }
}

impl Drop for TlsCryptoInfoImpl {
    fn drop(&mut self) {
        match self {
            Self::AesGcm128(libc::tls12_crypto_info_aes_gcm_128 { key, .. }) => {
                key.zeroize();
            }
            Self::AesGcm256(libc::tls12_crypto_info_aes_gcm_256 { key, .. }) => {
                key.zeroize();
            }
            Self::AesCcm128(libc::tls12_crypto_info_aes_ccm_128 { key, .. }) => {
                key.zeroize();
            }
            Self::Chacha20Poly1305(libc::tls12_crypto_info_chacha20_poly1305 { key, .. }) => {
                key.zeroize();
            }
            Self::Sm4Gcm(libc::tls12_crypto_info_sm4_gcm { key, .. }) => {
                key.zeroize();
            }
            Self::Sm4Ccm(libc::tls12_crypto_info_sm4_ccm { key, .. }) => {
                key.zeroize();
            }
            Self::Aria128Gcm(libc::tls12_crypto_info_aria_gcm_128 { key, .. }) => {
                key.zeroize();
            }
            Self::Aria256Gcm(libc::tls12_crypto_info_aria_gcm_256 { key, .. }) => {
                key.zeroize();
            }
        }
    }
}

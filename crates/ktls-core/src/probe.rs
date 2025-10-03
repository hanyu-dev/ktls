//! Utilities for probing kernel TLS support.

use std::io;
use std::net::{TcpListener, TcpStream};

use bitfield_struct::bitfield;

use crate::setup::{setup_ulp, TlsCryptoInfoTx};
use crate::tls::{AeadKey, ConnectionTrafficSecrets, ProtocolVersion};

#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
/// The current Linux kernel's kTLS cipher suites compatibility.
pub struct Compatibilities {
    /// TLS 1.2 cipher suite compatibility.
    pub tls12: Compatibility,

    /// TLS 1.3 cipher suite compatibility.
    pub tls13: Compatibility,
}

impl Compatibilities {
    /// Probes the current Linux kernel for kTLS cipher suites compatibility.
    ///
    /// Returns `None` if the kernel does not support kTLS at all.
    ///
    /// ## Errors
    ///
    /// [`io::Error`].
    pub fn probe() -> io::Result<Option<Self>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;

        let local_addr = listener.local_addr()?;

        let mut tls12 = Compatibility::new();
        let mut tls13 = Compatibility::new();

        macro_rules! test {
            ($ver:ident, $cipher:ident, $c:ident, $m:ident) => {{
                let stream = TcpStream::connect(local_addr)?;

                match setup_ulp(&stream) {
                    Ok(_) => {}
                    Err(err) if err.is_ktls_unsupported() => return Ok(None),
                    Err(err) => {
                        crate::error!(
                            "Failed to probe compatibility of {} {}",
                            stringify!($ver),
                            stringify!($cipher)
                        );

                        return Err(err.into());
                    }
                }

                if TlsCryptoInfoTx::new(
                    ProtocolVersion::$ver,
                    ConnectionTrafficSecrets::$cipher {
                        key: AeadKey::new(Default::default()),
                        iv: Default::default(),
                        salt: Default::default(),
                    },
                    0,
                )
                .unwrap()
                .set(&stream)
                .inspect_err(|err| {
                    crate::trace!(
                        "{} {}: Not suitable: {}",
                        stringify!($ver),
                        stringify!($cipher),
                        err
                    );
                })
                .is_ok()
                {
                    $c.$m(true);
                }
            }};
        }

        test!(TLSv1_2, Aes128Gcm, tls12, set_aes_128_gcm);
        test!(TLSv1_2, Aes256Gcm, tls12, set_aes_256_gcm);
        test!(TLSv1_2, Chacha20Poly1305, tls12, set_chacha20_poly1305);
        test!(TLSv1_2, Aes128Ccm, tls12, set_aes_128_ccm);
        test!(TLSv1_2, Sm4Gcm, tls12, set_sm4_gcm);
        test!(TLSv1_2, Sm4Ccm, tls12, set_sm4_ccm);
        test!(TLSv1_2, Aria128Gcm, tls12, set_aria_128_gcm);
        test!(TLSv1_2, Aria256Gcm, tls12, set_aria_256_gcm);

        test!(TLSv1_3, Aes128Gcm, tls13, set_aes_128_gcm);
        test!(TLSv1_3, Aes256Gcm, tls13, set_aes_256_gcm);
        test!(TLSv1_3, Chacha20Poly1305, tls13, set_chacha20_poly1305);
        test!(TLSv1_3, Aes128Ccm, tls13, set_aes_128_ccm);
        test!(TLSv1_3, Sm4Gcm, tls13, set_sm4_gcm);
        test!(TLSv1_3, Sm4Ccm, tls13, set_sm4_ccm);
        test!(TLSv1_3, Aria128Gcm, tls13, set_aria_128_gcm);
        test!(TLSv1_3, Aria256Gcm, tls13, set_aria_256_gcm);

        Ok(Some(Self { tls12, tls13 }))
    }
}

#[bitfield(u8)]
/// Represents the compatibility of various TLS cipher suites with kernel TLS.
pub struct Compatibility {
    /// AES-128-GCM cipher suite support.
    pub aes_128_gcm: bool,

    /// AES-256-GCM cipher suite support.
    pub aes_256_gcm: bool,

    /// ChaCha20-Poly1305 cipher suite support.
    pub chacha20_poly1305: bool,

    /// AES-128-CCM cipher suite support.
    pub aes_128_ccm: bool,

    /// SM4-GCM cipher suite support.
    pub sm4_gcm: bool,

    /// SM4-CCM cipher suite support.
    pub sm4_ccm: bool,

    /// ARIA-128-GCM cipher suite support.
    pub aria_128_gcm: bool,

    /// ARIA-256-GCM cipher suite support.
    pub aria_256_gcm: bool,
}

impl Compatibility {
    /// Returns whether no cipher suites are supported (the corresponding TLS
    /// version is unsupported).
    #[must_use] 
    pub const fn is_unsupported(&self) -> bool {
        self.0 == 0
    }
}

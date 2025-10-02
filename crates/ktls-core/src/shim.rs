//! Shim layer for different TLS libraries.

// Make linter happy
#![cfg_attr(not(feature = "shim-rustls"), allow(unused_imports))]

use std::io;

use crate::error::{Error, Result};
use crate::setup::{TlsCryptoInfoRx, TlsCryptoInfoTx};
use crate::tls::{AeadKey, ConnectionTrafficSecrets, Peer, ProtocolVersion, Session};

#[cfg(feature = "shim-rustls")]
impl Session for rustls::kernel::KernelConnection<rustls::client::ClientConnectionData> {
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
            .map_err(|e| Error::KeyUpdateFailed(io::Error::other(format!("{e}"))))?;

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
            .map_err(|e| Error::KeyUpdateFailed(io::Error::other(format!("{e}"))))?;

        TlsCryptoInfoRx::new(
            self.protocol_version().into(),
            ConnectionTrafficSecrets::try_from(secrets)?,
            seq,
        )
    }

    fn handle_new_session_ticket(&mut self, payload: &[u8]) -> Result<()> {
        self.handle_new_session_ticket(payload)
            .map_err(|e| Error::HandleNewSessionTicketFailed(io::Error::other(format!("{e}"))))
    }
}

#[cfg(feature = "shim-rustls")]
impl Session for rustls::kernel::KernelConnection<rustls::server::ServerConnectionData> {
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
            .map_err(|e| Error::KeyUpdateFailed(io::Error::other(format!("{e}"))))?;

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
            .map_err(|e| Error::KeyUpdateFailed(io::Error::other(format!("{e}"))))?;

        TlsCryptoInfoRx::new(
            self.protocol_version().into(),
            ConnectionTrafficSecrets::try_from(secrets)?,
            seq,
        )
    }

    #[track_caller]
    fn handle_new_session_ticket(&mut self, _payload: &[u8]) -> Result<()> {
        unreachable!("Only clients receive NewSessionTicket messages")
    }
}

#[cfg(feature = "shim-rustls")]
impl From<rustls::ProtocolVersion> for ProtocolVersion {
    fn from(value: rustls::ProtocolVersion) -> Self {
        ProtocolVersion::from_int(value.into())
    }
}

#[cfg(feature = "shim-rustls")]
impl TryFrom<rustls::ConnectionTrafficSecrets> for ConnectionTrafficSecrets {
    type Error = Error;

    fn try_from(value: rustls::ConnectionTrafficSecrets) -> Result<Self, Self::Error> {
        match value {
            rustls::ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                Ok(ConnectionTrafficSecrets::Aes128Gcm {
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
                })
            }
            rustls::ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
                Ok(ConnectionTrafficSecrets::Aes256Gcm {
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
                })
            }
            rustls::ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
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
            secrets => Err(Error::CryptoMaterialTx(io::Error::other(format!(
                "The given crypto material is not supported by the running kernel: {}",
                std::any::type_name_of_val(&secrets)
            )))),
        }
    }
}

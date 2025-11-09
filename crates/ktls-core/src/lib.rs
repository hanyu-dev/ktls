#![doc = include_str!("../README.md")]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::used_underscore_binding)]

pub mod context;
pub mod error;
pub mod ffi;
mod log;
#[cfg(feature = "probe-ktls-compatibility")]
pub mod probe;
pub mod setup;
pub mod tls;
pub mod utils;

pub use self::context::Context;
pub use self::error::Error;
#[cfg(feature = "probe-ktls-compatibility")]
pub use self::probe::{Compatibilities, Compatibility};
pub use self::setup::{setup_tls_params, setup_ulp, TlsCryptoInfoRx, TlsCryptoInfoTx};
pub use self::tls::{
    AeadKey, AlertDescription, ConnectionTrafficSecrets, ContentType, DummyTlsSession,
    ExtractedSecrets, Peer, ProtocolVersion, TlsSession, DUMMY_TLS_12_SESSION_CLIENT,
    DUMMY_TLS_12_SESSION_SERVER, DUMMY_TLS_13_SESSION_CLIENT, DUMMY_TLS_13_SESSION_SERVER,
};
pub use self::utils::Buffer;

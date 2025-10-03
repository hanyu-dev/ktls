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
pub mod shim;
pub mod tls;
pub mod utils;

pub use self::context::Context;
pub use self::error::Error;
pub use self::setup::{setup_tls_params, setup_ulp, TlsCryptoInfoRx, TlsCryptoInfoTx};
pub use self::tls::{ConnectionTrafficSecrets, ProtocolVersion, TlsSession};

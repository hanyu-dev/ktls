//! Tests

use std::time::Duration;

use clap::Parser;
use ktls_tests::{init_logger, test_echo_async, Termination};
use rustls::CipherSuite;
use tokio::time::timeout;

#[tokio::main]
async fn main() {
    init_logger();

    tracing::info!("Starting test");

    let cli = Cli::try_parse().expect("Invalid arguments");

    let termination_options = if let Some(termination) = cli.termination {
        &[termination][..]
    } else {
        &[Termination::Client, Termination::Server][..]
    };

    let cipher_options = if let Some(cipher) = cli.cipher {
        &[Some(cipher)][..]
    } else {
        &[
            None,
            Some(CipherSuite::TLS13_AES_128_GCM_SHA256),
            Some(CipherSuite::TLS13_AES_256_GCM_SHA384),
            Some(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
            Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
            Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
            Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
        ][..]
    };

    for &termination in termination_options {
        for &cipher in cipher_options {
            tracing::info!(
                "Testing termination: {:?}, cipher: {:?}",
                termination,
                cipher
            );

            // Test: kTLS offloaded client <-> kTLS offloaded server
            timeout(
                Duration::from_secs(15),
                test_echo_async(termination, cipher),
            )
            .await
            .expect("test_bidi_offloaded_echo_async timeout")
            .expect("test_bidi_offloaded_echo_async failed");

            tracing::info!("test_echo completed successfully");
        }
    }

    tracing::info!("Test finished");
}

#[derive(clap::Parser)]
struct Cli {
    #[arg(short, long, value_parser = termination_parser)]
    termination: Option<Termination>,

    #[arg(short, long, value_parser = cipher_parser)]
    cipher: Option<CipherSuite>,
}

fn termination_parser(s: &str) -> Result<Termination, String> {
    match s.to_lowercase().as_str() {
        "client" => Ok(Termination::Client),
        "server" => Ok(Termination::Server),
        _ => Err(format!("Invalid termination: {s}")),
    }
}

fn cipher_parser(s: &str) -> Result<CipherSuite, String> {
    match s {
        s if s
            == CipherSuite::TLS13_AES_128_GCM_SHA256
                .as_str()
                .unwrap() =>
        {
            Ok(CipherSuite::TLS13_AES_128_GCM_SHA256)
        }
        s if s
            == CipherSuite::TLS13_AES_256_GCM_SHA384
                .as_str()
                .unwrap() =>
        {
            Ok(CipherSuite::TLS13_AES_256_GCM_SHA384)
        }
        s if s
            == CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                .as_str()
                .unwrap() =>
        {
            Ok(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
        }
        s if s
            == CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                .as_str()
                .unwrap() =>
        {
            Ok(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
        }
        s if s
            == CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                .as_str()
                .unwrap() =>
        {
            Ok(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
        }
        s if s
            == CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                .as_str()
                .unwrap() =>
        {
            Ok(CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
        }
        _ => Err(format!("Invalid cipher: {s}")),
    }
}

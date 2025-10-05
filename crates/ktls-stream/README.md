# ktls-stream

[![Crates.io](https://img.shields.io/crates/v/ktls-stream)](https://crates.io/crates/ktls-stream)
[![Docs.rs](https://docs.rs/ktls-stream/badge.svg)](https://docs.rs/ktls-stream)
[![Test pipeline](https://github.com/hanyu-dev/ktls/actions/workflows/ci.yml/badge.svg)](https://github.com/hanyu-dev/ktls/actions/workflows/ci.yml?query=branch%3Amain)
[![Test pipeline](https://github.com/hanyu-dev/ktls/actions/workflows/kernel-compatibility-test.yml/badge.svg)](https://github.com/hanyu-dev/ktls/actions/workflows/kernel-compatibility-test.yml?query=branch%3Amain)
[![Code Coverage](https://codecov.io/github/hanyu-dev/ktls/graph/badge.svg?token=vwYtOhk2cV)](https://codecov.io/github/hanyu-dev/ktls)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

`Stream` abstraction for implementing Linux kernel TLS (kTLS) offload.

## Overview

This crate is built on top of [`ktls-core`](https://crates.io/crates/ktls-core) and provides higher-level `Stream` abstraction that can be used as a drop-in replacement of `TcpStream` (or `UnixStream`, etc) after setting up kTLS offload.

## Usage

Setting up kTLS offload generally involves these steps:

```rust,no_run
use tokio::net::TcpStream;

// Step 1: Creates a `TcpStream` (or something else like `UnixStream`).
let stream = TcpStream::connect("www.example.com:443").await.expect("failed to connect");

// Step 2: Configures TLS User Level Protocol (ULP) on the socket.
if let Err(e) = ktls_core::setup_ulp(&stream) {
    if e.is_ktls_unsupported() {
        // You can fallback to general TLS implementation (omitted here).
    } else {
        panic!("failed to set TLS ULP: {e}");
    }
}

// Step 3: Performs TLS handshake using your preferred TLS library over the socket.
// (omitted here)
let (extracted_secrets, early_data_received) = handshake(&stream, ...).await.expect("failed to perform TLS handshake");

// Step 4: Extracts the crypto materials after handshake completion.
// (omitted here)
let (tls_session, tls_crypto_info_tx, tls_crypto_info_rx) = extract_tls_crypto_info(&extracted_secrets)
    .expect("failed to extract TLS crypto info");

// Step 5: Sets the kTLS parameters on the socket after the TLS handshake is completed.
ktls_core::setup_tls_params(&stream, &tls_crypto_info_tx, &tls_crypto_info_rx).expect("failed to set kTLS parameters");

// Step 6: Creates a `Stream` using the configured socket and crypto materials.
let mut stream = ktls_stream::Stream::new(stream, tls_session, Some(early_data_received))
    .expect("failed to create ktls stream");

// Now you can use the `Stream` as a drop-in replacement of the original `TcpStream`.
// (omitted here)
```

Please check [`ktls-tests`](https://github.com/hanyu-dev/ktls/tree/main/crates/ktls-tests) for more examples.

## Kernel Compatibility

We perform daily CI tests against the following kernel versions:

|     Ver.     | Min. Ver. |
| :----------: | :-------: |
|   mainline   |     -     |
|    stable    |     -     |
| 6.12.x (LTS) |  6.12.0   |
| 6.6.x (LTS)  |   6.6.0   |
| 6.1.x (LTS)  |  6.1.28   |
| 5.15.x (LTS) |  5.15.25  |
| 5.10.x (LTS) | 5.10.102  |
| 5.4.x (LTS)  |  5.4.181  |

- For LTS versions, we test against the latest patch.
- Have simply tested the minimum applicable kernel version, and listed above, though lacking CI testing guarantees.

  We recommend using the latest Linux kernel, at least 6.6 LTS, for better support of kTLS.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

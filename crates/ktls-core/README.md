# ktls-core

[![Crates.io](https://img.shields.io/crates/v/ktls-core)](https://crates.io/crates/ktls-core)
[![Docs.rs](https://docs.rs/ktls-core/badge.svg)](https://docs.rs/ktls-core)
[![Code Coverage](https://codecov.io/github/hanyu-dev/ktls/graph/badge.svg?token=vwYtOhk2cV)](https://codecov.io/github/hanyu-dev/ktls)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

Abstraction for implementing Linux kernel TLS (kTLS) offload in Rust.

## Overview

This crate provides a low-level interface for setting up kernel TLS (kTLS) regardless of your preferred TLS library.

## Implementation Guide

Setting up kTLS generally involves these steps:

1. Creates a `TcpStream` (or something else like `UnixStream`).
1. Configures the TLS User Level Protocol (ULP) on the stream.
1. Performs the TLS handshake using your preferred TLS library over the stream.
1. Creates the `KtlsStream` using the configured stream and crypto materials.

Then you can use the `KtlsStream` as a drop-in replacement of the original `TcpStream`.

## Kernel Compatibility

We perform daily CI tests against the following kernel versions:

| Version | CI Status |
| :-: | :-: |
| mainline | N/A |
| stable | N/A |
| 6.6.x (LTS) | N/A |
| 6.1.x (LTS) | N/A |
| 5.15.x (LTS) | N/A |
| 5.10.x (LTS) | N/A |
| 5.4.x (LTS) | N/A |

(For LTS kernels, we test against the latest patch version)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

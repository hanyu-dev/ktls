# ktls-core

[![Crates.io](https://img.shields.io/crates/v/ktls-core)](https://crates.io/crates/ktls-core)
[![Docs.rs](https://docs.rs/ktls-core/badge.svg)](https://docs.rs/ktls-core)
[![Test pipeline](https://github.com/hanyu-dev/ktls/actions/workflows/ci.yml/badge.svg)](https://github.com/hanyu-dev/ktls/actions/workflows/ci.yml?query=branch%3Amain)
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
1. Creates the `Stream` using the configured stream and crypto materials.

Then you can use the `Stream` as a drop-in replacement of the original `TcpStream`.

## Kernel Compatibility

[![Test pipeline](https://github.com/hanyu-dev/ktls/actions/workflows/kernel-compatibility-test.yml/badge.svg)](https://github.com/hanyu-dev/ktls/actions/workflows/kernel-compatibility-test.yml?query=branch%3Amain)

We perform daily CI tests against the following kernel versions:

|   Version    |
| :----------: |
|   mainline   |
|    stable    |
| 6.6.x (LTS)  |
| 6.1.x (LTS)  |
| 5.15.x (LTS) |
| 5.10.x (LTS) |
| 5.4.x (LTS)  |

(For LTS kernels, we test against the latest patch version)

For examples and tests details, please refer to the [ktls-tests](../ktls-tests/README.md).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

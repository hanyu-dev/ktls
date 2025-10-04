# ktls

[![Test pipeline](https://github.com/hanyu-dev/ktls/actions/workflows/ci.yml/badge.svg)](https://github.com/hanyu-dev/ktls/actions/workflows/ci.yml?query=branch%3Amain)
[![Test pipeline](https://github.com/hanyu-dev/ktls/actions/workflows/kernel-compatibility-test.yml/badge.svg)](https://github.com/hanyu-dev/ktls/actions/workflows/kernel-compatibility-test.yml?query=branch%3Amain)
[![Code Coverage](https://codecov.io/github/hanyu-dev/ktls/graph/badge.svg?token=vwYtOhk2cV)](https://codecov.io/github/hanyu-dev/ktls)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

Abstraction for implementing Linux kernel TLS (kTLS) offload in Rust.

## Overview

- [`ktls-core`](./crates/ktls-core/README.md)

  [![Crates.io](https://img.shields.io/crates/v/ktls-core)](https://crates.io/crates/ktls-core)
  [![Docs.rs](https://docs.rs/ktls-core/badge.svg)](https://docs.rs/ktls-core)

- [`ktls-stream`](./crates/ktls-stream/README.md)

  [![Crates.io](https://img.shields.io/crates/v/ktls-stream)](https://crates.io/crates/ktls-stream)
  [![Docs.rs](https://docs.rs/ktls-stream/badge.svg)](https://docs.rs/ktls-stream)

- [`ktls-tests`](./crates/ktls-tests/README.md): Testing utilities

  (not published on crates.io).

## Information

This repository does not serve as a drop-in replacement of crate [`ktls`](https://crates.io/crates/ktls) but rather provides a more generic interface for implementing kTLS offload with any TLS library.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

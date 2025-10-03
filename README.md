# ktls

[![Code Coverage](https://codecov.io/github/hanyu-dev/ktls/graph/badge.svg?token=vwYtOhk2cV)](https://codecov.io/github/hanyu-dev/ktls)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

Abstraction for implementing Linux kernel TLS (kTLS) offload in Rust.

## Information

If you are looking for crates providing kTLS support on top of [`rustls`](https://crates.io/crates/rustls), please check out crate [`ktls`](https://crates.io/crates/ktls).

This repository does not serve as a replacement of `ktls` but rather provides a more generic interface for implementing kTLS offload with any TLS library.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

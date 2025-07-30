# Stratum V2 UniFFI

<p>
    <center><a href="https://github.com/stratum-mining/sv2-uniffi/blob/master/LICENSE"><img alt="MIT or Apache-2.0 Licensed" src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg"/></a></center>
</p>

Language bindings to [Stratum V2 Reference Implementation (SRI)](https://github.com/stratum-mining/stratum) via [UniFFI](https://mozilla.github.io/uniffi-rs/latest/).

The Rust crate on the root of this repository creates the `libsv2` multi-language library. It wraps around a few crates from the SRI ecosystem to expose its APIs in a uniform way using the UniFFI bindings generator for each supported target language.

Each supported language has its own directory.

## Supported target languages

For now, only Python is supported.

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features with Rust 1.82.0.

## Roadmap

- [x] Sv2 Codec with Noise Encryption
- [x] Interfaces for all Sv2 messages
- [ ] Interfaces for Sv2 Channels (Extended, Standard and Group)
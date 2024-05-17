# 0.10.0-beta

Re-implement the crate level API using the new `primitives` module.

# 0.10.0-alpha

This release introduces a new `primitives` module that is basically a new implementation of the
whole crate. We also add a `segwit` module but we have not yet settled on the exact new API in
`lib.rs`, hence the `alpha` release.

# 0.9.1

<!-- Woops, added to the API in a point release -->
- [Support bech32 encoding without a checksum](https://github.com/rust-bitcoin/rust-bech32/pull/66)

# 0.9.0

- [Enable edition 2018](https://github.com/rust-bitcoin/rust-bech32/pull/57) bumping MSRV to 1.41.1
- [Implement `From<u5> for u8`](https://github.com/rust-bitcoin/rust-bech32/pull/58)

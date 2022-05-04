# Changelog

## [Unreleased]
- Add `display` parameter to `root_fingerprint()`.

## 6.0.0
- Offset the recoverable ID by 27 in the signature returned by `eth_sign_msg()`.
- Rename `BTCOutputExternal.hash` to `BTCOutputExternal.payload`.
- Support P2TR (taproot) receive addresses and transaction inputs
- `eth_pub()`, `eth_sign()` and `eth_sign_msg()` now take the network chain ID instead of a ETHCoin enum value for network identification

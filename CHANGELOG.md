# Changelog

The changelog records significant changes to both the firmware and the
bootloader. Since the bootloader has a separate release cycle and existing
customers cannot upgrade their bootloader, its changes are recorded separately.

## Firmware

### [Unreleased]
- Add ability to display the root fingerprint on the device

### 9.10.0 [2022-03-10]
- Bitcoin: add support for BIP-86: receive to taproot addresses and sign transactions with taproot inputs
- Ethereum: add support for the Binance Smart Chain, Optimism, Polygon, Fantom Opera and Arbitrum One networks

### 9.9.1 [2022-02-07]
- Cardano: support sending to legacy Byron addresses
- Cardano: disallow duplicate token keys in an output

### 9.9.0 [released 2022-01-10]
- Support sending to taproot addresses
- ListBackups: ported to Rust
- Confirm restore from microSD before setting a device password
- Cardano: allow transactions with a zero TTL value
- Cardano: add support for sending tokens
- Protobuf: rename BTCSignOutputRequest.hash to BTCSignOutputRequest.payload
- Ethereum: add 807 ERC-20 tokens
- Ethereum: increase size limit for transaction data to accommodate Opensea transactions

### 9.8.0 [released 2021-10-21]
- Multi edition: add Cardano support.
- Allow recovery words that convert to a zero seed, such as the 12 words `abandon abandon .... about`.
- RestoreBackup: ported to Rust. Will now return UserAbortError on user abort instead of GenericError.
- Show "Transaction confirmed"/"Transaction canceled" messages when signing Ethereum transactions

### 9.7.0 [released 2021-09-06]
- Allow mainnet keypaths (`m/44'/60'/0'/0/*`) Rinkeby and Ropsten, and testnet keypaths (`m/44'/1'/0'/0/*`) for Ethereum mainnet
- Display granular error codes when unlock fails unexpectedly
- Remove RandomNumber API endpoint

### 9.6.0 [released 2021-05-20]
- Attempt to fix flaky SD behavior
- Add securechip_model to DeviceInfo: ATECCC608A or ATECC608B.
- Added reboot purpose for clearer UX: "Proceed to upgrade?" vs. "Go to startup settings?"
- Allow creation of 128 bit seeds (12 BIP39 recovery words)
- Increase maximum number of registered multisig accounts from 10 to 25.

### 9.5.0 [released 2021-03-10]
- RestoreFromMnemonic: ported to Rust. Will now return UserAbortError on user abort instead of GenericError.
- Anti-klepto support for ETH transaction signing and for BTC and ETH message signing.
- Add Uniswap ERC-20 token.
- Display warning before confirming raw ETH data.

### 9.4.0 [released 2021-01-20]
- ETHPubRequest api call now fails if a an invalid contract address is provided also if `display` is
  false.
- Fix a memory leak (freeing a malloc'd string - no a functional or security issue)
- Title fixed when entering the 21st, 22nd and 23rd recovery word (was 21th, 22th, 23th) before.
- Verifiable seed generation: when restoring from 24 recovery words, for the 24th word, show all 8 candidate words which result in a valid checksum.
- Better error reporting on secure chip setup failures.
- Fix a rare touch issue resulting from failed calibration.
- Protection against the nonce covert channel attack when singing Bitcoin/Litecoin transactions (antiklepto protocol).

### 9.3.1 [tagged 2020-12-01]
- Fix a bug where the device could freeze and become unresponsive.

### 9.3.0 [tagged 2020-11-23]
- Enter multisig account name on the device if the name in BTCRegisterScriptConfigRequest is empty.
- Allow new keypaths: m/48'/coin'/account' for multisig, to enable compatibility with the Nunchuk wallet.
- Multisig script type and derivation keypath are now also verified during account regisration.

## Bootloader

### v1.0.4
- Make bootloader mode more user-friendly and prompt for action on empty firmware

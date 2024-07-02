# Changelog

The changelog records significant changes to both the firmware and the
bootloader. Since the bootloader has a separate release cycle and existing
customers cannot upgrade their bootloader, its changes are recorded separately.

## Firmware

### [Unreleased]

### 9.19.0
- Display device name on screen before unlock
- Bitcoin: add support for payment requests
- Bitcoin: allow multisig accounts at arbitrary keypaths
- Bitcoin: allow spendung UTXOs at very high BIP-44 address indices
- Ethereum: allow signing EIP-712 messages containing multi-line strings
- Allow exiting the screen asking to insert the microSD card
- HWW: add initialized status byte to _api_info response

### 9.18.0
- Add support for deriving BIP-39 mnemonics according to BIP-85

### 9.17.1
- Intermediate release to rotate the root pubkeys in the bootloader

### 9.17.0
- Add support for deriving mnemonics for Lightning hot wallets according to BIP-85 (using a custom
  BIP-85 application number)

### 9.16.0
- Disable screensaver when displaying a receive address, confirming a transaction, and other interactive actions
- Add Sepolia testnet for Ethereum
- Added a disclaimer screen before the recovery words are displayed
- Verifiable seed generation: when restoring from 12 or 18 recovery words, for the final word, restrict input to the valid candidate words which result in a valid checksum.
  For 24 words, this feature was already introduced in 9.4.0.
- Bitcoin: don't warn about "unusual" sequence numbers in transactions anymore
- Add EIP-1559 transaction support for Ethereum

### 9.15.0
- Security bugfix: check index of an input's previous output to prevent the fee attack originally
  reported by Saleem Rashid
- Allow exporting the xpub at any keypath after user confirmation
- Support for Miniscript wallet policies of the form `wsh(<miniscript expression>)`
- Updated BTC/LTC amount formatting to display the trailing zeroes
- Bitcoin: allow marking non-change transaction outputs as internal
- Allow ETH transactions with empty data + zero value

### 9.14.1
- Improved security: keep seed encrypted in RAM

### 9.14.0
- Improved touch button positional accuracy in noisy environments
- Increased performance when signing Bitcoin transactions
- Warn if the transaction fee is higher than 10% of the coins sent
- ETH Testnets: add Goerli and remove deprecated Rinkeby and Ropsten

### 9.13.1
- Fix bug introduced in 9.13.0: remove double cancel confirmation in the 'Restore from recovery words' workflow

### 9.13.0
- Bitcoin: allow displaying BTC values in the 'sat' unit
- Allow skipping the microSD card backup in favor of backing up using the recovery words
- Allow arbitrary input sequence numbers (fixes compatibility with Taproot transactions in Sparrow wallet)
- The BackupData.length field is now obsolete and always set to 0
- Port remaining protobuf code to Rust, remove the C nanopb protobuf dependency.
- Ethereum: replace ERC20 token names with their unit codes in the receive screen
- SetPassword now returns the UserAbort error instead of the Generic error if the user cancelled

### 9.12.0
- Ethereum: add support for EIP-712 structured data signing
- UI: add a 1px padding for left/right-aligned text for better visibility

### 9.11.0
- Add SSD1312 driver for new OLED screens

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

### v1.0.6
- Replace root pubkeys

### v1.0.5
- Add SSD1312 driver for new OLED screens

### v1.0.4
- Make bootloader mode more user-friendly and prompt for action on empty firmware

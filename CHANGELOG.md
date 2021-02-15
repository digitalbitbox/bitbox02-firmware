# Changelog

## [Unreleased]
- RestoreFrommnemonic: ported to Rust. Will now return UserAbortError on user abort instead of GenericError.
- Added [rlp] as an optional dependency of the bitbox02 Python package using an environment marker
  `ethereum`; see PEP-508 for environment markers

[rlp]: https://pypi.org/project/rlp/

## 9.4.0 [released 2021-01-20]
- ETHPubRequest api call now fails if a an invalid contract address is provided also if `display` is
  false.
- Fix a memory leak (freeing a malloc'd string - no a functional or security issue)
- Title fixed when entering the 21st, 22nd and 23rd recovery word (was 21th, 22th, 23th) before.
- Verifiable seed generation: when restoring from 24 recovery words, for the 24th word, show all 8 candidate words which result in a valid checksum.
- Better error reporting on secure chip setup failures.
- Fix a rare touch issue resulting from failed calibration.
- Protection against the nonce covert channel attack when singing Bitcoin/Litecoin transactions (antiklepto protocol).

## 9.3.1 [tagged 2020-12-01]
- Fix a bug where the device could freeze and become unresponsive.

## 9.3.0 [tagged 2020-11-23]
- Enter multisig account name on the device if the name in BTCRegisterScriptConfigRequest is empty.
- Allow new keypaths: m/48'/coin'/account' for multisig, to enable compatibility with the Nunchuk wallet.
- Multisig script type and derivation keypath are now also verified during account regisration.

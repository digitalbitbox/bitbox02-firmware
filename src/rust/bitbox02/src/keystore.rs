// Copyright 2020 Shift Cryptosecurity AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate alloc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use core::convert::TryInto;

use crate::input::SafeInputString;
use bitbox02_sys::keystore_error_t;

pub const BIP39_WORDLIST_LEN: u16 = bitbox02_sys::BIP39_WORDLIST_LEN as u16;
pub const EC_PUBLIC_KEY_UNCOMPRESSED_LEN: usize = bitbox02_sys::EC_PUBLIC_KEY_UNCOMPRESSED_LEN as _;
pub const EC_PUBLIC_KEY_LEN: usize = bitbox02_sys::EC_PUBLIC_KEY_LEN as _;
pub const MAX_SEED_LENGTH: usize = bitbox02_sys::KEYSTORE_MAX_SEED_LENGTH as usize;

pub fn is_locked() -> bool {
    unsafe { bitbox02_sys::keystore_is_locked() }
}

#[derive(Debug)]
pub enum Error {
    CannotUnlockBIP39,
    IncorrectPassword { remaining_attempts: u8 },
    MaxAttemptsExceeded,
    Unseeded,
    Memory,
    // Securechip error with the error code from securechip.c. 0 if the error is unspecified.
    SecureChip(i32),
    Salt,
    Hash,
    SeedSize,
    Encrypt,
}

impl core::convert::From<keystore_error_t> for Error {
    fn from(error: keystore_error_t) -> Self {
        match error {
            keystore_error_t::KEYSTORE_ERR_MAX_ATTEMPTS_EXCEEDED => Error::MaxAttemptsExceeded,
            keystore_error_t::KEYSTORE_ERR_UNSEEDED => Error::Unseeded,
            keystore_error_t::KEYSTORE_ERR_MEMORY => Error::Memory,
            keystore_error_t::KEYSTORE_ERR_SEED_SIZE => Error::SeedSize,
            keystore_error_t::KEYSTORE_ERR_SECURECHIP => Error::SecureChip(0),
            keystore_error_t::KEYSTORE_ERR_SALT => Error::Salt,
            keystore_error_t::KEYSTORE_ERR_HASH => Error::Hash,
            keystore_error_t::KEYSTORE_ERR_ENCRYPT => Error::Encrypt,
            _ => panic!("cannot convert error"),
        }
    }
}

pub fn unlock(password: &SafeInputString) -> Result<(), Error> {
    let mut remaining_attempts: u8 = 0;
    let mut securechip_result: i32 = 0;
    match unsafe {
        bitbox02_sys::keystore_unlock(
            password.as_cstr(),
            &mut remaining_attempts,
            &mut securechip_result,
        )
    } {
        keystore_error_t::KEYSTORE_OK => Ok(()),
        keystore_error_t::KEYSTORE_ERR_INCORRECT_PASSWORD => {
            Err(Error::IncorrectPassword { remaining_attempts })
        }
        keystore_error_t::KEYSTORE_ERR_SECURECHIP => Err(Error::SecureChip(securechip_result)),
        err => Err(err.into()),
    }
}

pub fn lock() {
    unsafe { bitbox02_sys::keystore_lock() }
}

pub fn unlock_bip39(mnemonic_passphrase: &SafeInputString) -> Result<(), Error> {
    if unsafe { bitbox02_sys::keystore_unlock_bip39(mnemonic_passphrase.as_cstr()) } {
        Ok(())
    } else {
        Err(Error::CannotUnlockBIP39)
    }
}

pub fn create_and_store_seed(password: &SafeInputString, host_entropy: &[u8]) -> Result<(), Error> {
    match unsafe {
        bitbox02_sys::keystore_create_and_store_seed(
            password.as_cstr(),
            host_entropy.as_ptr(),
            host_entropy.len() as _,
        )
    } {
        keystore_error_t::KEYSTORE_OK => Ok(()),
        err => Err(err.into()),
    }
}

pub fn copy_seed() -> Result<zeroize::Zeroizing<Vec<u8>>, ()> {
    let mut seed = zeroize::Zeroizing::new([0u8; MAX_SEED_LENGTH].to_vec());
    let mut seed_len: usize = 0;
    match unsafe { bitbox02_sys::keystore_copy_seed(seed.as_mut_ptr(), &mut seed_len) } {
        true => {
            seed.truncate(seed_len);
            Ok(seed)
        }
        false => Err(()),
    }
}

pub fn get_bip39_mnemonic() -> Result<zeroize::Zeroizing<String>, ()> {
    let mut mnemonic = zeroize::Zeroizing::new([0u8; 256]);
    match unsafe {
        bitbox02_sys::keystore_get_bip39_mnemonic(mnemonic.as_mut_ptr(), mnemonic.len() as _)
    } {
        false => Err(()),
        true => Ok(zeroize::Zeroizing::new(
            crate::util::str_from_null_terminated(&mnemonic[..])
                .unwrap()
                .into(),
        )),
    }
}

/// `idx` must be smaller than BIP39_WORDLIST_LEN.
pub fn get_bip39_word(idx: u16) -> Result<zeroize::Zeroizing<String>, ()> {
    let mut word_ptr: *mut u8 = core::ptr::null_mut();
    match unsafe { bitbox02_sys::keystore_get_bip39_word(idx, &mut word_ptr) } {
        false => Err(()),
        true => {
            let word = zeroize::Zeroizing::new(unsafe {
                crate::util::str_from_null_terminated_ptr(word_ptr)
                    .unwrap()
                    .into()
            });
            unsafe {
                bitbox02_sys::wally_free_string(word_ptr as _);
            }
            Ok(word)
        }
    }
}

/// An opaque C type which gives access to all BIP39 words.
pub struct Bip39Wordlist(Vec<*const u8>);

impl Bip39Wordlist {
    pub fn as_ptr(&self) -> *const *const u8 {
        self.0.as_ptr()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Drop for Bip39Wordlist {
    fn drop(&mut self) {
        for ptr in self.0.iter() {
            unsafe {
                bitbox02_sys::wally_free_string(*ptr as _);
            }
        }
    }
}

/// If indices is None, all BIP39 English words are returned, otherwise only the words of the given
/// indices in the BIP39 English wordlist.
pub fn get_bip39_wordlist(indices: Option<&[u16]>) -> Bip39Wordlist {
    let indices = match indices {
        Some(indices) => indices.to_vec(),
        None => (0..BIP39_WORDLIST_LEN).collect(),
    };
    Bip39Wordlist(
        indices
            .into_iter()
            .map(|i| {
                let mut word_ptr: *mut u8 = core::ptr::null_mut();
                match unsafe { bitbox02_sys::keystore_get_bip39_word(i, &mut word_ptr) } {
                    false => panic!("get_bip39_wordlist"),
                    true => word_ptr as _,
                }
            })
            .collect(),
    )
}

pub fn secp256k1_pubkey_compressed_to_uncompressed(
    compressed_pubkey: &[u8],
) -> Result<[u8; EC_PUBLIC_KEY_UNCOMPRESSED_LEN], ()> {
    let mut pubkey = [0u8; EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    match unsafe {
        bitbox02_sys::keystore_secp256k1_compressed_to_uncompressed(
            compressed_pubkey.as_ptr(),
            pubkey.as_mut_ptr(),
        )
    } {
        true => Ok(pubkey),
        false => Err(()),
    }
}

pub fn encode_xpub_at_keypath(keypath: &[u32]) -> Result<Vec<u8>, ()> {
    let mut xpub = vec![0u8; bitbox02_sys::BIP32_SERIALIZED_LEN as _];
    match unsafe {
        bitbox02_sys::keystore_encode_xpub_at_keypath(
            keypath.as_ptr(),
            keypath.len() as _,
            xpub.as_mut_ptr(),
        )
    } {
        true => Ok(xpub),
        false => Err(()),
    }
}

pub fn secp256k1_get_private_key(
    keypath: &[u32],
    tweak_bip86: bool,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ()> {
    let mut key = zeroize::Zeroizing::new(vec![0u8; 32]);
    match unsafe {
        bitbox02_sys::keystore_secp256k1_get_private_key(
            keypath.as_ptr(),
            keypath.len() as _,
            tweak_bip86,
            key.as_mut_ptr(),
        )
    } {
        true => Ok(key),
        false => Err(()),
    }
}

pub struct SignResult {
    pub signature: [u8; 64],
    pub recid: u8,
}

pub fn secp256k1_sign(
    keypath: &[u32],
    msg: &[u8; 32],
    host_nonce: &[u8; 32],
) -> Result<SignResult, ()> {
    let mut signature = [0u8; 64];
    let mut recid: util::c_types::c_int = 0;
    match unsafe {
        bitbox02_sys::keystore_secp256k1_sign(
            keypath.as_ptr(),
            keypath.len() as _,
            msg.as_ptr(),
            host_nonce.as_ptr(),
            signature.as_mut_ptr(),
            &mut recid,
        )
    } {
        true => Ok(SignResult {
            signature,
            recid: recid.try_into().unwrap(),
        }),
        false => Err(()),
    }
}

pub fn secp256k1_nonce_commit(
    keypath: &[u32],
    msg: &[u8; 32],
    host_commitment: &[u8; 32],
) -> Result<[u8; EC_PUBLIC_KEY_LEN], ()> {
    let mut signer_commitment = [0u8; EC_PUBLIC_KEY_LEN];
    match unsafe {
        bitbox02_sys::keystore_secp256k1_nonce_commit(
            keypath.as_ptr(),
            keypath.len() as _,
            msg.as_ptr(),
            host_commitment.as_ptr(),
            signer_commitment.as_mut_ptr(),
        )
    } {
        true => Ok(signer_commitment),
        false => Err(()),
    }
}

pub fn bip39_mnemonic_to_seed(mnemonic: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, ()> {
    let mnemonic = zeroize::Zeroizing::new(crate::util::str_to_cstr_vec(mnemonic)?);
    let mut seed = zeroize::Zeroizing::new([0u8; MAX_SEED_LENGTH]);
    let mut seed_len: usize = 0;
    match unsafe {
        bitbox02_sys::keystore_bip39_mnemonic_to_seed(
            mnemonic.as_ptr(),
            seed.as_mut_ptr(),
            &mut seed_len,
        )
    } {
        true => Ok(zeroize::Zeroizing::new(seed[..seed_len].to_vec())),
        false => Err(()),
    }
}

pub fn encrypt_and_store_seed(seed: &[u8], password: &SafeInputString) -> Result<(), Error> {
    match unsafe {
        bitbox02_sys::keystore_encrypt_and_store_seed(seed.as_ptr(), seed.len(), password.as_cstr())
    } {
        keystore_error_t::KEYSTORE_OK => Ok(()),
        err => Err(err.into()),
    }
}

pub fn get_ed25519_seed() -> Result<zeroize::Zeroizing<Vec<u8>>, ()> {
    let mut seed = zeroize::Zeroizing::new([0u8; 96].to_vec());
    match unsafe { bitbox02_sys::keystore_get_ed25519_seed(seed.as_mut_ptr()) } {
        true => Ok(seed),
        false => Err(()),
    }
}

pub fn bip85_bip39(words: u32, index: u32) -> Result<zeroize::Zeroizing<String>, ()> {
    let mut mnemonic = zeroize::Zeroizing::new([0u8; 256]);
    match unsafe {
        bitbox02_sys::keystore_bip85_bip39(words, index, mnemonic.as_mut_ptr(), mnemonic.len() as _)
    } {
        false => Err(()),
        true => Ok(zeroize::Zeroizing::new(
            crate::util::str_from_null_terminated(&mnemonic[..])
                .unwrap()
                .into(),
        )),
    }
}

pub fn bip85_ln(index: u32) -> Result<Vec<u8>, ()> {
    let mut entropy = vec![0u8; 16];
    match unsafe { bitbox02_sys::keystore_bip85_ln(index, entropy.as_mut_ptr()) } {
        false => Err(()),
        true => Ok(entropy),
    }
}

pub fn secp256k1_schnorr_bip86_sign(keypath: &[u32], msg: &[u8; 32]) -> Result<[u8; 64], ()> {
    let mut signature = [0u8; 64];
    match unsafe {
        bitbox02_sys::keystore_secp256k1_schnorr_bip86_sign(
            keypath.as_ptr(),
            keypath.len() as _,
            msg.as_ptr(),
            signature.as_mut_ptr(),
        )
    } {
        true => Ok(signature),
        false => Err(()),
    }
}

pub fn secp256k1_schnorr_bip86_pubkey(pubkey33: &[u8]) -> Result<[u8; 32], ()> {
    let mut pubkey = [0u8; 32];
    match unsafe {
        bitbox02_sys::keystore_secp256k1_schnorr_bip86_pubkey(
            pubkey33.as_ptr(),
            pubkey.as_mut_ptr(),
        )
    } {
        true => Ok(pubkey),
        false => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{mock_unlocked, mock_unlocked_using_mnemonic, TEST_MNEMONIC};
    use util::bip32::HARDENED;

    #[test]
    fn test_bip39_mnemonic_to_seed() {
        assert!(bip39_mnemonic_to_seed("invalid").is_err());

        // Zero seed
        assert_eq!(
            bip39_mnemonic_to_seed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap().as_ref() as &[u8],
            &[0u8; 16],
        );

        // 12 words
        assert_eq!(
            bip39_mnemonic_to_seed(
                "trust cradle viable innocent stand equal little small junior frost laundry room"
            )
            .unwrap()
            .as_ref() as &[u8],
            b"\xe9\xa6\x3f\xcd\x3a\x4d\x48\x98\x20\xa6\x63\x79\x2b\xad\xf6\xdd",
        );

        // 18 words
        assert_eq!(
            bip39_mnemonic_to_seed("pupil parent toe bright slam plastic spy suspect verb battle nominee loan call crystal upset razor luggage join").unwrap().as_ref() as &[u8],
            b"\xad\xf4\x07\x8e\x0e\x0c\xb1\x4c\x34\xd6\xd6\xf2\x82\x6a\x57\xc1\x82\x06\x6a\xbb\xcd\x95\x84\xcf",
        );

        // 24 words
        assert_eq!(
            bip39_mnemonic_to_seed("purity concert above invest pigeon category peace tuition hazard vivid latin since legal speak nation session onion library travel spell region blast estate stay").unwrap().as_ref() as &[u8],
            b"\xae\x45\xd4\x02\x3a\xfa\x4a\x48\x68\x77\x51\x69\xfe\xa5\xf5\xe4\x97\xf7\xa1\xa4\xd6\x22\x9a\xd0\x23\x9e\x68\x9b\x48\x2e\xd3\x5e",
        );
    }

    #[test]
    fn test_copy_seed() {
        // 12 words
        mock_unlocked_using_mnemonic(
            "trust cradle viable innocent stand equal little small junior frost laundry room",
            "",
        );
        assert_eq!(
            copy_seed().unwrap().as_slice(),
            b"\xe9\xa6\x3f\xcd\x3a\x4d\x48\x98\x20\xa6\x63\x79\x2b\xad\xf6\xdd",
        );

        // 18 words
        mock_unlocked_using_mnemonic(
            "pupil parent toe bright slam plastic spy suspect verb battle nominee loan call crystal upset razor luggage join",
            "",
        );
        assert_eq!(
            copy_seed().unwrap().as_slice(),
            b"\xad\xf4\x07\x8e\x0e\x0c\xb1\x4c\x34\xd6\xd6\xf2\x82\x6a\x57\xc1\x82\x06\x6a\xbb\xcd\x95\x84\xcf",
        );

        mock_unlocked_using_mnemonic(
            "purity concert above invest pigeon category peace tuition hazard vivid latin since legal speak nation session onion library travel spell region blast estate stay",
            "",
        );
        assert_eq!(
            copy_seed().unwrap().as_slice(),
            b"\xae\x45\xd4\x02\x3a\xfa\x4a\x48\x68\x77\x51\x69\xfe\xa5\xf5\xe4\x97\xf7\xa1\xa4\xd6\x22\x9a\xd0\x23\x9e\x68\x9b\x48\x2e\xd3\x5e",
        );
    }

    #[test]
    fn test_get_bip39_mnemonic() {
        lock();
        assert!(get_bip39_mnemonic().is_err());

        mock_unlocked();

        assert_eq!(
            get_bip39_mnemonic().unwrap().as_ref() as &str,
            TEST_MNEMONIC
        );
    }

    #[test]
    fn test_get_bip39_word() {
        assert!(get_bip39_word(2048).is_err());

        assert_eq!(get_bip39_word(0).unwrap().as_ref() as &str, "abandon");
        assert_eq!(get_bip39_word(2047).unwrap().as_ref() as &str, "zoo");
        assert_eq!(get_bip39_word(563).unwrap().as_ref() as &str, "edit");
    }

    #[test]
    fn test_get_ed25519_seed() {
        // No seed on a locked keystore.
        lock();
        assert!(get_ed25519_seed().is_err());

        mock_unlocked();
        assert_eq!(
            get_ed25519_seed().unwrap().as_ref() as &[u8],
            b"\xf8\xcb\x28\x85\x37\x60\x2b\x90\xd1\x29\x75\x4b\xdd\x0e\x4b\xed\xf9\xe2\x92\x3a\x04\xb6\x86\x7e\xdb\xeb\xc7\x93\xa7\x17\x6f\x5d\xca\xc5\xc9\x5d\x5f\xd2\x3a\x8e\x01\x6c\x95\x57\x69\x0e\xad\x1f\x00\x2b\x0f\x35\xd7\x06\xff\x8e\x59\x84\x1c\x09\xe0\xb6\xbb\x23\xf0\xa5\x91\x06\x42\xd0\x77\x98\x17\x40\x2e\x5e\x7a\x75\x54\x95\xe7\x44\xf5\x5c\xf1\x1e\x49\xee\xfd\x22\xa4\x60\xe9\xb2\xf7\x53",
        );
    }

    #[test]
    fn test_bip85_bip39() {
        lock();
        assert!(bip85_bip39(12, 0).is_err());

        // Test fixtures generated using:
        // `docker build -t bip85 .`
        // `podman run --rm bip85 --index 0 --bip39-mnemonic "virtual weapon code laptop defy cricket vicious target wave leopard garden give" bip39 --num-words 12`
        // `podman run --rm bip85 --index 1 --bip39-mnemonic "virtual weapon code laptop defy cricket vicious target wave leopard garden give" bip39 --num-words 12`
        // `podman run --rm bip85 --index 2147483647 --bip39-mnemonic "virtual weapon code laptop defy cricket vicious target wave leopard garden give" bip39 --num-words 12`
        // `podman run --rm bip85 --index 0 --bip39-mnemonic "virtual weapon code laptop defy cricket vicious target wave leopard garden give" bip39 --num-words 18`
        // `podman run --rm bip85 --index 0 --bip39-mnemonic "virtual weapon code laptop defy cricket vicious target wave leopard garden give" bip39 --num-words 24`
        // in  https://github.com/ethankosakovsky/bip85/tree/435a0589746c1036735d0a5081167e08abfa7413.

        mock_unlocked_using_mnemonic(
            "virtual weapon code laptop defy cricket vicious target wave leopard garden give",
            "",
        );

        assert_eq!(
            bip85_bip39(12, 0).unwrap().as_ref() as &str,
            "slender whip place siren tissue chaos ankle door only assume tent shallow",
        );
        assert_eq!(
            bip85_bip39(12, 1).unwrap().as_ref() as &str,
            "income soft level reunion height pony crane use unfold win keen satisfy",
        );
        assert_eq!(
            bip85_bip39(12, HARDENED - 1).unwrap().as_ref() as &str,
            "carry build nerve market domain energy mistake script puzzle replace mixture idea",
        );
        assert_eq!(
            bip85_bip39(18, 0).unwrap().as_ref() as &str,
            "enact peasant tragic habit expand jar senior melody coin acid logic upper soccer later earn napkin planet stereo",
        );
        assert_eq!(
            bip85_bip39(24, 0).unwrap().as_ref() as &str,
            "cabbage wink october add anchor mean tray surprise gasp tomorrow garbage habit beyond merge where arrive beef gentle animal office drop panel chest size",
        );

        // Invalid number of words.
        assert!(bip85_bip39(10, 0).is_err());
        // Index too high.
        assert!(bip85_bip39(12, HARDENED).is_err());
    }

    #[test]
    fn test_bip85_ln() {
        lock();
        assert!(bip85_ln(0).is_err());

        mock_unlocked_using_mnemonic(
            "virtual weapon code laptop defy cricket vicious target wave leopard garden give",
            "",
        );

        assert_eq!(
            bip85_ln(0).unwrap().as_slice(),
            b"\x3a\x5f\x3b\x88\x8a\xab\x88\xe2\xa9\xab\x99\x1b\x60\xa0\x3e\xd8",
        );
        assert_eq!(
            bip85_ln(1).unwrap().as_slice(),
            b"\xe7\xd9\xce\x75\xf8\xcb\x17\x57\x0e\x66\x54\x17\xb4\x7f\xa0\xbe",
        );
        assert_eq!(
            bip85_ln(HARDENED - 1).unwrap().as_slice(),
            b"\x1f\x3b\x75\xea\x25\x27\x49\x70\x0a\x1e\x45\x34\x69\x14\x8c\xa6",
        );

        // Index too high.
        assert!(bip85_ln(HARDENED).is_err());
    }

    #[test]
    fn test_secp256k1_get_private_key() {
        lock();
        let keypath = &[84 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0];
        assert!(secp256k1_get_private_key(keypath, false).is_err());

        mock_unlocked_using_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        );

        assert_eq!(
            hex::encode(secp256k1_get_private_key(keypath, false).unwrap()),
            "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3"
        );

        // See first test vector in
        // https://github.com/bitcoin/bips/blob/edffe529056f6dfd33d8f716fb871467c3c09263/bip-0086.mediawiki#test-vectors
        // The below privte key's public key is: a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c.
        assert_eq!(
            hex::encode(
                secp256k1_get_private_key(&[86 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0], true)
                    .unwrap()
            ),
            "eaac016f36e8c18347fbacf05ab7966708fbfce7ce3bf1dc32a09dd0645db038",
        );
    }
}

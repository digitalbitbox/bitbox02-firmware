// Copyright 2019 Shift Cryptosecurity AG
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

#ifndef _KEYSTORE_H_
#define _KEYSTORE_H_

#include "compiler_util.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <secp256k1.h>
#include <wally_bip32.h>
#include <wally_bip39.h> // for BIP39_WORDLIST_LEN
#include <wally_crypto.h> // for EC_PUBLIC_KEY_UNCOMPRESSED_LEN and EC_PUBLIC_KEY_LEN

#define KEYSTORE_MAX_SEED_LENGTH (32)
#define KEYSTORE_U2F_SEED_LENGTH SHA256_LEN

// Max. length of an xpub string, including the null terminator.
#define XPUB_ENCODED_LEN 113

typedef enum {
    KEYSTORE_OK,
    KEYSTORE_ERR_INCORRECT_PASSWORD,
    KEYSTORE_ERR_MAX_ATTEMPTS_EXCEEDED,
    KEYSTORE_ERR_UNSEEDED,
    KEYSTORE_ERR_MEMORY,
    KEYSTORE_ERR_SECURECHIP,
    KEYSTORE_ERR_SEED_SIZE,
    KEYSTORE_ERR_SALT,
    KEYSTORE_ERR_HASH,
    KEYSTORE_ERR_ENCRYPT,
    KEYSTORE_ERR_DECRYPT,
} keystore_error_t;

/**
 * Copies the retained seed into the given buffer. The caller must
 * zero the seed with util_zero once it is no longer needed.
 * @param[out] seed_out The seed bytes copied from the retained seed.
 * The buffer should be KEYSTORE_MAX_SEED_LENGTH bytes long.
 * @param[out] length_out The seed length.
 * @return true if the seed was still retained.
 */
USE_RESULT bool keystore_copy_seed(uint8_t* seed_out, size_t* length_out);

/**
 * Restores a seed.
 * @param[in] seed The seed that is to be restored.
 * @param[in] seed_length The length of the seed (max. 32 bytes).
 * @param[in] password The password with which we encrypt the seed.
 */
USE_RESULT keystore_error_t
keystore_encrypt_and_store_seed(const uint8_t* seed, size_t seed_length, const char* password);

/**
   Generates the seed, mixes it with host_entropy, and stores it encrypted with the
   password. The size of the host entropy determines the size of the seed. Can be either 16 or 32
   bytes, resulting in 12 or 24 BIP39 recovery words.
   @param[in] host_entropy bytes of entropy to be mixed in.
   @param[in] host_entropy_size must be 16 or 32.
*/
USE_RESULT keystore_error_t keystore_create_and_store_seed(
    const char* password,
    const uint8_t* host_entropy,
    size_t host_entropy_size);

/** Unlocks the keystore seed or checks the password:
 * If the keystore is locked, it decrypts and loads the seed, unlocking the keystore:
 * 1) loads the stored seed and tries to decrypt using password.
 * 2) if successful, the bip39 seed should be derived using keystore_unlock_bip39().
 * If the keystore is already unlocked, this function does *not* change the state (can be used to
 * check the password).
 * @param[in] password keystore password, used to decrypt the seed.
 * If it is false, the keystore is not unlocked.
 * @param[out] remaining_attempts_out will have the number of remaining attempts.
 * If zero, the keystore is locked until the device is reset.
 * @param[out] securechip_result_out, if not NULL, will contain the error code from
 * `securechip_kdf()` if there was a secure chip error, and 0 otherwise.
 * @return
 * - KEYSTORE_OK if they keystore was successfully unlocked
 * - KEYSTORE_ERR_* if unsuccessful.
 * Only call this if memory_is_seeded() returns true.
 */
USE_RESULT keystore_error_t
keystore_unlock(const char* password, uint8_t* remaining_attempts_out, int* securechip_result_out);

/** Unlocks the bip39 seed.
 * @param[in] mnemonic_passphrase bip39 passphrase used in the derivation. Use the
 * empty string if no passphrase is needed or provided.
 * @return returns false if there was a critital memory error, otherwise true.
 */
USE_RESULT bool keystore_unlock_bip39(const char* mnemonic_passphrase);

/**
 * Locks the keystore (resets to state before `keystore_unlock()`).
 */
void keystore_lock(void);

/**
 * @return false if the keystore is unlocked (keystore_unlock() followed by
 * keystore_unlock_bip39()), true otherwise.
 */
USE_RESULT bool keystore_is_locked(void);

/**
 * @param[out] mnemonic_out resulting mnemonic
 * @param[in] mnemonic_out_size size of mnemonic_out. Should be at least 216 bytes (longest possible
 *            24 word phrase plus null terminator).
 * @return returns false if the keystore is not unlocked or the mnemonic does not fit.
 * The resulting string should be safely zeroed after use.
 */
USE_RESULT bool keystore_get_bip39_mnemonic(char* mnemonic_out, size_t mnemonic_out_size);

/**
 * Turn a bip39 mnemonic into a seed. Make sure to use UTIL_CLEANUP_32 to destroy it.
 * Output can be fed into `keystore_encrypt_and_store_seed` to create a keystore from the mnemonic.
 * @param[in] mnemonic 12/18/24 word bip39 mnemonic
 * @param[out] seed_out must be 32 bytes
 * @param[out] seed_len_out will be the size of the seed
 */
USE_RESULT bool keystore_bip39_mnemonic_to_seed(
    const char* mnemonic,
    uint8_t* seed_out,
    size_t* seed_len_out);

/**
 * Can be used only if the keystore is unlocked. Returns the derived xpub,
 * using bip32 derivation. Derivation is done from the xprv master, so hardened
 * derivation is allowed.
 * On success, xpub_out must be destroyed using keystore_zero_xkey().
 * @return true on success, false on failure.
 */
USE_RESULT bool keystore_get_xpub(
    const uint32_t* keypath,
    size_t keypath_len,
    struct ext_key* hdkey_neutered_out);

/**
 * Safely destroy a xpub or xprv.
 */
void keystore_zero_xkey(struct ext_key* xkey);

/**
 * Returns the pointer to a word in the word list for the given index.
 * @param[in] idx The index into the word list. Must be smaller than BIP39_WORDLIST_LEN.
 * @param[out] word_out The pointer to the character array for the given index.
 */
USE_RESULT bool keystore_get_bip39_word(uint16_t idx, char** word_out);

// Reformats pubkey from compressed 33 bytes to uncompressed 65 bytes (<0x04><64 bytes X><64 bytes
// Y>),
// pubkey must be 33 bytes
// uncompressed_out must be 65 bytes.
USE_RESULT bool keystore_secp256k1_compressed_to_uncompressed(
    const uint8_t* pubkey_bytes,
    uint8_t* uncompressed_out);

/**
 * Get a commitment to the original nonce before tweaking it with the host nonce. This is part of
 * the ECDSA Anti-Klepto Protocol. For more details, check the docs of
 * `secp256k1_ecdsa_anti_exfil_signer_commit`.
 * @param[in] keypath derivation keypath
 * @param[in] keypath_len size of keypath buffer
 * @param[in] msg32 32 byte message which will be signed by `keystore_secp256k1_sign`.
 * @param[in] host_commitment must be `sha256(sha256(tag)||shas256(tag)||host_nonce)` where
 * host_nonce is passed to `keystore_secp256k1_sign()`. See
 * `secp256k1_ecdsa_anti_exfil_host_commit()`.
 * @param[out] client_commitment_out EC_PUBLIC_KEY_LEN bytes compressed signer nonce pubkey.
 */
USE_RESULT bool keystore_secp256k1_nonce_commit(
    const uint32_t* keypath,
    size_t keypath_len,
    const uint8_t* msg32,
    const uint8_t* host_commitment,
    uint8_t* client_commitment_out);

// clang-format off
/**
 * Sign message with private key at the given keypath. Keystore must be unlocked.
 *
 * Details about `host_nonce32`, the host nonce contribution.
 * Instead of using plain rfc6979 to generate the nonce in this signature, the following formula is used:
 *     r = rfc6979(..., additional_data=Hash_d(host_nonce32))
 *     R=r*G (pubkey to secret r)
 *     nonce = r + Hash_p(R, host_nonce32)
 * `Hash_d(msg)` and `Hash_p(msg)` are tagged hashes: `sha256(sha256(tag)||shas256(tag)||msg)`.
 * Tag for `Hash_d`: "s2c/ecdsa/data".
 * Tag for `Hash_p`: "s2c/ecdsa/point".
 * This is part of the ECSDA Anti-Klepto protocol, preventing this function to leak any secrets via
 * the signatures (see the ecdsa-s2c module in secp256k1-zpk for more details).
 *
 * @param[in] keypath derivation keypath
 * @param[in] keypath_len size of keypath buffer
 * @param[in] msg32 32 byte message to sign
 * @param[in] host_nonce32 32 byte nonce contribution. Cannot be NULL.
 * Intended to be a contribution by the host. If there is none available, use 32 zero bytes.
 * @param[out] sig_compact_out resulting signature in compact format. Must be 64 bytes.
 * @param[out] recid recoverable id. Can be NULL if not needed.
 * Parse with secp256k1_ecdsa_signature_serialize_compact().
 * @return true on success, false if the keystore is locked.
 */
// clang-format on
USE_RESULT bool keystore_secp256k1_sign(
    const uint32_t* keypath,
    size_t keypath_len,
    const uint8_t* msg32,
    const uint8_t* host_nonce32,
    uint8_t* sig_compact_out,
    int* recid_out);

/**
 * Get the seed to be used for u2f
 * @param seed_out Buffer for seed, must be KEYSTORE_U2F_SEED_LENGTH
 * @return true if succes
 */
USE_RESULT bool keystore_get_u2f_seed(uint8_t* seed_out);

/**
 * Get the seed to be used for ed25519 applications such as Cardano. The output is the root key to
 * BIP32-ED25519.
 * This implements a derivation compatible with Ledger according to
 * https://github.com/LedgerHQ/orakolo/blob/0b2d5e669ec61df9a824df9fa1a363060116b490/src/python/orakolo/HDEd25519.py.
 * @param seed_out Buffer for the seed. Must be 96 bytes. It will contain a 64 byte expanded
 * ed25519 private key followed by a 32 byte chain code.
 */
USE_RESULT bool keystore_get_ed25519_seed(uint8_t* seed_out);

/**
 * Computes a BIP39 mnemonic according to BIP-85:
 * https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki#bip39
 * @param[in] words must be 12, 18 or 24.
 * @param[in] index must be smaller than `BIP32_INITIAL_HARDENED_CHILD`.
 * @param[out] mnemonic_out resulting mnemonic
 * @param[in] mnemonic_out_size size of mnemonic_out. Should be at least 216 bytes (longest possible
 *            24 word phrase plus null terminator).
 */
USE_RESULT bool keystore_bip85_bip39(
    uint32_t words,
    uint32_t index,
    char* mnemonic_out,
    size_t mnemonic_out_size);

/**
 * Computes a 16 byte deterministic seed specifically for Lightning hot wallets according to BIP-85.
 * It is the same as BIP-85 with app number 39', but instead using app number 19534' (= 0x4c4e =
 * 'LN'). https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki#bip39
 * Restricted to 16 byte output entropy.
 * @param[in] index must be smaller than `BIP32_INITIAL_HARDENED_CHILD`.
 * @param[out] entropy_out resulting entropy, must be at least 16 bytes in size.
 */
USE_RESULT bool keystore_bip85_ln(uint32_t index, uint8_t* entropy_out);

/**
 * Encode an xpub at the given `keypath` as 78 bytes according to BIP32. The version bytes are
 * the ones corresponding to `xpub`, i.e. 0x0488B21E.
 * `out` must be `BIP32_SERIALIZED_LEN` long.
 */
USE_RESULT bool keystore_encode_xpub_at_keypath(
    const uint32_t* keypath,
    size_t keypath_len,
    uint8_t* out);

/**
 * Return the tweaked taproot pubkey.
 *
 * Instead of returning the original pubkey directly, it is tweaked with the hash of the pubkey.
 *
 * See
 * https://github.com/bitcoin/bips/blob/edffe529056f6dfd33d8f716fb871467c3c09263/bip-0086.mediawiki#address-derivation
 *
 * @param[in] pubkey33 33 byte compressed pubkey.
 * @param[out] pubkey_out 32 byte x-only pubkey (see BIP-340 for details).
 */
USE_RESULT bool keystore_secp256k1_schnorr_bip86_pubkey(
    const uint8_t* pubkey33,
    uint8_t* pubkey_out);

/**
 * Sign a message that verifies against the pubkey returned by
 * `keystore_secp256k1_schnorr_bip86_pubkey()`.
 *
 * @param[in] keypath derivation keypath
 * @param[in] keypath_len number of elements in keypath
 * @param[in] msg32 32 byte message to sign
 * @param[out] sig64_out resulting 64 byte signature
 */
USE_RESULT bool keystore_secp256k1_schnorr_bip86_sign(
    const uint32_t* keypath,
    size_t keypath_len,
    const uint8_t* msg32,
    uint8_t* sig64_out);

USE_RESULT bool keystore_secp256k1_get_private_key(
    const uint32_t* keypath,
    size_t keypath_len,
    bool tweak_bip86,
    uint8_t* key_out);

#ifdef TESTING
/**
 * convenience to mock the keystore state (locked, seed) in tests.
 */
void keystore_mock_unlocked(const uint8_t* seed, size_t seed_len, const uint8_t* bip39_seed);

const uint8_t* keystore_test_get_retained_seed_encrypted(size_t* len_out);
const uint8_t* keystore_test_get_retained_bip39_seed_encrypted(size_t* len_out);
#endif

#endif

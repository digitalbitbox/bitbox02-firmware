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

#include <string.h>

#include "cipher/cipher.h"
#include "hardfault.h"
#include "keystore.h"
#include "memory/bitbox02_smarteeprom.h"
#include "memory/memory.h"
#include "random.h"
#include "reset.h"
#include "salt.h"
#include "securechip/securechip.h"
#include "util.h"

#include <rust/rust.h>
#include <secp256k1_ecdsa_s2c.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

// This number of KDF iterations on the 2nd kdf slot when stretching the device
// password.
#define KDF_NUM_ITERATIONS (2)

// Change this ONLY via keystore_unlock() or keystore_lock()
static bool _is_unlocked_device = false;
// Stores a random key after unlock which, after stretching, is used to encrypt the retained seed.
static uint8_t _unstretched_retained_seed_encryption_key[32] = {0};
// Must be defined if is_unlocked is true. ONLY ACCESS THIS WITH keystore_copy_seed().
// Stores the encrypted seed after unlock.
static uint8_t _retained_seed_encrypted[KEYSTORE_MAX_SEED_LENGTH + 64] = {0};
static size_t _retained_seed_encrypted_len = 0;

// Change this ONLY via keystore_unlock_bip39().
static bool _is_unlocked_bip39 = false;
// Stores a random keyy after bip39-unlock which, after stretching, is used to encrypt the retained
// bip39 seed.
static uint8_t _unstretched_retained_bip39_seed_encryption_key[32] = {0};
// Must be defined if _is_unlocked is true. ONLY ACCESS THIS WITH _copy_bip39_seed().
// Stores the encrypted BIP-39 seed after bip39-unlock.
static uint8_t _retained_bip39_seed_encrypted[64 + 64] = {0};
static size_t _retained_bip39_seed_encrypted_len = 0;

/**
 * We allow seeds of 16, 24 or 32 bytes.
 */
static bool _validate_seed_length(size_t seed_len)
{
    return seed_len == 16 || seed_len == 24 || seed_len == 32;
}

USE_RESULT static keystore_error_t _stretch_retained_seed_encryption_key(
    const uint8_t* encryption_key,
    const char* purpose_in,
    const char* purpose_out,
    uint8_t* out)
{
    uint8_t salted_hashed[32] = {0};
    UTIL_CLEANUP_32(salted_hashed);
    if (!salt_hash_data(encryption_key, 32, purpose_in, salted_hashed)) {
        return KEYSTORE_ERR_SALT;
    }
    if (securechip_kdf(SECURECHIP_SLOT_KDF, salted_hashed, 32, out)) {
        return KEYSTORE_ERR_SECURECHIP;
    }
    if (!salt_hash_data(encryption_key, 32, purpose_out, salted_hashed)) {
        return KEYSTORE_ERR_SALT;
    }
    if (wally_hmac_sha256(salted_hashed, sizeof(salted_hashed), out, 32, out, 32) != WALLY_OK) {
        return KEYSTORE_ERR_HASH;
    }
    return KEYSTORE_OK;
}

bool keystore_copy_seed(uint8_t* seed_out, size_t* length_out)
{
    if (!_is_unlocked_device) {
        return false;
    }

    uint8_t retained_seed_encryption_key[32] = {0};
    UTIL_CLEANUP_32(retained_seed_encryption_key);
    if (_stretch_retained_seed_encryption_key(
            _unstretched_retained_seed_encryption_key,
            "keystore_retained_seed_access_in",
            "keystore_retained_seed_access_out",
            retained_seed_encryption_key) != KEYSTORE_OK) {
        return false;
    }
    size_t len = _retained_seed_encrypted_len - 48;
    bool password_correct = cipher_aes_hmac_decrypt(
        _retained_seed_encrypted,
        _retained_seed_encrypted_len,
        seed_out,
        &len,
        retained_seed_encryption_key);
    if (!password_correct) {
        // Should never happen.
        return false;
    }
    *length_out = len;
    return true;
}

/**
 * Copies the retained bip39 seed into the given buffer. The caller must
 * zero the seed with util_zero once it is no longer needed.
 * @param[out] bip39_seed_out The seed bytes copied from the retained bip39 seed.
 * The buffer must be 64 bytes long.
 * @return true if the bip39 seed is available.
 */
static bool _copy_bip39_seed(uint8_t* bip39_seed_out)
{
    if (!_is_unlocked_bip39) {
        return false;
    }

    uint8_t retained_bip39_seed_encryption_key[32] = {0};
    UTIL_CLEANUP_32(retained_bip39_seed_encryption_key);
    if (_stretch_retained_seed_encryption_key(
            _unstretched_retained_bip39_seed_encryption_key,
            "keystore_retained_bip39_seed_access_in",
            "keystore_retained_bip39_seed_access_out",
            retained_bip39_seed_encryption_key) != KEYSTORE_OK) {
        return false;
    }
    size_t len = _retained_bip39_seed_encrypted_len - 48;
    bool password_correct = cipher_aes_hmac_decrypt(
        _retained_bip39_seed_encrypted,
        _retained_bip39_seed_encrypted_len,
        bip39_seed_out,
        &len,
        retained_bip39_seed_encryption_key);
    if (!password_correct) {
        // Should never happen.
        return false;
    }
    if (len != 64) {
        // Should never happen.
        return false;
    }
    // sanity check
    uint8_t zero[64] = {0};
    util_zero(zero, 64);
    if (MEMEQ(bip39_seed_out, zero, 64)) {
        return false;
    }
    return true;
}

/**
 * Stretch the user password using the securechip, putting the result in `kdf_out`, which must be 32
 * bytes. `securechip_result_out`, if not NULL, will contain the error code from `securechip_kdf()`
 * if there was a secure chip error, and 0 otherwise.
 */
static keystore_error_t _stretch_password(
    const char* password,
    uint8_t* kdf_out,
    int* securechip_result_out)
{
    if (securechip_result_out != NULL) {
        *securechip_result_out = 0;
    }
    uint8_t password_salted_hashed[32] = {0};
    UTIL_CLEANUP_32(password_salted_hashed);
    if (!salt_hash_data(
            (const uint8_t*)password,
            strlen(password),
            "keystore_seed_access_in",
            password_salted_hashed)) {
        return KEYSTORE_ERR_SALT;
    }

    uint8_t kdf_in[32] = {0};
    UTIL_CLEANUP_32(kdf_in);
    memcpy(kdf_in, password_salted_hashed, 32);

    // First KDF on SECURECHIP_SLOT_ROLLKEY increments the monotonic
    // counter. Call only once!
    int securechip_result = securechip_kdf(SECURECHIP_SLOT_ROLLKEY, kdf_in, 32, kdf_out);
    if (securechip_result) {
        if (securechip_result_out != NULL) {
            *securechip_result_out = securechip_result;
        }
        return KEYSTORE_ERR_SECURECHIP;
    }
    // Second KDF does not use the counter and we call it multiple times.
    for (int i = 0; i < KDF_NUM_ITERATIONS; i++) {
        memcpy(kdf_in, kdf_out, 32);
        securechip_result = securechip_kdf(SECURECHIP_SLOT_KDF, kdf_in, 32, kdf_out);
        if (securechip_result) {
            if (securechip_result_out != NULL) {
                *securechip_result_out = securechip_result;
            }
            return KEYSTORE_ERR_SECURECHIP;
        }
    }

    if (!salt_hash_data(
            (const uint8_t*)password,
            strlen(password),
            "keystore_seed_access_out",
            password_salted_hashed)) {
        return KEYSTORE_ERR_SALT;
    }
    if (wally_hmac_sha256(
            password_salted_hashed, sizeof(password_salted_hashed), kdf_out, 32, kdf_out, 32) !=
        WALLY_OK) {
        return KEYSTORE_ERR_HASH;
    }

    return KEYSTORE_OK;
}

/**
 * Retrieves the encrypted seed and attempts to decrypt it using the password.
 *
 * `securechip_result_out`, if not NULL, will contain the error code from `securechip_kdf()` if
 * there was a secure chip error, and 0 otherwise.
 */
static keystore_error_t _get_and_decrypt_seed(
    const char* password,
    uint8_t* decrypted_seed_out,
    size_t* decrypted_seed_len_out,
    int* securechip_result_out)
{
    uint8_t encrypted_seed_and_hmac[96];
    UTIL_CLEANUP_32(encrypted_seed_and_hmac);
    uint8_t encrypted_len;
    if (!memory_get_encrypted_seed_and_hmac(encrypted_seed_and_hmac, &encrypted_len)) {
        return KEYSTORE_ERR_MEMORY;
    }
    uint8_t secret[32];
    UTIL_CLEANUP_32(secret);
    keystore_error_t result = _stretch_password(password, secret, securechip_result_out);
    if (result != KEYSTORE_OK) {
        return result;
    }
    if (encrypted_len < 49) {
        Abort("_get_and_decrypt_seed: underflow / zero size");
    }
    size_t decrypted_len = encrypted_len - 48;
    uint8_t decrypted[decrypted_len];
    bool password_correct = cipher_aes_hmac_decrypt(
        encrypted_seed_and_hmac, encrypted_len, decrypted, &decrypted_len, secret);
    if (!password_correct) {
        return KEYSTORE_ERR_INCORRECT_PASSWORD;
    }
    if (!_validate_seed_length(decrypted_len)) {
        util_zero(decrypted, sizeof(decrypted));
        return KEYSTORE_ERR_SEED_SIZE;
    }
    *decrypted_seed_len_out = decrypted_len;
    memcpy(decrypted_seed_out, decrypted, decrypted_len);

    return KEYSTORE_OK;
}

static bool _verify_seed(
    const char* password,
    const uint8_t* expected_seed,
    size_t expected_seed_len)
{
    uint8_t decrypted_seed[KEYSTORE_MAX_SEED_LENGTH] = {0};
    size_t seed_len;
    UTIL_CLEANUP_32(decrypted_seed);
    if (_get_and_decrypt_seed(password, decrypted_seed, &seed_len, NULL) != KEYSTORE_OK) {
        return false;
    }
    if (expected_seed_len != seed_len) {
        return false;
    }
    if (!MEMEQ(expected_seed, decrypted_seed, seed_len)) {
        return false;
    }
    return true;
}

keystore_error_t keystore_encrypt_and_store_seed(
    const uint8_t* seed,
    size_t seed_length,
    const char* password)
{
    if (memory_is_initialized()) {
        return KEYSTORE_ERR_MEMORY;
    }
    keystore_lock();
    if (!_validate_seed_length(seed_length)) {
        return KEYSTORE_ERR_SEED_SIZE;
    }
    // Update the two kdf keys before setting a new password. This already
    // happens on a device reset, but we do it here again anyway so the keys are
    // initialized also on first use, reducing trust in the factory setup.
    if (!securechip_update_keys()) {
        return KEYSTORE_ERR_SECURECHIP;
    }
    uint8_t secret[32] = {0};
    UTIL_CLEANUP_32(secret);
    keystore_error_t res = _stretch_password(password, secret, NULL);
    if (res != KEYSTORE_OK) {
        return res;
    }

    size_t encrypted_seed_len = seed_length + 64;
    uint8_t encrypted_seed[encrypted_seed_len];
    UTIL_CLEANUP_32(encrypted_seed);
    if (!cipher_aes_hmac_encrypt(seed, seed_length, encrypted_seed, &encrypted_seed_len, secret)) {
        return KEYSTORE_ERR_ENCRYPT;
    }
    if (encrypted_seed_len > 255) { // sanity check, can't happen
        Abort("keystore_encrypt_and_store_seed");
    }
    uint8_t encrypted_seed_len_u8 = (uint8_t)encrypted_seed_len;
    if (!memory_set_encrypted_seed_and_hmac(encrypted_seed, encrypted_seed_len_u8)) {
        return KEYSTORE_ERR_MEMORY;
    }
    if (!_verify_seed(password, seed, seed_length)) {
        if (!memory_reset_hww()) {
            return KEYSTORE_ERR_MEMORY;
        }
        return KEYSTORE_ERR_MEMORY;
    }
    return KEYSTORE_OK;
}

keystore_error_t keystore_create_and_store_seed(
    const char* password,
    const uint8_t* host_entropy,
    size_t host_entropy_size)
{
    if (host_entropy_size != 16 && host_entropy_size != 32) {
        return KEYSTORE_ERR_SEED_SIZE;
    }
    if (KEYSTORE_MAX_SEED_LENGTH != RANDOM_NUM_SIZE) {
        Abort("keystore create: size mismatch");
    }
    uint8_t seed[KEYSTORE_MAX_SEED_LENGTH];
    UTIL_CLEANUP_32(seed);
    random_32_bytes(seed);

    // Mix in Host entropy.
    for (size_t i = 0; i < host_entropy_size; i++) {
        seed[i] ^= host_entropy[i];
    }

    // Mix in entropy derived from the user password.
    uint8_t password_salted_hashed[KEYSTORE_MAX_SEED_LENGTH] = {0};
    UTIL_CLEANUP_32(password_salted_hashed);
    if (!salt_hash_data(
            (const uint8_t*)password,
            strlen(password),
            "keystore_seed_generation",
            password_salted_hashed)) {
        return KEYSTORE_ERR_SALT;
    }

    for (size_t i = 0; i < host_entropy_size; i++) {
        seed[i] ^= password_salted_hashed[i];
    }
    return keystore_encrypt_and_store_seed(seed, host_entropy_size, password);
}

static void _free_string(char** str)
{
    wally_free_string(*str);
}

USE_RESULT static keystore_error_t _retain_seed(const uint8_t* seed, size_t seed_len)
{
    random_32_bytes(_unstretched_retained_seed_encryption_key);
    uint8_t retained_seed_encryption_key[32] = {0};
    UTIL_CLEANUP_32(retained_seed_encryption_key);
    keystore_error_t result = _stretch_retained_seed_encryption_key(
        _unstretched_retained_seed_encryption_key,
        "keystore_retained_seed_access_in",
        "keystore_retained_seed_access_out",
        retained_seed_encryption_key);
    if (result != KEYSTORE_OK) {
        return result;
    }
    size_t len = seed_len + 64;
    if (!cipher_aes_hmac_encrypt(
            seed, seed_len, _retained_seed_encrypted, &len, retained_seed_encryption_key)) {
        return KEYSTORE_ERR_ENCRYPT;
    }
    _retained_seed_encrypted_len = len;
    return KEYSTORE_OK;
}

USE_RESULT static bool _retain_bip39_seed(const uint8_t* bip39_seed)
{
    random_32_bytes(_unstretched_retained_bip39_seed_encryption_key);
    uint8_t retained_bip39_seed_encryption_key[32] = {0};
    UTIL_CLEANUP_32(retained_bip39_seed_encryption_key);
    if (_stretch_retained_seed_encryption_key(
            _unstretched_retained_bip39_seed_encryption_key,
            "keystore_retained_bip39_seed_access_in",
            "keystore_retained_bip39_seed_access_out",
            retained_bip39_seed_encryption_key) != KEYSTORE_OK) {
        return false;
    }
    size_t len = sizeof(_retained_bip39_seed_encrypted);
    if (!cipher_aes_hmac_encrypt(
            bip39_seed,
            64,
            _retained_bip39_seed_encrypted,
            &len,
            retained_bip39_seed_encryption_key)) {
        return false;
    }
    _retained_bip39_seed_encrypted_len = len;
    return true;
}

static void _delete_retained_seeds(void)
{
    util_zero(
        _unstretched_retained_seed_encryption_key,
        sizeof(_unstretched_retained_seed_encryption_key));
    util_zero(_retained_seed_encrypted, sizeof(_retained_seed_encrypted));
    _retained_seed_encrypted_len = 0;
    util_zero(
        _unstretched_retained_bip39_seed_encryption_key,
        sizeof(_unstretched_retained_seed_encryption_key));
    util_zero(_retained_bip39_seed_encrypted, sizeof(_retained_bip39_seed_encrypted));
    _retained_bip39_seed_encrypted_len = 0;
}

keystore_error_t keystore_unlock(
    const char* password,
    uint8_t* remaining_attempts_out,
    int* securechip_result_out)
{
    if (!memory_is_seeded()) {
        return KEYSTORE_ERR_UNSEEDED;
    }
    uint8_t failed_attempts = bitbox02_smarteeprom_get_unlock_attempts();
    if (failed_attempts >= MAX_UNLOCK_ATTEMPTS) {
        /*
         * We reset the device as soon as the MAX_UNLOCK_ATTEMPTSth attempt
         * is made. So we should never enter this branch...
         * This is just an extraordinary measure for added resilience.
         */
        *remaining_attempts_out = 0;
        reset_reset(false);
        return KEYSTORE_ERR_MAX_ATTEMPTS_EXCEEDED;
    }
    bitbox02_smarteeprom_increment_unlock_attempts();
    uint8_t seed[KEYSTORE_MAX_SEED_LENGTH] = {0};
    UTIL_CLEANUP_32(seed);
    size_t seed_len;
    keystore_error_t result =
        _get_and_decrypt_seed(password, seed, &seed_len, securechip_result_out);
    if (result != KEYSTORE_OK && result != KEYSTORE_ERR_INCORRECT_PASSWORD) {
        return result;
    }
    if (result == KEYSTORE_OK) {
        if (_is_unlocked_device) {
            // Already unlocked. Fail if the seed changed under our feet (should never happen).
            uint8_t current_seed[KEYSTORE_MAX_SEED_LENGTH] = {0};
            size_t current_seed_len = 0;
            if (!keystore_copy_seed(current_seed, &current_seed_len)) {
                return KEYSTORE_ERR_DECRYPT;
            }
            if (seed_len != current_seed_len || !MEMEQ(current_seed, seed, current_seed_len)) {
                Abort("Seed has suddenly changed. This should never happen.");
            }
        } else {
            keystore_error_t retain_seed_result = _retain_seed(seed, seed_len);
            if (retain_seed_result != KEYSTORE_OK) {
                return retain_seed_result;
            }
            _is_unlocked_device = true;
        }
        bitbox02_smarteeprom_reset_unlock_attempts();
    }
    // Compute remaining attempts
    failed_attempts = bitbox02_smarteeprom_get_unlock_attempts();

    if (failed_attempts >= MAX_UNLOCK_ATTEMPTS) {
        *remaining_attempts_out = 0;
        reset_reset(false);
        return KEYSTORE_ERR_MAX_ATTEMPTS_EXCEEDED;
    }

    *remaining_attempts_out = MAX_UNLOCK_ATTEMPTS - failed_attempts;
    return result;
}

bool keystore_unlock_bip39(const char* mnemonic_passphrase)
{
    if (!_is_unlocked_device) {
        return false;
    }
    char* mnemonic __attribute__((__cleanup__(_free_string))) = NULL;
    { // block so that `seed` is zeroed as soon as possible
        uint8_t seed[KEYSTORE_MAX_SEED_LENGTH] = {0};
        UTIL_CLEANUP_32(seed);
        size_t seed_length = 0;
        if (!keystore_copy_seed(seed, &seed_length)) {
            return false;
        }
        if (bip39_mnemonic_from_bytes(NULL, seed, seed_length, &mnemonic) != WALLY_OK) {
            return false;
        }
    }
    uint8_t bip39_seed[BIP39_SEED_LEN_512] = {0};
    UTIL_CLEANUP_64(bip39_seed);
    if (bip39_mnemonic_to_seed(
            mnemonic, mnemonic_passphrase, bip39_seed, sizeof(bip39_seed), NULL) != WALLY_OK) {
        return false;
    }
    if (!_retain_bip39_seed(bip39_seed)) {
        return false;
    }
    _is_unlocked_bip39 = true;
    return true;
}

void keystore_lock(void)
{
    _is_unlocked_device = false;
    _is_unlocked_bip39 = false;
    _delete_retained_seeds();
}

bool keystore_is_locked(void)
{
    bool unlocked = _is_unlocked_device && _is_unlocked_bip39;
    return !unlocked;
}

bool keystore_get_bip39_mnemonic(char* mnemonic_out, size_t mnemonic_out_size)
{
    if (keystore_is_locked()) {
        return false;
    }
    char* mnemonic = NULL;
    { // block so that `seed` is zeroed as soon as possible
        uint8_t seed[KEYSTORE_MAX_SEED_LENGTH] = {0};
        UTIL_CLEANUP_32(seed);
        size_t seed_length = 0;
        if (!keystore_copy_seed(seed, &seed_length)) {
            return false;
        }
        if (bip39_mnemonic_from_bytes(NULL, seed, seed_length, &mnemonic) != WALLY_OK) {
            return false;
        }
    }
    int snprintf_result = snprintf(mnemonic_out, mnemonic_out_size, "%s", mnemonic);
    util_cleanup_str(&mnemonic);
    free(mnemonic);
    return snprintf_result >= 0 && snprintf_result < (int)mnemonic_out_size;
}

bool keystore_bip39_mnemonic_to_seed(const char* mnemonic, uint8_t* seed_out, size_t* seed_len_out)
{
    return bip39_mnemonic_to_bytes(NULL, mnemonic, seed_out, 32, seed_len_out) == WALLY_OK;
}

static bool _get_xprv(const uint32_t* keypath, const size_t keypath_len, struct ext_key* xprv_out)
{
    if (keystore_is_locked()) {
        return false;
    }

    uint8_t bip39_seed[64] = {0};
    UTIL_CLEANUP_64(bip39_seed);
    if (!_copy_bip39_seed(bip39_seed)) {
        return false;
    }
    struct ext_key xprv_master __attribute__((__cleanup__(keystore_zero_xkey))) = {0};

    if (bip32_key_from_seed(
            bip39_seed, BIP32_ENTROPY_LEN_512, BIP32_VER_MAIN_PRIVATE, 0, &xprv_master) !=
        WALLY_OK) {
        return false;
    }
    util_zero(bip39_seed, sizeof(bip39_seed));
    if (keypath_len == 0) {
        *xprv_out = xprv_master;
    } else if (
        bip32_key_from_parent_path(
            &xprv_master, keypath, keypath_len, BIP32_FLAG_KEY_PRIVATE, xprv_out) != WALLY_OK) {
        keystore_zero_xkey(xprv_out);
        return false;
    }
    return true;
}

static bool _ext_key_equal(struct ext_key* one, struct ext_key* two)
{
    if (!MEMEQ(one->chain_code, two->chain_code, sizeof(one->chain_code))) {
        return false;
    }
    if (!MEMEQ(one->parent160, two->parent160, sizeof(one->parent160))) {
        return false;
    }
    if (one->depth != two->depth) {
        return false;
    }
    if (!MEMEQ(one->priv_key, two->priv_key, sizeof(one->priv_key))) {
        return false;
    }
    if (one->child_num != two->child_num) {
        return false;
    }
    if (!MEMEQ(one->hash160, two->hash160, sizeof(one->hash160))) {
        return false;
    }
    if (one->version != two->version) {
        return false;
    }
    if (!MEMEQ(one->pub_key, two->pub_key, sizeof(one->pub_key))) {
        return false;
    }
    return true;
}

static bool _get_xprv_twice(
    const uint32_t* keypath,
    const size_t keypath_len,
    struct ext_key* xprv_out)
{
    struct ext_key one __attribute__((__cleanup__(keystore_zero_xkey))) = {0};
    if (!_get_xprv(keypath, keypath_len, &one)) {
        return false;
    }
    if (!_get_xprv(keypath, keypath_len, xprv_out)) {
        return false;
    }
    if (!_ext_key_equal(&one, xprv_out)) {
        keystore_zero_xkey(xprv_out);
        return false;
    }
    return true;
}

bool keystore_get_xpub(
    const uint32_t* keypath,
    const size_t keypath_len,
    struct ext_key* hdkey_neutered_out)
{
    struct ext_key xprv __attribute__((__cleanup__(keystore_zero_xkey))) = {0};
    if (!_get_xprv_twice(keypath, keypath_len, &xprv)) {
        return false;
    }
    bip32_key_strip_private_key(&xprv); // neuter
    *hdkey_neutered_out = xprv;
    return true;
}

void keystore_zero_xkey(struct ext_key* xkey)
{
    util_zero(xkey, sizeof(struct ext_key));
}

bool keystore_get_bip39_word(uint16_t idx, char** word_out)
{
    return bip39_get_word(NULL, idx, word_out) == WALLY_OK;
}

bool keystore_secp256k1_compressed_to_uncompressed(
    const uint8_t* pubkey_bytes,
    uint8_t* uncompressed_out)
{
    const secp256k1_context* ctx = wally_get_secp_context();
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkey_bytes, 33)) {
        return false;
    }
    size_t len = 65;
    if (!secp256k1_ec_pubkey_serialize(
            ctx, uncompressed_out, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
        return false;
    }
    return true;
}

bool keystore_secp256k1_nonce_commit(
    const uint32_t* keypath,
    size_t keypath_len,
    const uint8_t* msg32,
    const uint8_t* host_commitment,
    uint8_t* signer_commitment_out)
{
    struct ext_key xprv __attribute__((__cleanup__(keystore_zero_xkey))) = {0};
    if (!_get_xprv(keypath, keypath_len, &xprv)) {
        return false;
    }
    const secp256k1_context* ctx = wally_get_secp_context();
    secp256k1_ecdsa_s2c_opening signer_commitment;
    if (!secp256k1_ecdsa_anti_exfil_signer_commit(
            ctx,
            &signer_commitment,
            msg32,
            xprv.priv_key + 1, // first byte is 0,
            host_commitment)) {
        return false;
    }

    if (!secp256k1_ecdsa_s2c_opening_serialize(ctx, signer_commitment_out, &signer_commitment)) {
        return false;
    }
    return true;
}

bool keystore_secp256k1_sign(
    const uint32_t* keypath,
    size_t keypath_len,
    const uint8_t* msg32,
    const uint8_t* host_nonce32,
    uint8_t* sig_compact_out,
    int* recid_out)
{
    if (keystore_is_locked()) {
        return false;
    }
    struct ext_key xprv __attribute__((__cleanup__(keystore_zero_xkey))) = {0};
    if (!_get_xprv(keypath, keypath_len, &xprv)) {
        return false;
    }
    const secp256k1_context* ctx = wally_get_secp_context();
    secp256k1_ecdsa_signature secp256k1_sig = {0};
    if (!secp256k1_anti_exfil_sign(
            ctx,
            &secp256k1_sig,
            msg32,
            xprv.priv_key + 1, // first byte is 0
            host_nonce32,
            recid_out)) {
        return false;
    }
    if (!secp256k1_ecdsa_signature_serialize_compact(ctx, sig_compact_out, &secp256k1_sig)) {
        return false;
    }
    return true;
}

bool keystore_get_u2f_seed(uint8_t* seed_out)
{
    if (keystore_is_locked()) {
        return false;
    }
    uint8_t bip39_seed[64] = {0};
    UTIL_CLEANUP_64(bip39_seed);
    if (!_copy_bip39_seed(bip39_seed)) {
        return false;
    }
    const uint8_t message[] = "u2f";
    if (wally_hmac_sha256(bip39_seed, 64, message, sizeof(message), seed_out, SHA256_LEN) !=
        WALLY_OK) {
        return false;
    }
    return true;
}

bool keystore_get_ed25519_seed(uint8_t* seed_out)
{
    uint8_t bip39_seed[64] = {0};
    UTIL_CLEANUP_64(bip39_seed);
    if (!_copy_bip39_seed(bip39_seed)) {
        return false;
    }

    const uint8_t key[] = "ed25519 seed";

    // Derive a 64 byte expanded ed25519 private key and put it into seed_out.
    memcpy(seed_out, bip39_seed, 64);
    do {
        if (wally_hmac_sha512(key, sizeof(key), seed_out, 64, seed_out, 64) != WALLY_OK) {
            util_zero(seed_out, 64);
            return false;
        }
    } while (seed_out[31] & 0x20);

    seed_out[0] &= 248;
    seed_out[31] &= 127;
    seed_out[31] |= 64;

    // Compute chain code and put it into seed_out at offset 64.
    uint8_t message[65] = {0};
    message[0] = 0x01;
    memcpy(&message[1], bip39_seed, 64);
    util_zero(bip39_seed, sizeof(bip39_seed));
    if (wally_hmac_sha256(key, sizeof(key), message, sizeof(message), &seed_out[64], 32) !=
        WALLY_OK) {
        util_zero(message, sizeof(message));
        return false;
    }
    util_zero(message, sizeof(message));
    return true;
}

static bool _bip85_entropy(const uint32_t* keypath, size_t keypath_len, uint8_t* out)
{
    struct ext_key xprv __attribute__((__cleanup__(keystore_zero_xkey))) = {0};
    if (!_get_xprv_twice(keypath, keypath_len, &xprv)) {
        return false;
    }
    const uint8_t* priv_key = xprv.priv_key + 1; // first byte is 0
    const uint8_t key[] = "bip-entropy-from-k";
    return wally_hmac_sha512(key, sizeof(key), priv_key, 32, out, 64) == WALLY_OK;
}

bool keystore_bip85_bip39(
    uint32_t words,
    uint32_t index,
    char* mnemonic_out,
    size_t mnemonic_out_size)
{
    size_t seed_size;
    switch (words) {
    case 12:
        seed_size = 16;
        break;
    case 18:
        seed_size = 24;
        break;
    case 24:
        seed_size = 32;
        break;
    default:
        return false;
    }

    if (index >= BIP32_INITIAL_HARDENED_CHILD) {
        return false;
    }

    const uint32_t keypath[] = {
        83696968 + BIP32_INITIAL_HARDENED_CHILD,
        39 + BIP32_INITIAL_HARDENED_CHILD,
        0 + BIP32_INITIAL_HARDENED_CHILD,
        words + BIP32_INITIAL_HARDENED_CHILD,
        index + BIP32_INITIAL_HARDENED_CHILD,
    };

    uint8_t entropy[64] = {0};
    UTIL_CLEANUP_64(entropy);
    if (!_bip85_entropy(keypath, sizeof(keypath) / sizeof(uint32_t), entropy)) {
        return false;
    }

    char* mnemonic = NULL;
    if (bip39_mnemonic_from_bytes(NULL, entropy, seed_size, &mnemonic) != WALLY_OK) {
        return false;
    }
    int snprintf_result = snprintf(mnemonic_out, mnemonic_out_size, "%s", mnemonic);
    util_cleanup_str(&mnemonic);
    free(mnemonic);
    return snprintf_result >= 0 && snprintf_result < (int)mnemonic_out_size;
}

bool keystore_bip85_ln(uint32_t index, uint8_t* entropy_out)
{
    if (index >= BIP32_INITIAL_HARDENED_CHILD) {
        return false;
    }

    const uint32_t keypath[] = {
        83696968 + BIP32_INITIAL_HARDENED_CHILD,
        19534 + BIP32_INITIAL_HARDENED_CHILD,
        0 + BIP32_INITIAL_HARDENED_CHILD,
        12 + BIP32_INITIAL_HARDENED_CHILD,
        index + BIP32_INITIAL_HARDENED_CHILD,
    };

    uint8_t entropy[64] = {0};
    UTIL_CLEANUP_64(entropy);
    if (!_bip85_entropy(keypath, sizeof(keypath) / sizeof(uint32_t), entropy)) {
        return false;
    }

    memcpy(entropy_out, entropy, 16);
    return true;
}

USE_RESULT bool keystore_encode_xpub_at_keypath(
    const uint32_t* keypath,
    size_t keypath_len,
    uint8_t* out)
{
    struct ext_key derived_xpub __attribute__((__cleanup__(keystore_zero_xkey))) = {0};
    if (!keystore_get_xpub(keypath, keypath_len, &derived_xpub)) {
        return false;
    }
    return bip32_key_serialize(&derived_xpub, BIP32_FLAG_KEY_PUBLIC, out, BIP32_SERIALIZED_LEN) ==
           WALLY_OK;
}

static void _tagged_hash(const char* tag, const uint8_t* msg, size_t msg_len, uint8_t* hash_out)
{
    uint8_t tag_hash[32] = {0};
    rust_sha256(tag, strlen(tag), tag_hash);
    void* hash_ctx = rust_sha256_new();
    rust_sha256_update(hash_ctx, tag_hash, sizeof(tag_hash));
    rust_sha256_update(hash_ctx, tag_hash, sizeof(tag_hash));
    rust_sha256_update(hash_ctx, msg, msg_len);
    rust_sha256_finish(&hash_ctx, hash_out);
}

bool keystore_secp256k1_schnorr_bip86_pubkey(const uint8_t* pubkey33, uint8_t* pubkey_out)
{
    const secp256k1_context* ctx = wally_get_secp_context();

    secp256k1_pubkey pubkey = {0};
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkey33, 33)) {
        return false;
    }
    secp256k1_xonly_pubkey xonly_pubkey = {0};
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_pubkey, NULL, &pubkey)) {
        return false;
    }
    uint8_t xonly_pubkey_serialized[32] = {0};
    if (!secp256k1_xonly_pubkey_serialize(ctx, xonly_pubkey_serialized, &xonly_pubkey)) {
        return false;
    }
    uint8_t hash[32] = {0};
    secp256k1_pubkey tweaked_pubkey = {0};
    _tagged_hash("TapTweak", xonly_pubkey_serialized, sizeof(xonly_pubkey_serialized), hash);
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_pubkey, &xonly_pubkey, hash)) {
        return false;
    }
    secp256k1_xonly_pubkey tweaked_xonly_pubkey = {0};
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly_pubkey, NULL, &tweaked_pubkey)) {
        return false;
    }
    return secp256k1_xonly_pubkey_serialize(ctx, pubkey_out, &tweaked_xonly_pubkey) == 1;
}

static bool _schnorr_bip86_keypair(
    const uint32_t* keypath,
    size_t keypath_len,
    secp256k1_keypair* keypair_out,
    secp256k1_xonly_pubkey* pubkey_out)
{
    if (keystore_is_locked()) {
        return false;
    }
    struct ext_key xprv __attribute__((__cleanup__(keystore_zero_xkey))) = {0};
    if (!_get_xprv(keypath, keypath_len, &xprv)) {
        return false;
    }
    const uint8_t* secret_key = xprv.priv_key + 1; // first byte is 0;
    const secp256k1_context* ctx = wally_get_secp_context();
    if (!secp256k1_keypair_create(ctx, keypair_out, secret_key)) {
        return false;
    }
    if (!secp256k1_keypair_xonly_pub(ctx, pubkey_out, NULL, keypair_out)) {
        return false;
    }
    uint8_t pubkey_serialized[32] = {0};
    if (!secp256k1_xonly_pubkey_serialize(ctx, pubkey_serialized, pubkey_out)) {
        return false;
    }
    uint8_t hash[32] = {0};
    _tagged_hash("TapTweak", pubkey_serialized, sizeof(pubkey_serialized), hash);

    if (secp256k1_keypair_xonly_tweak_add(ctx, keypair_out, hash) != 1) {
        return false;
    }
    return secp256k1_keypair_xonly_pub(ctx, pubkey_out, NULL, keypair_out) == 1;
}

static void _cleanup_keypair(secp256k1_keypair* keypair)
{
    util_zero(keypair, sizeof(secp256k1_keypair));
}

bool keystore_secp256k1_schnorr_bip86_sign(
    const uint32_t* keypath,
    size_t keypath_len,
    const uint8_t* msg32,
    uint8_t* sig64_out)
{
    secp256k1_keypair __attribute__((__cleanup__(_cleanup_keypair))) keypair = {0};
    secp256k1_xonly_pubkey pubkey = {0};
    if (!_schnorr_bip86_keypair(keypath, keypath_len, &keypair, &pubkey)) {
        return false;
    }
    const secp256k1_context* ctx = wally_get_secp_context();
    uint8_t aux_rand[32] = {0};
    random_32_bytes(aux_rand);
    if (secp256k1_schnorrsig_sign32(ctx, sig64_out, msg32, &keypair, aux_rand) != 1) {
        return false;
    }
    return secp256k1_schnorrsig_verify(ctx, sig64_out, msg32, 32, &pubkey) == 1;
}

bool keystore_secp256k1_get_private_key(
    const uint32_t* keypath,
    const size_t keypath_len,
    bool tweak_bip86,
    uint8_t* key_out)
{
    if (tweak_bip86) {
        secp256k1_keypair __attribute__((__cleanup__(_cleanup_keypair))) keypair = {0};
        secp256k1_xonly_pubkey pubkey = {0};
        if (!_schnorr_bip86_keypair(keypath, keypath_len, &keypair, &pubkey)) {
            return false;
        }
        const secp256k1_context* ctx = wally_get_secp_context();
        return secp256k1_keypair_sec(ctx, key_out, &keypair) == 1;
    }
    struct ext_key xprv __attribute__((__cleanup__(keystore_zero_xkey))) = {0};
    if (!_get_xprv_twice(keypath, keypath_len, &xprv)) {
        return false;
    }
    memcpy(key_out, xprv.priv_key + 1, 32);
    return true;
}

#ifdef TESTING
void keystore_mock_unlocked(const uint8_t* seed, size_t seed_len, const uint8_t* bip39_seed)
{
    _is_unlocked_device = seed != NULL;
    if (seed != NULL) {
        if (_retain_seed(seed, seed_len) != KEYSTORE_OK) {
            Abort("couldn't retain seed");
        }
    }
    _is_unlocked_bip39 = bip39_seed != NULL;
    if (bip39_seed != NULL) {
        if (!_retain_bip39_seed(bip39_seed)) {
            Abort("couldn't retain bip39 seed");
        }
    }
}

const uint8_t* keystore_test_get_retained_seed_encrypted(size_t* len_out)
{
    *len_out = _retained_seed_encrypted_len;
    return _retained_seed_encrypted;
}

const uint8_t* keystore_test_get_retained_bip39_seed_encrypted(size_t* len_out)
{
    *len_out = _retained_bip39_seed_encrypted_len;
    return _retained_bip39_seed_encrypted;
}
#endif

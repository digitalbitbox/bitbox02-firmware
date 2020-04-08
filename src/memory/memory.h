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

#ifndef _MEMORY_H_
#define _MEMORY_H_

#include <stdbool.h>
#include <stdint.h>

#include "compiler_util.h"
#include "util.h"

#include <fido2/ctap.h>

// Including null terminator.
#define MEMORY_MULTISIG_NAME_MAX_LEN (31)

// How many multisig configurations (accounts) can be registered.
#define MEMORY_MULTISIG_NUM_ENTRIES 10

typedef struct {
    void (*const random_32_bytes)(uint8_t* buf_out);
} memory_interface_functions_t;

typedef enum {
    // success
    MEMORY_OK,
    // invalid function parameters.
    MEMORY_ERR_INVALID_INPUT,
    // there was no more free slot available.
    MEMORY_ERR_FULL,
    // a different entry with the same name already exists.
    MEMORY_ERR_DUPLICATE_NAME,
    // memory write error or other unknown error.
    MEMORY_ERR_UNKNOWN,
} memory_result_t;

/**
 * Initializes the flash memory (including factory install when running the
 * first time).
 * @param[in] ifs Interface functions.
 * @return true on success, false on failure.
 */
USE_RESULT bool memory_setup(memory_interface_functions_t* ifs);
USE_RESULT bool memory_reset_hww(void);

/**
 * Erases the memory area reserved to SmartEEPROM.
 */
USE_RESULT bool memory_cleanup_smarteeprom(void);

#define MEMORY_DEFAULT_DEVICE_NAME "My BitBox"
// Don't change this without proper memory layout migration! (see chunk_1_t in
// memory.c)
#define MEMORY_DEVICE_NAME_MAX_LEN (64)

/* Each memory chunk can contain up to 23 resident keys. */
#define MEMORY_CTAP_RESIDENT_KEYS_PER_CHUNK (23)
#define MEMORY_CTAP_RESIDENT_KEYS_CHUNKS (2)
#define MEMORY_CTAP_RESIDENT_KEYS_MAX (MEMORY_CTAP_RESIDENT_KEYS_CHUNKS * MEMORY_CTAP_RESIDENT_KEYS_PER_CHUNK)

// set device name. name is an utf8-encoded string, and null terminated. The max
// size (including the null terminator) is MEMORY_DEVICE_NAME_MAX_LEN bytes.
USE_RESULT bool memory_set_device_name(const char* name);

// name_out must have MEMORY_DEVICE_NAME_MAX_LEN bytes in size.
void memory_get_device_name(char* name_out);

/**
 * Sets the seed's birthdate to a unix timestamp.
 * @param[in] timestamp The seed birthdate.
 */
USE_RESULT bool memory_set_seed_birthdate(uint32_t timestamp);

/**
 * Retrieves the stored seed birthdate from memory.
 * @param[out] timestamp_out Will contain the seed's birthdate or 0 if it hasn't been set.
 */
void memory_get_seed_birthdate(uint32_t* timestamp_out);

// returns true if a seed has been stored (see memory_set_encrypted_seed_and_hmac)
USE_RESULT bool memory_is_seeded(void);

/**
 * Returns true if the device is initialized (seeded and a backup has been
 * stored).
 */
USE_RESULT bool memory_is_initialized(void);

/**
 * Sets the initialized flag to true.
 * @return true on success, false on failure.
 */
USE_RESULT bool memory_set_initialized(void);

/**
 * Returns true if the bip39 passphrase feature is enabled.
 */
USE_RESULT bool memory_is_mnemonic_passphrase_enabled(void);

/**
 * Activates or deactives the bip39 passphrase feature.
 * @return true on success, false on failure.
 */
USE_RESULT bool memory_set_mnemonic_passphrase_enabled(bool enabled);

/**
 * @return The number of failed unlock attempts.
 */
USE_RESULT uint8_t memory_get_failed_unlock_attempts(void);

/**
 * Increment failed unlock attempts counter. Default value is zero.
 * @return false if there was a write error or there would be a uint8_t overflow.
 */
USE_RESULT bool memory_increment_failed_unlock_attempts(void);

/**
 * Resets the failed unlock counter to 0.
 * @return false if there was a write error
 */
USE_RESULT bool memory_reset_failed_unlock_attempts(void);

USE_RESULT bool memory_set_encrypted_seed_and_hmac(
    const uint8_t* encrypted_seed_and_hmac,
    uint8_t len);

/**
 * Retrieves the encrypted seed and hmac.
 " param[out] encrypted_seed_and_hmac_out must have size 96.
 " param[out] len_out will contain the length of the encrypted seed.
 * memory_is_seeded() must return true prior to calling this
 * function, otherwise the result is undefined.
 */
USE_RESULT bool memory_get_encrypted_seed_and_hmac(
    uint8_t* encrypted_seed_and_hmac_out,
    uint8_t* len_out);

void memory_get_io_protection_key(uint8_t* key_out);
void memory_get_authorization_key(uint8_t* key_out);
void memory_get_encryption_key(uint8_t* key_out);

/**
 * @return true if the attestation setup has been completed.
 */
USE_RESULT bool memory_is_attestation_setup_done(void);

/**
 * Persists the given attestation device pubkey.
 * @param[in] attestation_device_pubkey P256 NIST ECC pubkey (X and Y coordinates).
 * @return false if there was a write error or if the attestation setup was
 * already complete.
 */
USE_RESULT bool memory_set_attestation_device_pubkey(const uint8_t* attestation_device_pubkey);

/**
 * Persists the certificate generated by the host.
 * @param[in] attestation_device_pubkey (64 bytes) is provided as a sanity check, and
 * must match the already persisted pubkey (see
 * memory_set_attestation_device_pubkey()).
 * @param[in] certificate 64 bytes certificate to persist.
 * @param[in] root_pubkey_identifier 32 bytes identifier of the root pubkey
 * whose privkey generated the certificate
 * @return false if there was a write error, the pubkey does not match, or the
 * attestation setup was already complete.
 */
USE_RESULT bool memory_set_attestation_certificate(
    const uint8_t* attestation_device_pubkey,
    const uint8_t* certificate,
    const uint8_t* root_pubkey_identifier);

USE_RESULT bool memory_get_attestation_pubkey_and_certificate(
    uint8_t* pubkey_out,
    uint8_t* certificate_out,
    uint8_t* root_pubkey_identifier_out);

/**
 * Computes sha256(bootloader area).
 * @param[out] hash_out must be 32 bytes and will contain the result.
 */
void memory_bootloader_hash(uint8_t* hash_out);

typedef struct {
    secbool_u8 value;
} auto_enter_t;

typedef struct {
    bool value;
} upside_down_t;

/**
 * Sets the auto_enter and upside_down flags read by the bootloader.
 */
USE_RESULT bool memory_bootloader_set_flags(auto_enter_t auto_enter, upside_down_t upside_down);

/**
 * @param[out] salt_root_out must be 32 bytes.
 * @return false if the key has not been initialized (memory_setup() has not
 * been called before).
 */
USE_RESULT bool memory_get_salt_root(uint8_t* salt_root_out);

/**
 * @param[out] private_key_out must be 32 bytes.
 * @return false if the key has not been initialized (memory_setup() has not
 * been called before).
 */
USE_RESULT bool memory_get_noise_static_private_key(uint8_t* private_key_out);

/*
 * Checks if the pubkey is stored in one of 5 slots.
 * @param[in] pubkey 32 byte noise static pubkey to store.
 * @return true if the pubkey is already stored, false if it is not stored.
 */
USE_RESULT bool memory_check_noise_remote_static_pubkey(const uint8_t* pubkey);

/*
 * Stores a noise remote static pubkey, if it is not already stored. There are 5 slots. If they are
 * all occupied, the oldest (first seen) is evicted.
 * @param[in] pubkey 32 byte noise static pubkey to store.
 * @return false on memory write error.
 */
USE_RESULT bool memory_add_noise_remote_static_pubkey(const uint8_t* pubkey);

/**
 * Store a multisig name under the multisig configuration ID (the hash of the config). At most
 * MEMORY_MULTISIG_NUM_ENTRIES different configs can be stored.
 * If a name is already stored with this hash, the old name will be overwritten.
 * It's the callers responsibility to validate the name (beyond that it must be non-empty).
 * @param[in] hash hash identifying the multisig config. Can't be 0xfffff....
 * @param[in] human readable name. Must be at most MEMORY_MULTISIG_NAME_MAX_LEN bytes,
 * including the null terminator (otherwise the name will be truncated), and non-empty.
 * @return see memory_result_t, can return MEMORY_OK, MEMORY_ERR_INVALID_INPUT, MEMORY_ERR_FULL,
 * MEMORY_ERR_DUPLICATE_NAME, MEMORY_ERR_UNKNOWN.
 */
USE_RESULT memory_result_t memory_multisig_set_by_hash(const uint8_t* hash, const char* name);

/**
 * Retrieves the name of a previously stored multisig config identified by `hash`.
 * @param[in] hash hash identifying the multisig config.
 * @param[out] name_out will contain the name. Must have at least
 * `MEMORY_MULTISIG_NAME_MAX_LEN` bytes. Can be NULL.
 * @return true if the multisig config was found, false otherwise.
 */
USE_RESULT bool memory_multisig_get_by_hash(const uint8_t* hash, char* name_out);

/*
 * Loads the nth CTAP resident key from flash.
 */
USE_RESULT bool memory_get_ctap_resident_key(int key_idx, ctap_resident_key_t* key_out);

void memory_store_ctap_resident_key(int store_location, const ctap_resident_key_t* rk_to_store);

#endif // _MEMORY_H_

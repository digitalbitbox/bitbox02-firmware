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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "flags.h"
#include "hardfault.h"
#include "memory/memory.h"
#include "random.h"
#include "usb/noise.h"
#include "util.h"

#ifndef TESTING
#include "driver_init.h"
#include <hal_delay.h>
#else
#include <mock_memory.h>
#endif

#include <crypto/sha2/sha256.h>

/********* Definitions and read/write helper functions ****************/

// Documentation of all appData chunks and their contents.  A chunk is defined as
// 16 pages, which is the erase granularity: changing any byte in the page
// involves erases and writing all 16 pages. One page is 512 bytes.  The MCU has
// a minimum endurance of 10K write-and-erase cycles.

// Everything defaults to 0xFF (erased state).

#define CHUNK_SIZE (FLASH_ERASE_MIN_LEN) // 8kB; minimum erase granularity
#if (FLASH_APPDATA_START % CHUNK_SIZE)
#error "Chunk start not aligned with erase granularity"
#endif
#if (FLASH_APPDATA_LEN % CHUNK_SIZE)
#error "Chunk end not aligned with erase granularity"
#endif
#if (FLASH_SHARED_DATA_LEN != CHUNK_SIZE)
#error "Shared data chunk not correct length"
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpacked"
#pragma GCC diagnostic ignored "-Wattributes"
// Packed so there is no padding between the fields,
// making the layout more explicit.

typedef struct __attribute__((__packed__)) {
    uint8_t device_pubkey[64]; // P256 NIST ECC pubkey (X and Y coordinates)
    uint8_t certificate[64]; // SECP256k1 signature (R, S)
    // Identifier of the root pubkey whose privkey generated the certificate
    uint8_t root_pubkey_identifier[32];
} attestation_t;

// CHUNK_0_PERMANENT: Written during factory installation, never changed.
#define CHUNK_0_PERMANENT (0)
typedef union {
    struct __attribute__((__packed__)) {
        secbool_u8 factory_setup_done;
        uint8_t reserved[3];
        uint8_t io_protection_key[32];
        uint8_t authorization_key[32];
        uint8_t encryption_key[32];
        attestation_t attestation;
    } fields;
    uint8_t bytes[CHUNK_SIZE];
} chunk_0_t;

// CHUNK_1: Firmware system data
#define CHUNK_1 (1)
typedef union {
    struct __attribute__((__packed__)) {
        uint8_t bitmask; // inverse bitmask, BITMASK_* bits
        uint8_t failed_unlock_attempts; // starts at 0xFF (0 failed attempts), counting downwards
        uint8_t reserved[2];
        uint8_t noise_static_private_key[32]; // CURVE25519
        uint8_t noise_remote_static_pubkeys[5][NOISE_PUBKEY_SIZE]; // 5 pubkey slots
        uint8_t salt_root[32];
        uint8_t
            device_name[MEMORY_DEVICE_NAME_MAX_LEN]; // utf8 encoded device name. 0xFF if not set.
        uint8_t encrypted_seed_and_hmac_len;
        uint8_t encrypted_seed_and_hmac[96];
        uint32_t seed_birthdate; // unix timestamp.
    } fields;
    uint8_t bytes[CHUNK_SIZE];
} chunk_1_t;

typedef struct __attribute__((__packed__)) {
    // version fixed at 0xFF for now - can be repurposed to turn this struct into an union to
    // support other types of data.
    // The multisig entry is considered empty/unset if the hash is filled with 0xFF.
    uint8_t version;
    char name[MEMORY_MULTISIG_NAME_MAX_LEN]; // user-given name for this multisig setup.
    uint8_t hash[32]; // hash comitting to the multisig setup.
} multisig_configuration_t;

// CHUNK_2: Various app data
#define CHUNK_2 (2)
typedef union {
    struct __attribute__((__packed__)) {
        multisig_configuration_t multisig_configs[MEMORY_MULTISIG_NUM_ENTRIES];
    } fields;
    uint8_t bytes[CHUNK_SIZE];
} chunk_2_t;

// Resident key stored in memory:
// the raw key object is stored, followed by a valid byte.
// The key is valid if valid == sectrue_u8.
typedef struct __attribute__((packed)) {
    ctap_resident_key_t key;
    uint8_t valid;
} memory_resident_key_t;

// CHUNK_3-4: FIDO2 resident keys (first chunk).
typedef union {
    struct __attribute__((__packed__)) {
        memory_resident_key_t keys[MEMORY_CTAP_RESIDENT_KEYS_PER_CHUNK];
    } fields;
    uint8_t bytes[CHUNK_SIZE];
} fido2_resident_key_chunk_t;

#define CHUNK_3 (3)
typedef fido2_resident_key_chunk_t chunk_3_t;

#define CHUNK_4 (4)
typedef fido2_resident_key_chunk_t chunk_4_t;

// CHUNK_SHARED: Shared data between the bootloader and firmware.
//    auto_enter: if sectrue_u8, bootloader mode is entered on reboot
//    upside_down: passes screen orientation to the bootloader
//
// ** DO NOT CHANGE MEMBER ORDER OR MEMORY LOCATION **
//
// Because the bootloader is fixed, changes may break the bootloader!
//
typedef union {
    struct __attribute__((__packed__)) {
        // Shared flags - do not change order!
        uint8_t auto_enter;
        uint8_t upside_down;
        // Following are used by firmware only
        uint8_t reserved[2];
        uint8_t io_protection_key_split[32];
        uint8_t authorization_key_split[32];
        uint8_t encryption_key_split[32];
    } fields;
    uint8_t bytes[CHUNK_SIZE];
} chunk_shared_t;
#pragma GCC diagnostic pop

#define BITMASK_SEEDED ((uint8_t)(1u << 0u))
#define BITMASK_INITIALIZED ((uint8_t)(1u << 1u))
#define BITMASK_ENABLE_MNEMONIC_PASSPHRASE ((uint8_t)(1u << 2u))

static void _clean_chunk(uint8_t** chunk_bytes)
{
    util_zero(*chunk_bytes, CHUNK_SIZE);
}

#define CLEANUP_CHUNK(var)                                                                    \
    uint8_t* __attribute__((__cleanup__(_clean_chunk))) __attribute__((unused)) var##_bytes = \
        (var).bytes;

// chunk must have size CHUNK_SIZE. if chunk is NULL, the chunk is erased,
// i.e. filled with 0xFF.
static bool _write_to_address(uint32_t addr, uint8_t* chunk)
{
#ifdef TESTING
    return memory_write_to_address_mock(addr, chunk);
#else
    // Sanity check that the address is correctly aligned,
    // so the erase actually erases only one block.
    if (addr != (addr & ~(CHUNK_SIZE - 1))) {
        return false;
    }
    // Locking granularity is 64 pages, aligned at 16 pages, so we lock/unlock
    // more than just the chunk we want to write.
    const uint32_t lock_size = FLASH_REGION_PAGE_NUM;
    uint32_t lock_addr = addr & ~(lock_size - 1);
    const uint32_t lock_page = lock_addr / FLASH_PAGE_SIZE;
    const size_t n_pages = FLASH_SIZE / FLASH_PAGE_SIZE;
    /*
     * The last address we can unlock is (#pages) - FLASH_REGION_PAGE_NUM.
     * Adjust the address if we are above this point.
     */
    if (lock_page > n_pages - FLASH_REGION_PAGE_NUM && lock_page < n_pages) {
        lock_addr = (n_pages - FLASH_REGION_PAGE_NUM) * FLASH_PAGE_SIZE;
    }

    int res = flash_unlock(&FLASH_0, lock_addr, FLASH_REGION_PAGE_NUM);
    if (res != FLASH_REGION_PAGE_NUM) {
        return false;
    }
    if (chunk == NULL) {
        // Usually has a minimum granularity of 16 pages (one chunk), but the
        // flash_erase driver manually handles smaller/bigger erases.
        if (flash_erase(&FLASH_0, addr, FLASH_ERASE_PAGE_NUM) != ERR_NONE) {
            return false;
        }
    } else {
        // Usually flash_erase is needed before flash_write, the flash_write
        // driver already handles this.
        if (flash_write(&FLASH_0, addr, chunk, CHUNK_SIZE) != ERR_NONE) {
            return false;
        }
    }
    if (flash_lock(&FLASH_0, lock_addr, FLASH_REGION_PAGE_NUM) != FLASH_REGION_PAGE_NUM) {
        // pass, not a critical error.
    }
    return true;
#endif
}

static bool _write_chunk(uint32_t chunk_num, uint8_t* chunk)
{
#ifdef TESTING
    return memory_write_chunk_mock(chunk_num, chunk);
#else
    uint32_t addr = FLASH_APPDATA_START + chunk_num * CHUNK_SIZE;
    return _write_to_address(addr, chunk);
#endif
}

// chunk_out must have size CHUNK_SIZE.
static void _read_chunk(uint32_t chunk_num, uint8_t* chunk_out)
{
#ifdef TESTING
    // empty, can be mocked in cmocka.
    memory_read_chunk_mock(chunk_num, chunk_out);
#else
    memcpy(chunk_out, (uint8_t*)(FLASH_APPDATA_START + chunk_num * CHUNK_SIZE), CHUNK_SIZE);
#endif
}

static void _read_shared_bootdata(uint8_t* chunk_out)
{
#ifdef TESTING
    memory_read_shared_bootdata_mock(chunk_out);
#else
    memcpy(chunk_out, (uint8_t*)(FLASH_SHARED_DATA_START), CHUNK_SIZE);
#endif
}

memory_interface_functions_t* _interface_functions = NULL;

/********* Exposed functions ****************/

bool memory_set_device_name(const char* name)
{
    if (name[0] == (char)0xFF) {
        // utf8 string can't start with 0xFF.
        return false;
    }

    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);
    util_zero(chunk.fields.device_name, sizeof(chunk.fields.device_name));
    snprintf((char*)&chunk.fields.device_name, MEMORY_DEVICE_NAME_MAX_LEN, "%s", name);
    return _write_chunk(CHUNK_1, chunk.bytes);
}

void memory_get_device_name(char* name_out)
{
    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);
    if (chunk.fields.device_name[0] == 0xFF) {
        snprintf(name_out, MEMORY_DEVICE_NAME_MAX_LEN, "%s", MEMORY_DEFAULT_DEVICE_NAME);
    } else {
        snprintf(name_out, MEMORY_DEVICE_NAME_MAX_LEN, "%s", chunk.fields.device_name);
    }
}

bool memory_set_seed_birthdate(uint32_t timestamp)
{
    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);
    chunk.fields.seed_birthdate = timestamp;
    return _write_chunk(CHUNK_1, chunk.bytes);
}

void memory_get_seed_birthdate(uint32_t* timestamp_out)
{
    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);
    if (chunk.fields.seed_birthdate == 0xFFFFFFFF) {
        *timestamp_out = 0;
    } else {
        *timestamp_out = chunk.fields.seed_birthdate;
    }
}

bool memory_setup(memory_interface_functions_t* ifs)
{
    if (ifs == NULL) {
        return false;
    }
    _interface_functions = ifs;

    chunk_0_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_0_PERMANENT, chunk_bytes);
    if (chunk.fields.factory_setup_done == sectrue_u8) {
        // already factory installed
        return true;
    }
    // Perform factory setup.
    if (!memory_reset_hww()) {
        return false;
    }

    chunk_shared_t shared_chunk = {0};
    CLEANUP_CHUNK(shared_chunk);
    _read_shared_bootdata(shared_chunk.bytes);

    // Sanity check: io/auth keys must not have been set before.
    uint8_t empty[32] = {0};
    memset(empty, 0xFF, sizeof(empty));
    if (!MEMEQ(chunk.fields.io_protection_key, empty, 32) ||
        !MEMEQ(chunk.fields.authorization_key, empty, 32) ||
        !MEMEQ(chunk.fields.encryption_key, empty, 32) ||
        !MEMEQ(shared_chunk.fields.io_protection_key_split, empty, 32) ||
        !MEMEQ(shared_chunk.fields.authorization_key_split, empty, 32) ||
        !MEMEQ(shared_chunk.fields.encryption_key_split, empty, 32)) {
        Abort("io/auth/enc key already set");
    }

    _interface_functions->random_32_bytes(chunk.fields.io_protection_key);
    _interface_functions->random_32_bytes(shared_chunk.fields.io_protection_key_split);
    _interface_functions->random_32_bytes(chunk.fields.authorization_key);
    _interface_functions->random_32_bytes(shared_chunk.fields.authorization_key_split);
    _interface_functions->random_32_bytes(chunk.fields.encryption_key);
    _interface_functions->random_32_bytes(shared_chunk.fields.encryption_key_split);

    if (!_write_to_address(FLASH_SHARED_DATA_START, shared_chunk.bytes)) {
        return false;
    }

    // Factory setup done; set initialized byte.
    // TODO: enable once factory install code is complete.
    chunk.fields.factory_setup_done = sectrue_u8;
    return _write_chunk(CHUNK_0_PERMANENT, chunk.bytes);
}

bool memory_cleanup_smarteeprom(void)
{
    // Erase all SmartEEPROM data chunks.
    for (size_t i = 0; i < SMARTEEPROM_ALLOCATED_BLOCKS; ++i) {
        uint32_t w_addr = FLASH_SMARTEEPROM_START + i * CHUNK_SIZE;
        if (!_write_to_address(w_addr, NULL)) {
            return false;
        }
    }
    return true;
}

bool memory_reset_hww(void)
{
    // Erase all app data chunks expect the first one, which is permanent.
    for (uint32_t chunk = CHUNK_1; chunk < FLASH_APPDATA_LEN / CHUNK_SIZE; chunk++) {
        if (!_write_chunk(chunk, NULL)) {
            return false;
        }
    }

    // Initialize hww memory

    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);

    // Set salt root
    _interface_functions->random_32_bytes(chunk.fields.salt_root);

    // Set a new noise static private key.
    if (!bb_noise_generate_static_private_key(chunk.fields.noise_static_private_key)) {
        Abort("memory_reset_hww:\ncould not generate\nnoise key");
    }
    return _write_chunk(CHUNK_1, chunk.bytes);
}

static bool _is_bitmask_flag_set(uint8_t flag)
{
    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);
    return ~chunk.fields.bitmask & flag;
}

bool memory_is_seeded(void)
{
    return _is_bitmask_flag_set(BITMASK_SEEDED);
}

bool memory_is_initialized(void)
{
    return _is_bitmask_flag_set(BITMASK_INITIALIZED);
}

bool memory_set_initialized(void)
{
    if (!memory_is_seeded()) {
        return false;
    }
    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);
    uint8_t bitmask = ~chunk.fields.bitmask;
    bitmask |= BITMASK_INITIALIZED;
    chunk.fields.bitmask = ~bitmask;
    return _write_chunk(CHUNK_1, chunk.bytes);
}

bool memory_is_mnemonic_passphrase_enabled(void)
{
    return _is_bitmask_flag_set(BITMASK_ENABLE_MNEMONIC_PASSPHRASE);
}

bool memory_set_mnemonic_passphrase_enabled(bool enabled)
{
    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);
    uint8_t bitmask = ~chunk.fields.bitmask;
    if (enabled) {
        bitmask |= BITMASK_ENABLE_MNEMONIC_PASSPHRASE;
    } else {
        bitmask &= ~BITMASK_ENABLE_MNEMONIC_PASSPHRASE;
    }
    chunk.fields.bitmask = ~bitmask;
    return _write_chunk(CHUNK_1, chunk.bytes);
}

uint8_t memory_get_failed_unlock_attempts(void)
{
    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);
    return 0xFF - chunk.fields.failed_unlock_attempts;
}

bool memory_increment_failed_unlock_attempts(void)
{
    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);
    if (chunk.fields.failed_unlock_attempts == 0) {
        return false;
    }
    // Unlock attempts are encoded as (0xFF - attempts), i.e. counting down from
    // 0xFF, which is why we decrement here.
    chunk.fields.failed_unlock_attempts--;
    return _write_chunk(CHUNK_1, chunk.bytes);
}

bool memory_reset_failed_unlock_attempts(void)
{
    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);
    // Save a write instruction if already reset.
    if (chunk.fields.failed_unlock_attempts == 0xFF) {
        return true;
    }
    chunk.fields.failed_unlock_attempts = 0xFF;
    return _write_chunk(CHUNK_1, chunk.bytes);
}

bool memory_set_encrypted_seed_and_hmac(const uint8_t* encrypted_seed_and_hmac, uint8_t len)
{
    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);
    chunk.fields.encrypted_seed_and_hmac_len = len;
    memset(
        chunk.fields.encrypted_seed_and_hmac, 0xFF, sizeof(chunk.fields.encrypted_seed_and_hmac));
    memcpy(chunk.fields.encrypted_seed_and_hmac, encrypted_seed_and_hmac, len);
    // set seeded bit
    uint8_t bitmask = ~chunk.fields.bitmask;
    bitmask |= BITMASK_SEEDED;
    chunk.fields.bitmask = ~bitmask;
    return _write_chunk(CHUNK_1, chunk.bytes);
}

bool memory_get_encrypted_seed_and_hmac(uint8_t* encrypted_seed_and_hmac_out, uint8_t* len_out)
{
    if (!memory_is_seeded()) {
        return false;
    }
    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);
    memcpy(
        encrypted_seed_and_hmac_out,
        chunk.fields.encrypted_seed_and_hmac,
        sizeof(chunk.fields.encrypted_seed_and_hmac));
    *len_out = chunk.fields.encrypted_seed_and_hmac_len;
    return true;
}

void memory_get_io_protection_key(uint8_t* key_out)
{
    chunk_0_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_0_PERMANENT, chunk_bytes);

    memcpy(key_out, chunk.fields.io_protection_key, sizeof(chunk.fields.io_protection_key));

    // xor with the second part

    chunk_shared_t shared_chunk = {0};
    CLEANUP_CHUNK(shared_chunk);
    _read_shared_bootdata(shared_chunk.bytes);

    // check assumption
    if (sizeof(shared_chunk.fields.io_protection_key_split) !=
        sizeof(chunk.fields.io_protection_key)) {
        Abort("size mismatch");
    }

    for (size_t i = 0; i < sizeof(shared_chunk.fields.io_protection_key_split); i++) {
        key_out[i] ^= shared_chunk.fields.io_protection_key_split[i];
    }
}

void memory_get_authorization_key(uint8_t* key_out)
{
    chunk_0_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_0_PERMANENT, chunk_bytes);
    memcpy(key_out, chunk.fields.authorization_key, sizeof(chunk.fields.authorization_key));

    // xor with the second part

    chunk_shared_t shared_chunk = {0};
    CLEANUP_CHUNK(shared_chunk);
    _read_shared_bootdata(shared_chunk.bytes);

    // check assumption
    if (sizeof(shared_chunk.fields.authorization_key_split) !=
        sizeof(chunk.fields.authorization_key)) {
        Abort("size mismatch");
    }

    for (size_t i = 0; i < sizeof(shared_chunk.fields.authorization_key_split); i++) {
        key_out[i] ^= shared_chunk.fields.authorization_key_split[i];
    }
}

void memory_get_encryption_key(uint8_t* key_out)
{
    chunk_0_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_0_PERMANENT, chunk_bytes);
    memcpy(key_out, chunk.fields.encryption_key, sizeof(chunk.fields.encryption_key));

    // xor with the second part

    chunk_shared_t shared_chunk = {0};
    CLEANUP_CHUNK(shared_chunk);
    _read_shared_bootdata(shared_chunk.bytes);

    // check assumption
    if (sizeof(shared_chunk.fields.encryption_key_split) != sizeof(chunk.fields.encryption_key)) {
        Abort("size mismatch");
    }

    for (size_t i = 0; i < sizeof(shared_chunk.fields.encryption_key_split); i++) {
        key_out[i] ^= shared_chunk.fields.encryption_key_split[i];
    }
}

bool memory_is_attestation_setup_done(void)
{
    chunk_0_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_0_PERMANENT, chunk_bytes);

    uint8_t empty[64] = {0};
    memset(empty, 0xFF, sizeof(empty));
    return !MEMEQ(chunk.fields.attestation.certificate, empty, 64);
}

bool memory_set_attestation_device_pubkey(const uint8_t* attestation_device_pubkey)
{
    chunk_0_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_0_PERMANENT, chunk_bytes);
    memcpy(chunk.fields.attestation.device_pubkey, attestation_device_pubkey, 64);
    return _write_chunk(CHUNK_0_PERMANENT, chunk.bytes);
}

bool memory_set_attestation_certificate(
    const uint8_t* attestation_device_pubkey,
    const uint8_t* certificate,
    const uint8_t* root_pubkey_identifier)
{
    chunk_0_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_0_PERMANENT, chunk_bytes);
    if (!MEMEQ(attestation_device_pubkey, chunk.fields.attestation.device_pubkey, 64)) {
        return false;
    }
    memcpy(chunk.fields.attestation.certificate, certificate, 64);
    memcpy(chunk.fields.attestation.root_pubkey_identifier, root_pubkey_identifier, 32);
    return _write_chunk(CHUNK_0_PERMANENT, chunk.bytes);
}

bool memory_get_attestation_pubkey_and_certificate(
    uint8_t* pubkey_out,
    uint8_t* certificate_out,
    uint8_t* root_pubkey_identifier_out)
{
    if (!memory_is_attestation_setup_done()) {
        return false;
    }
    chunk_0_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_0_PERMANENT, chunk_bytes);
    memcpy(
        pubkey_out,
        chunk.fields.attestation.device_pubkey,
        sizeof(chunk.fields.attestation.device_pubkey));
    memcpy(
        certificate_out,
        chunk.fields.attestation.certificate,
        sizeof(chunk.fields.attestation.certificate));
    memcpy(
        root_pubkey_identifier_out,
        chunk.fields.attestation.root_pubkey_identifier,
        sizeof(chunk.fields.attestation.root_pubkey_identifier));
    return true;
}

void memory_bootloader_hash(uint8_t* hash_out)
{
    uint8_t* bootloader = FLASH_BOOT_START;
    size_t len = FLASH_BOOT_LEN - 32; // 32 bytes are random
    sha256_context_t ctx;
    sha256_reset(&ctx);
    noise_sha256_update(&ctx, bootloader, len);
    sha256_finish(&ctx, hash_out);
}

bool memory_bootloader_set_flags(auto_enter_t auto_enter, upside_down_t upside_down)
{
    chunk_shared_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_shared_bootdata(chunk.bytes);
    chunk.fields.auto_enter = auto_enter.value;
    chunk.fields.upside_down = upside_down.value ? 1 : 0;
    // As this operation is quite important to succeed, we try it multiple times.
    for (int i = 0; i < 10; i++) {
        if (_write_to_address(FLASH_SHARED_DATA_START, chunk.bytes)) {
            return true;
        }
#ifndef TESTING
        delay_ms(50);
#endif
    }
    return false;
}

bool memory_get_salt_root(uint8_t* salt_root_out)
{
    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);
    memcpy(salt_root_out, chunk.fields.salt_root, sizeof(chunk.fields.salt_root));
    uint8_t empty[32];
    memset(empty, 0xff, sizeof(empty));
    return !MEMEQ(salt_root_out, empty, sizeof(empty));
}

bool memory_get_noise_static_private_key(uint8_t* private_key_out)
{
    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);
    memcpy(
        private_key_out,
        chunk.fields.noise_static_private_key,
        sizeof(chunk.fields.noise_static_private_key));
    uint8_t empty[32];
    memset(empty, 0xff, sizeof(empty));
    return !MEMEQ(private_key_out, empty, sizeof(empty));
}

bool memory_check_noise_remote_static_pubkey(const uint8_t* pubkey)
{
    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);

    const size_t number_of_slots = sizeof(chunk.fields.noise_remote_static_pubkeys) /
                                   sizeof(chunk.fields.noise_remote_static_pubkeys[0]);

    for (size_t slot = 0; slot < number_of_slots; slot++) {
        const uint8_t* stored_pubkey = chunk.fields.noise_remote_static_pubkeys[slot];
        if (MEMEQ(stored_pubkey, pubkey, NOISE_PUBKEY_SIZE)) {
            return true;
        }
    }
    return false;
}

bool memory_add_noise_remote_static_pubkey(const uint8_t* pubkey)
{
    if (memory_check_noise_remote_static_pubkey(pubkey)) {
        // Already stored, do nothing.
        return true;
    }

    chunk_1_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_1, chunk_bytes);

    uint8_t empty[NOISE_PUBKEY_SIZE];
    memset(empty, 0xff, sizeof(empty));

    const size_t number_of_slots = sizeof(chunk.fields.noise_remote_static_pubkeys) /
                                   sizeof(chunk.fields.noise_remote_static_pubkeys[0]);

    // First slot is the oldest, last slot is the newest. We evict the first one and shift the
    // rest to the left by one to make space for the new pubkey.
    for (size_t slot = 0; slot < number_of_slots - 1; slot++) {
        memcpy(
            chunk.fields.noise_remote_static_pubkeys[slot],
            chunk.fields.noise_remote_static_pubkeys[slot + 1],
            NOISE_PUBKEY_SIZE);
    }
    memcpy(
        chunk.fields.noise_remote_static_pubkeys[number_of_slots - 1], pubkey, NOISE_PUBKEY_SIZE);

    return _write_chunk(CHUNK_1, chunk.bytes);
}

memory_result_t memory_multisig_set_by_hash(const uint8_t* hash, const char* name)
{
    uint8_t empty[32];
    memset(empty, 0xFF, sizeof(empty));

    if (!strlens(name)) {
        return MEMORY_ERR_INVALID_INPUT;
    }
    if (hash == NULL || MEMEQ(hash, empty, sizeof(empty))) {
        return MEMORY_ERR_INVALID_INPUT;
    }

    chunk_2_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_2, chunk.bytes);

    // Error if there is already a different multisig config with the same name.
    for (size_t i = 0; i < MEMORY_MULTISIG_NUM_ENTRIES; i++) {
        const multisig_configuration_t* multisig = &chunk.fields.multisig_configs[i];
        if (STREQ(multisig->name, name)) {
            if (!MEMEQ(multisig->hash, hash, sizeof(multisig->hash))) {
                return MEMORY_ERR_DUPLICATE_NAME;
            }
            // config already exists (equal), early abort, skipping another write.
            return MEMORY_OK;
        }
    }

    // This will be true if the hash already exists.
    bool found = false;
    // This is the slot we will write to.
    size_t write_index = 0;
    // This will be the index of an empty slot (if empty_found is true).
    size_t empty_index = 0;
    bool empty_found = false;
    // This loop looks for the already existing entry with the hash to overwrite, or an empty slot.
    for (size_t i = 0; i < MEMORY_MULTISIG_NUM_ENTRIES; i++) {
        const multisig_configuration_t* multisig = &chunk.fields.multisig_configs[i];
        if (!empty_found && MEMEQ(multisig->hash, empty, sizeof(multisig->hash))) {
            empty_found = true;
            empty_index = i;
        }
        if (MEMEQ(multisig->hash, hash, sizeof(multisig->hash))) {
            write_index = i;
            found = true;
            break;
        }
    }
    if (!found && !empty_found) {
        return MEMORY_ERR_FULL;
    }
    if (!found) {
        write_index = empty_index;
    }
    multisig_configuration_t* multisig = &chunk.fields.multisig_configs[write_index];
    memcpy(multisig->hash, hash, sizeof(multisig->hash));
    memset(multisig->name, '\0', sizeof(multisig->name));
    snprintf(multisig->name, sizeof(multisig->name), "%s", name);
    if (!_write_chunk(CHUNK_2, chunk.bytes)) {
        return MEMORY_ERR_UNKNOWN;
    }
    return MEMORY_OK;
}

bool memory_multisig_get_by_hash(const uint8_t* hash, char* name_out)
{
    chunk_2_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(CHUNK_2, chunk.bytes);

    for (size_t i = 0; i < MEMORY_MULTISIG_NUM_ENTRIES; i++) {
        const multisig_configuration_t* multisig = &chunk.fields.multisig_configs[i];
        if (MEMEQ(multisig->hash, hash, sizeof(multisig->hash))) {
            if (name_out != NULL) {
                snprintf(name_out, sizeof(multisig->name), "%s", multisig->name);
            }
            return true;
        }
    }
    return false;
}

static int _ctap_resident_key_chunk(int key_idx)
{
    return CHUNK_3 + key_idx / MEMORY_CTAP_RESIDENT_KEYS_PER_CHUNK;
}

bool memory_get_ctap_resident_key(int key_idx, ctap_resident_key_t* key_out)
{
    fido2_resident_key_chunk_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    _read_chunk(_ctap_resident_key_chunk(key_idx), chunk.bytes);
    /** TODO: simo: implement */
    int key_idx_in_chunk = key_idx % MEMORY_CTAP_RESIDENT_KEYS_PER_CHUNK;
    *key_out = chunk.fields.keys[key_idx_in_chunk].key;
    if (chunk.fields.keys[key_idx_in_chunk].valid == sectrue_u8) {
        key_out->valid = CTAP_RESIDENT_KEY_VALID;
    } else {
        key_out->valid = CTAP_RESIDENT_KEY_INVALID;
    }
    return true;
}

void memory_store_ctap_resident_key(int store_location, const ctap_resident_key_t* rk_to_store)
{
    fido2_resident_key_chunk_t chunk = {0};
    CLEANUP_CHUNK(chunk);
    int chunk_idx = _ctap_resident_key_chunk(store_location);
    int key_idx_in_chunk = store_location % MEMORY_CTAP_RESIDENT_KEYS_PER_CHUNK;

    _read_chunk(chunk_idx, chunk.bytes);

    chunk.fields.keys[key_idx_in_chunk].key = *rk_to_store;
    if (rk_to_store->valid == CTAP_RESIDENT_KEY_VALID) {
        chunk.fields.keys[key_idx_in_chunk].valid = sectrue_u8;
    } else {
        chunk.fields.keys[key_idx_in_chunk].valid = secfalse_u8;
    }
    _write_chunk(chunk_idx, chunk.bytes);
}

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

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <keystore.h>

#include <memory/bitbox02_smarteeprom.h>
#include <memory/smarteeprom.h>
#include <mock_memory.h>
#include <rust/rust.h>
#include <securechip/securechip.h>
#include <util.h>

#include <wally_crypto.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* This file performs some functional keystore tests against fixtures rather than unit tests,
   mocking only low-level functions which are not available on the host. This gives extra assurance
   that seeding/unlocking/derivations work as expected. */

static const char* _some_password = "foo";
static const char* _some_other_password = "bar";

static uint8_t _seed[KEYSTORE_MAX_SEED_LENGTH] =
    "\xcb\x33\xc2\x0c\xea\x62\xa5\xc2\x77\x52\x7e\x20\x02\xda\x82\xe6\xe2\xb3\x74\x50\xa7\x55\x14"
    "\x3a\x54\x0a\x54\xce\xa8\xda\x90\x44";

static uint8_t _salt_root[KEYSTORE_MAX_SEED_LENGTH] = {
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
};

/** Reset the SmartEEPROM configuration. */
static void _smarteeprom_reset(void)
{
    if (smarteeprom_is_enabled()) {
        smarteeprom_disable();
    }
    smarteeprom_bb02_config();
    bitbox02_smarteeprom_init();
}

static void _test_seeds(void** state)
{
    _smarteeprom_reset();
    assert_true(keystore_is_locked());
    uint8_t read_seed[KEYSTORE_MAX_SEED_LENGTH];
    size_t read_seed_len;
    assert_false(keystore_copy_seed(read_seed, &read_seed_len));

    will_return(__wrap_memory_is_initialized, true);
    assert_int_equal(
        keystore_encrypt_and_store_seed(_seed, 32, _some_password), KEYSTORE_ERR_MEMORY);

    uint32_t seed_sizes[3] = {16, 24, 32};
    for (size_t seed_size_idx = 0; seed_size_idx < 3; seed_size_idx++) {
        uint32_t seed_size = seed_sizes[seed_size_idx];
        will_return(__wrap_memory_is_initialized, false);
        assert_int_equal(
            keystore_encrypt_and_store_seed(_seed, seed_size, _some_password), KEYSTORE_OK);
        uint8_t remaining_attempts;
        will_return(__wrap_memory_is_seeded, true);
        assert_int_equal(
            KEYSTORE_ERR_INCORRECT_PASSWORD,
            keystore_unlock(_some_other_password, &remaining_attempts, NULL));
        // First time: unlock. After unlock, it becomes a password check.
        for (int i = 0; i < 3; i++) {
            will_return(__wrap_memory_is_seeded, true);
            assert_int_equal(
                KEYSTORE_OK, keystore_unlock(_some_password, &remaining_attempts, NULL));
        }
        assert_true(keystore_copy_seed(read_seed, &read_seed_len));
        assert_int_equal(seed_size, read_seed_len);
        assert_memory_equal(read_seed, _seed, seed_size);
        keystore_lock();
    }
}

static void _check_mnemonic(const char* expected)
{
    char mnemonic[300];
    assert_true(keystore_get_bip39_mnemonic(mnemonic, sizeof(mnemonic)));
    assert_string_equal(mnemonic, expected);
}

static void _assert_equal_memory_hex(const uint8_t* buf, size_t buf_size, const char* expected_hex)
{
    char buf_hex[2 * buf_size + 1];
    util_uint8_to_hex(buf, buf_size, buf_hex);
    assert_string_equal(buf_hex, expected_hex);
}

static bool _encode_xpub(const struct ext_key* xpub, char* out, size_t out_len)
{
    uint8_t bytes[BIP32_SERIALIZED_LEN] = {0};
    if (bip32_key_serialize(xpub, BIP32_FLAG_KEY_PUBLIC, bytes, sizeof(bytes)) != WALLY_OK) {
        return false;
    }
    return rust_base58_encode_check(
        rust_util_bytes(bytes, sizeof(bytes)), rust_util_bytes_mut((uint8_t*)out, out_len));
}

static void _check_pubs(const char* expected_xpub, const char* expected_pubkey_uncompressed_hex)
{
    struct ext_key __attribute__((__cleanup__(keystore_zero_xkey))) xpub_3;
    struct ext_key __attribute__((__cleanup__(keystore_zero_xkey))) xpub_5;
    uint32_t keypath[] = {
        44 + BIP32_INITIAL_HARDENED_CHILD,
        0 + BIP32_INITIAL_HARDENED_CHILD,
        0 + BIP32_INITIAL_HARDENED_CHILD,
        1,
        2,
    };

    assert_true(keystore_get_xpub(keypath, 3, &xpub_3));
    assert_true(keystore_get_xpub(keypath, 5, &xpub_5));
    char xpub_serialized[120];
    assert_true(_encode_xpub(&xpub_3, xpub_serialized, sizeof(xpub_serialized)));
    assert_string_equal(xpub_serialized, expected_xpub);

    uint8_t pubkey_uncompressed[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    assert_true(keystore_secp256k1_compressed_to_uncompressed(xpub_5.pub_key, pubkey_uncompressed));
    _assert_equal_memory_hex(
        pubkey_uncompressed, sizeof(pubkey_uncompressed), expected_pubkey_uncompressed_hex);
}

static void _test_combination(
    const char* mnemonic_passphrase,
    uint32_t seed_len,
    const char* expected_mnemonic,
    const char* expected_xpub,
    const char* expected_pubkey_uncompressed_hex,
    const char* expected_u2f_seed_hex)
{
    assert_false(keystore_unlock_bip39(mnemonic_passphrase));

    will_return(__wrap_memory_is_initialized, false);
    assert_int_equal(keystore_encrypt_and_store_seed(_seed, seed_len, _some_password), KEYSTORE_OK);
    assert_false(keystore_unlock_bip39(mnemonic_passphrase));
    uint8_t remaining_attempts;
    assert_true(keystore_is_locked());
    will_return(__wrap_memory_is_seeded, true);
    assert_int_equal(KEYSTORE_OK, keystore_unlock(_some_password, &remaining_attempts, NULL));
    assert_true(keystore_is_locked());
    assert_true(keystore_unlock_bip39(mnemonic_passphrase));
    assert_false(keystore_is_locked());
    _check_mnemonic(expected_mnemonic);
    _check_pubs(expected_xpub, expected_pubkey_uncompressed_hex);

    uint8_t u2f_seed[32];
    assert_true(keystore_get_u2f_seed(u2f_seed));
    _assert_equal_memory_hex(u2f_seed, sizeof(u2f_seed), expected_u2f_seed_hex);
    keystore_lock();
}

static void _test_fixtures(void** state)
{
    {
        const char* mnemonic_passphrase = "";
        uint32_t seed_len = 32;
        const char* expected_mnemonic =
            "sleep own lobster state clean thrive tail exist cactus bitter pass soccer clinic riot "
            "dream turkey before sport action praise tunnel hood donate man";
        const char* expected_xpub =
            "xpub6Cj6NNCGj2CRPHvkuEG1rbW3nrNCAnLjaoTg1P67FCGoahSsbg9WQ7YaMEEP83QDxt2kZ3hTPAPpGdyEZc"
            "fAC1C75HfR66UbjpAb39f4PnG";
        const char* expected_pubkey_uncompressed_hex =
            "0477a44aa9e8c8fb5105ef5ee2394e8aed89ad73fc74361425f06347ecfe326131e1339367ee3cbe877192"
            "85a07f774b17eb933ecf0b9b82acebc195226d634244";
        const char* expected_u2f_seed_hex =
            "4f464a6667ad88eebcd0f02982761e474ee0dd16253160320f49d1d6681745e9";
        _test_combination(
            mnemonic_passphrase,
            seed_len,
            expected_mnemonic,
            expected_xpub,
            expected_pubkey_uncompressed_hex,
            expected_u2f_seed_hex);
    }
    {
        const char* mnemonic_passphrase = "abc";
        uint32_t seed_len = 32;
        const char* expected_mnemonic =
            "sleep own lobster state clean thrive tail exist cactus bitter pass soccer clinic riot "
            "dream turkey before sport action praise tunnel hood donate man";
        const char* expected_xpub =
            "xpub6DXBP3HhFdhUTafatEULxfTXUUxDVuCxfa9RAiBU5r6aRgKiABbeBDyqwWWjmKPP1BZvpvVNMbVR5LeHzh"
            "QphtLcPZ8jk3MdLBgc2sACJwR";
        const char* expected_pubkey_uncompressed_hex =
            "044fb66eeefd352b441c86a6200a1e871928a367f5ab5f46566645d01d0534791ae39ff64a7d14d2427297"
            "61ebd3829e8536b389dba543cbc48b1d86c01559d27b";
        const char* expected_u2f_seed_hex =
            "d599da991ad83baaf449c789e2dff1539dd66983b47a1dec1c00ff3f352cccbc";
        _test_combination(
            mnemonic_passphrase,
            seed_len,
            expected_mnemonic,
            expected_xpub,
            expected_pubkey_uncompressed_hex,
            expected_u2f_seed_hex);
    }
    {
        const char* mnemonic_passphrase = "";
        uint32_t seed_len = 24;
        const char* expected_mnemonic =
            "sleep own lobster state clean thrive tail exist cactus bitter pass soccer clinic riot "
            "dream turkey before subject";
        const char* expected_xpub =
            "xpub6C7fKxGtTzEVxCC22U2VHx4GpaVy77DzU6KdZ1CLuHgoUGviBMWDc62uoQVxqcRa5RQbMPnffjpwxve18B"
            "G81VJhJDXnSpRe5NGKwVpXiAb";
        const char* expected_pubkey_uncompressed_hex =
            "043113631363e62a07d6a0becafc8063bb311fd1e9e71a6930d995857837642648aba5c743374e19428565"
            "80f565c6b929737af5439f65f5333baf1d63c1f986bf";
        const char* expected_u2f_seed_hex =
            "fb9dc3fb0a17390776df5c3d8f9261bc5fd5df9f00414cee1393e37e0efda7ef";
        _test_combination(
            mnemonic_passphrase,
            seed_len,
            expected_mnemonic,
            expected_xpub,
            expected_pubkey_uncompressed_hex,
            expected_u2f_seed_hex);
    }
    {
        const char* mnemonic_passphrase = "";
        uint32_t seed_len = 16;
        const char* expected_mnemonic =
            "sleep own lobster state clean thrive tail exist cactus bitter pass sniff";
        const char* expected_xpub =
            "xpub6DLvpzjKpJ8k4xYrWYPmZQkUe9dkG1eRig2v6Jz4iYgo8hcpHWx87gGoCGDaB2cHFZ3ExUfe1jDiMu7Ch6"
            "gA4ULCBhvwZj29mHCPYSux3YV";
        const char* expected_pubkey_uncompressed_hex =
            "04588110a40455d74a3fd439fa2f4c0994cd0dc64644f9e5bc03cc99e7fcfe32eea56cb72d31cb997663b1"
            "f62ad12e9c3a24b717064e8db4cc8ca70ac8a98a46a5";
        const char* expected_u2f_seed_hex =
            "20d68b206aff9667b623a460ce61fc94762de67561d6855ca9a6df7b409b2a54";
        _test_combination(
            mnemonic_passphrase,
            seed_len,
            expected_mnemonic,
            expected_xpub,
            expected_pubkey_uncompressed_hex,
            expected_u2f_seed_hex);
    }
}

int main(void)
{
    mock_memory_set_salt_root(_salt_root);

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(_test_seeds),
        cmocka_unit_test(_test_fixtures),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

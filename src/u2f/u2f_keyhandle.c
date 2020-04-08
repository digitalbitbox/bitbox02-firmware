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

#include "u2f_keyhandle.h"

#include <keystore.h>
#include <random.h>
#include <securechip/securechip.h>
#include <usb/u2f/u2f.h>
#include <util.h>
#include <wally_crypto.h>

USE_RESULT bool u2f_keyhandle_gen(
    const uint8_t* appId,
    const uint8_t* nonce,
    uint8_t* privkey,
    uint8_t* mac)
{
    uint8_t hmac_in[U2F_APPID_SIZE + U2F_NONCE_LENGTH];
    uint8_t seed[32];
    UTIL_CLEANUP_32(seed);
    if (!keystore_get_u2f_seed(seed)) {
        return false;
    }

    // Concatenate AppId and Nonce as input for the first HMAC round
    memcpy(hmac_in, appId, U2F_APPID_SIZE);
    memcpy(hmac_in + U2F_APPID_SIZE, nonce, U2F_NONCE_LENGTH);
    int res = wally_hmac_sha256(
        seed, KEYSTORE_U2F_SEED_LENGTH, hmac_in, sizeof(hmac_in), privkey, HMAC_SHA256_LEN);
    if (res != WALLY_OK) {
        return false;
    }

    // Concatenate AppId and privkey for the second HMAC round
    memcpy(hmac_in + U2F_APPID_SIZE, privkey, HMAC_SHA256_LEN);
    res = wally_hmac_sha256(
        seed, KEYSTORE_U2F_SEED_LENGTH, hmac_in, sizeof(hmac_in), mac, HMAC_SHA256_LEN);
    if (res != WALLY_OK) {
        return false;
    }
    return true;
}

bool u2f_keyhandle_verify(const uint8_t* appId, const uint8_t* key_handle_buf, size_t key_handle_len, uint8_t* privkey) {
    if (key_handle_len < sizeof(u2f_keyhandle_t)) {
        /* This U2F key handle can't represent a valid key handle. */
        return false;
    }

    const u2f_keyhandle_t* key_handle = (const u2f_keyhandle_t*)key_handle_buf;

    /* Compute the MAC corresponding to this nonce. */
    uint8_t mac[HMAC_SHA256_LEN];
    if (!u2f_keyhandle_gen(appId, key_handle->nonce, privkey, mac)) {
        return false;
    }

    /* Verify the key handle's MAC against the actual one we compute. */
    return MEMEQ(key_handle->mac, mac, SHA256_LEN);
}

bool u2f_keyhandle_create_key(const uint8_t* app_id, uint8_t* nonce_out, uint8_t* privkey_out, uint8_t* mac_out, uint8_t* pubkey_out)
{
    for (int i = 0; i < 10; ++i) {
        random_32_bytes(nonce_out);
        if (!u2f_keyhandle_gen(app_id, nonce_out, privkey_out, mac_out)) {
            continue;
        }
        if (securechip_ecc_generate_public_key(privkey_out, pubkey_out)) {
            return true;
        }
    }
    return false;
}

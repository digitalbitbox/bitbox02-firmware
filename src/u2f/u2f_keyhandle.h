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

#ifndef _U2F_KEYHANDLE_H
#define _U2F_KEYHANDLE_H

#include <compiler_util.h>
#include <stdbool.h>
#include <stdint.h>
#include <usb/u2f/u2f.h>
#include <wally_crypto.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpacked"
typedef struct __attribute__((__packed__)) {
    uint8_t mac[HMAC_SHA256_LEN];
    uint8_t nonce[U2F_NONCE_LENGTH];
} u2f_keyhandle_t;
#pragma GCC diagnostic pop

/**
 * Generates a new private key for the given app id, salted with the passed nonce.
 * @param[in] appId The app id of the RP which requests a registration or authentication process.
 * @param[in] nonce A random nonce with which the seed for the private key is salted.
 * @param[out] privkey Buffer in which to store the generated private key. Size must be HMAC_SHA256_LEN.
 * @param[out] mac Buffer in which to store the message authentication code for the private key.
 *                 Size must be HMAC_SHA256_LEN.
 */
USE_RESULT bool u2f_keyhandle_gen(
    const uint8_t* appId,
    const uint8_t* nonce,
    uint8_t* privkey,
    uint8_t* mac);

USE_RESULT bool u2f_keyhandle_verify(
    const uint8_t* appId, const uint8_t* key_handle_buf, size_t key_handle_len, uint8_t* privkey
);

USE_RESULT bool u2f_keyhandle_create_key(const uint8_t* app_id, uint8_t* nonce_out, uint8_t* privkey_out, uint8_t* mac_out, uint8_t* pubkey_out);

#endif // _U2F_KEYHANDLE_H

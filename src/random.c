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
#include <string.h>
#ifndef TESTING
#include "atecc/atecc.h"
#include "driver_init.h"
#include "flags.h"
#include <hal_rand_sync.h>
#endif
#include "hardfault.h"
#include "random.h"
#include "util.h"
#include <wally_crypto.h>

void random_32_bytes_mcu(uint8_t* buf)
{
    if (buf == NULL) {
        Abort("Abort: random_32_bytes_mcu");
    }
    uint8_t random[RANDOM_NUM_SIZE] = {0};
    UTIL_CLEANUP_32(random);
#ifdef TESTING
    // Use standard libary for off chip RNG
    for (size_t i = 0; i < sizeof(random); i++) {
        random[i] = rand();
    }
#else
    rand_sync_read_buf8(&RAND_0, random, sizeof(random));
#endif
    for (size_t i = 0; i < sizeof(random); i++) {
        buf[i] ^= random[i];
    }
}

uint8_t random_byte_mcu(void)
{
#ifdef TESTING
    // Use standard libary for off chip RNG
    return rand();
#else
    uint8_t random;
    rand_sync_read_buf8(&RAND_0, &random, sizeof(random));
    return random;
#endif
}

// random_32_bytes_sec xors random bytes, generated using the secure chip trng,
// into buf.
static void random_32_bytes_sec(uint8_t* buf)
{
    if (buf == NULL) {
        Abort("Abort: random_32_bytes_sec");
    }
    uint8_t random[RANDOM_NUM_SIZE] = {0};
    UTIL_CLEANUP_32(random);
#ifdef TESTING
    // Use standard libary for off chip RNG
    for (size_t i = 0; i < sizeof(random); i++) {
        random[i] = rand();
    }
#else
    if (!securechip_random(random)) {
        Abort("Abort: securechip_random");
    }
#endif
    for (size_t i = 0; i < sizeof(random); i++) {
        buf[i] ^= random[i];
    }
}

void random_32_bytes(uint8_t* buf)
{
    if (buf == NULL) {
        Abort("Abort: random_32_bytes");
    }
    uint8_t random[RANDOM_NUM_SIZE] = {0};
    UTIL_CLEANUP_32(random);
    random_32_bytes_mcu(random);
    random_32_bytes_sec(random);

#ifndef TESTING
    { // mix in factory randomness
        uint8_t* factory_randomness = (uint8_t*)(FLASH_BOOT_START + FLASH_BOOT_LEN - 32);
        for (uint32_t i = 0; i < RANDOM_NUM_SIZE; i++) {
            random[i] ^= factory_randomness[i];
        }
    }
#endif

    if (wally_sha256(random, sizeof(random), buf, RANDOM_NUM_SIZE) != WALLY_OK) {
        Abort("Abort: wally_sha256");
    }
}

#ifdef TESTING
void random_mock_reset(void)
{
    srand(0);
}
#endif

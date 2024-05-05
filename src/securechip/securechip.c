// Copyright 2024 Shift Cryptosecurity AG
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

#include "securechip.h"
#include "atecc/atecc.h"
#include "hardfault.h"
#include "memory/memory_shared.h"
#include "optiga-pal/optiga.h"

typedef struct {
    int (*setup)(const securechip_interface_functions_t* fns);
    bool (*update_keys)(void);
    int (*kdf)(const uint8_t* msg, size_t msg_len, uint8_t* kdf_out);
    int (*kdf_rollkey)(const uint8_t* msg, size_t msg_len, uint8_t* kdf_out);
    bool (*gen_attestation_key)(uint8_t* pubkey_out);
    bool (*attestation_sign)(const uint8_t* challenge, uint8_t* signature_out);
    bool (*monotonic_increments_remaining)(uint32_t* remaining_out);
    bool (*random)(uint8_t* rand_out);
    bool (*ecc_generate_public_key)(uint8_t* priv_key, uint8_t* pub_key);
    bool (*ecc_unsafe_sign)(const uint8_t* priv_key, const uint8_t* msg, uint8_t* sig);
#if APP_U2F == 1 || FACTORYSETUP == 1
    bool (*u2f_counter_set)(uint32_t counter);
#endif
#if APP_U2F == 1
    bool (*u2f_counter_inc)(uint32_t* counter);
#endif
    bool (*model)(securechip_model_t* model_out);
} securechip_crypt_interface_t;

static securechip_crypt_interface_t _fns = {0};

// Detect if we have atecc or optiga chip and set interface functions
bool securechip_init(void)
{
    switch (memory_get_securechip_type()) {
    case MEMORY_SECURECHIP_TYPE_OPTIGA:
        _fns.setup = optiga_setup;
        _fns.kdf = optiga_hmac;
        _fns.random = optiga_random;
        _fns.model = optiga_model;
        break;
    case MEMORY_SECURECHIP_TYPE_ATECC:
    default:
        _fns.setup = atecc_setup;
        _fns.update_keys = atecc_update_keys;
        _fns.kdf = atecc_kdf;
        _fns.kdf_rollkey = atecc_kdf_rollkey;
        _fns.gen_attestation_key = atecc_gen_attestation_key;
        _fns.attestation_sign = atecc_attestation_sign;
        _fns.monotonic_increments_remaining = atecc_monotonic_increments_remaining;
        _fns.random = atecc_random;
        _fns.ecc_generate_public_key = atecc_ecc_generate_public_key;
        _fns.ecc_unsafe_sign = atecc_ecc_unsafe_sign;
#if APP_U2F == 1 || FACTORYSETUP == 1
        _fns.u2f_counter_set = atecc_u2f_counter_set;
#endif
#if APP_U2F == 1
        _fns.u2f_counter_inc = atecc_u2f_counter_inc;
#endif
        _fns.model = atecc_model;
        break;
    }
    return true;
}

#define ABORT_IF_NULL(fn)                 \
    do {                                  \
        if (_fns.fn == 0) {               \
            Abort("No " #fn " function"); \
        }                                 \
    } while (0)

int securechip_setup(const securechip_interface_functions_t* ifs)
{
    ABORT_IF_NULL(setup);
    return _fns.setup(ifs);
}

bool securechip_update_keys(void)
{
    ABORT_IF_NULL(update_keys);
    return _fns.update_keys();
}

int securechip_kdf(const uint8_t* msg, size_t msg_len, uint8_t* mac_out)
{
    ABORT_IF_NULL(kdf);
    return _fns.kdf(msg, msg_len, mac_out);
}

int securechip_kdf_rollkey(const uint8_t* msg, size_t msg_len, uint8_t* mac_out)
{
    ABORT_IF_NULL(kdf_rollkey);
    return _fns.kdf_rollkey(msg, msg_len, mac_out);
}

bool securechip_gen_attestation_key(uint8_t* pubkey_out)
{
    ABORT_IF_NULL(gen_attestation_key);
    return _fns.gen_attestation_key(pubkey_out);
}

bool securechip_attestation_sign(const uint8_t* challenge, uint8_t* signature_out)
{
    ABORT_IF_NULL(attestation_sign);
    return _fns.attestation_sign(challenge, signature_out);
}

bool securechip_monotonic_increments_remaining(uint32_t* remaining_out)
{
    ABORT_IF_NULL(monotonic_increments_remaining);
    return _fns.monotonic_increments_remaining(remaining_out);
}

bool securechip_random(uint8_t* rand_out)
{
    ABORT_IF_NULL(random);
    return _fns.random(rand_out);
}

bool securechip_ecc_generate_public_key(uint8_t* priv_key, uint8_t* pub_key)
{
    ABORT_IF_NULL(ecc_generate_public_key);
    return _fns.ecc_generate_public_key(priv_key, pub_key);
}

bool securechip_ecc_unsafe_sign(const uint8_t* priv_key, const uint8_t* msg, uint8_t* sig)
{
    ABORT_IF_NULL(ecc_unsafe_sign);
    return _fns.ecc_unsafe_sign(priv_key, msg, sig);
}

#if APP_U2F == 1 || FACTORYSETUP == 1
bool securechip_u2f_counter_set(uint32_t counter)
{
    ABORT_IF_NULL(u2f_counter_set);
    return _fns.u2f_counter_set(counter);
}
#endif
#if APP_U2F == 1
bool securechip_u2f_counter_inc(uint32_t* counter)
{
    ABORT_IF_NULL(u2f_counter_inc);
    return _fns.u2f_counter_inc(counter);
}
#endif
bool securechip_model(securechip_model_t* model_out)
{
    ABORT_IF_NULL(model);
    return _fns.model(model_out);
}

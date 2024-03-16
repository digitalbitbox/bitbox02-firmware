// Copyright 2024 Shift Crypto AG
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
#include "optiga-pal/optiga.h"
#include "hal_delay.h"
#include "hardfault.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "optiga/optiga_crypt.h"
#include "optiga/optiga_util.h"
#include "optiga/pal/pal_i2c.h"
#include "optiga/pal/pal_os_datastore.h"
#include "optiga/pal/pal_os_timer.h"
#include "securechip/securechip.h"
#include "util.h"

#define OPTIGA_DATA_OBJECT_ID_HMAC 0xF1D0
#define OPTIGA_DATA_OBJECT_ID_PLATFORM_BINDING 0xE140

#define ABORT_IF_NULL(ptr)           \
    do {                             \
        if ((ptr) == 0) {            \
            Abort("Not initalized"); \
        }                            \
    } while (0)

static optiga_util_t* util;
static optiga_crypt_t* crypt;

static const securechip_interface_functions_t* _ifs = NULL;

// The OPTIGA library is asynchronous and will schedule a callback when the command is done. The
// callback will set this shared variable to the result of the command.
static volatile optiga_lib_status_t optiga_lib_status;

static void optiga_lib_callback(void* callback_ctx, optiga_lib_status_t event)
{
    (void)callback_ctx;
    optiga_lib_status = event;
    printf("optiga_lib_callback 0x%.3x\n", event);
}

// Helper that is used in the main thread to busy wait for the callback to update the shared
// variable.
// It first checks the return status of the command, then busy waits, and then checks the
// asynchronous return status.
// Will return from caller if command failed.
// `return_status` will be updated with the actual return status
// Return statuses are documented in optiga_lib_return_codes.h
#define _WAIT(return_status, optiga_lib_status)                                              \
    do {                                                                                     \
        if ((return_status) != OPTIGA_UTIL_SUCCESS) {                                        \
            traceln("%s failed immediately (code: 0x%04x)\n", __func__, (return_status));    \
            return (return_status);                                                          \
        }                                                                                    \
        while (OPTIGA_LIB_BUSY == (optiga_lib_status)) {                                     \
        }                                                                                    \
        if (OPTIGA_LIB_SUCCESS != (optiga_lib_status)) {                                     \
            traceln("%s failed eventually (code: 0x%04x)\n", __func__, (optiga_lib_status)); \
            return (optiga_lib_status);                                                      \
        }                                                                                    \
        (return_status) = (optiga_lib_status);                                               \
    } while (0)

// Value of Operational state
#define LCSO_STATE_CREATION (0x01)
// Value of Operational state
#define LCSO_STATE_OPERATIONAL (0x07)

// Currently set to Creation state(defualt value). At the real time/customer side this needs to be
// LCSO_STATE_OPERATIONAL (0x07)
#define FINAL_LCSO_STATE (LCSO_STATE_CREATION)

/* Platform Binding Shared Secret (0xE140) Metadata to be updated */
const uint8_t platform_binding_shared_secret_metadata_final[] = {
    // Metadata to be updated
    0x20,
    0x17,
    // LcsO
    0xC0,
    0x01,
    FINAL_LCSO_STATE, // Refer Macro to see the value or some more notes
    // Change/Write Access tag
    0xD0,
    0x07,
    // This allows updating the binding secret during the runtime using shielded connection
    // If not required to update the secret over the runtime, set this to NEV and
    // update Metadata length accordingly
    0xE1,
    0xFC,
    LCSO_STATE_OPERATIONAL, // LcsO < Operational state
    0xFE,
    0x20,
    0xE1,
    0x40,
    // Read Access tag
    0xD1,
    0x03,
    0xE1,
    0xFC,
    LCSO_STATE_OPERATIONAL, // LcsO < Operational state
    // Execute Access tag
    0xD3,
    0x01,
    0x00, // Always
    // Data object Type
    0xE8,
    0x01,
    0x22, // Platform binding secret type
};

static const uint8_t hmac_metadata[] = {
    // Metadata tag in the data object
    0x20,
    0x06,
    // Data object type set to PRESSEC
    0xE8,
    0x01,
    0x21,
    0xD3,
    0x01,
    0x00,
};

//
// Sync wrappers around optiga util/crypt functions
//

// static optiga_lib_status_t _optiga_util_read_data_sync(
//     optiga_util_t* me,
//     uint16_t optiga_oid,
//     uint16_t offset,
//     uint8_t* buffer,
//     uint16_t* length)
//{
//     ABORT_IF_NULL(me);
//
//     optiga_lib_status = OPTIGA_LIB_BUSY;
//     optiga_lib_status_t res = optiga_util_read_data(me, optiga_oid, offset, buffer, length);
//     _WAIT(res, optiga_lib_status);
//     return res;
// }

// static optiga_lib_status_t _optiga_util_read_metadata_sync(
//     optiga_util_t* me,
//     uint16_t optiga_oid,
//     uint8_t* buffer,
//     uint16_t* length)
//{
//     ABORT_IF_NULL(me);
//
//     optiga_lib_status = OPTIGA_LIB_BUSY;
//     optiga_lib_status_t res = optiga_util_read_metadata(me, optiga_oid, buffer, length);
//     _WAIT(res, optiga_lib_status);
//     return res;
// }

static optiga_lib_status_t _optiga_util_write_data_sync(
    optiga_util_t* me,
    uint16_t optiga_oid,
    uint8_t write_type,
    uint16_t offset,
    const uint8_t* buffer,
    uint16_t length)
{
    ABORT_IF_NULL(me);

    optiga_lib_status = OPTIGA_LIB_BUSY;
    optiga_lib_status_t res =
        optiga_util_write_data(me, optiga_oid, write_type, offset, buffer, length);
    _WAIT(res, optiga_lib_status);
    return res;
}

static optiga_lib_status_t _optiga_util_write_metadata_sync(
    optiga_util_t* me,
    uint16_t optiga_oid,
    const uint8_t* buffer,
    uint8_t length)
{
    ABORT_IF_NULL(me);

    optiga_lib_status = OPTIGA_LIB_BUSY;
    optiga_lib_status_t res = optiga_util_write_metadata(me, optiga_oid, buffer, length);
    _WAIT(res, optiga_lib_status);
    return res;
}

static optiga_lib_status_t _optiga_util_open_application_sync(
    optiga_util_t* me,
    bool_t perform_restore)
{
    ABORT_IF_NULL(me);

    optiga_lib_status = OPTIGA_LIB_BUSY;
    optiga_lib_status_t res = optiga_util_open_application(me, perform_restore);
    _WAIT(res, optiga_lib_status);
    return res;
}

static optiga_lib_status_t _optiga_util_close_application_sync(
    optiga_util_t* me,
    bool_t perform_hibernate)
{
    ABORT_IF_NULL(me);

    optiga_lib_status = OPTIGA_LIB_BUSY;
    optiga_lib_status_t res = optiga_util_close_application(me, perform_hibernate);
    _WAIT(res, optiga_lib_status);
    return res;
}

static optiga_lib_status_t _optiga_crypt_hmac_sync(
    optiga_crypt_t* me,
    optiga_hmac_type_t type,
    uint16_t secret,
    const uint8_t* input_data,
    uint32_t input_data_length,
    uint8_t* mac,
    uint32_t* mac_length)
{
    ABORT_IF_NULL(me);

    optiga_lib_status = OPTIGA_LIB_BUSY;
    optiga_lib_status_t res =
        optiga_crypt_hmac(me, type, secret, input_data, input_data_length, mac, mac_length);
    _WAIT(res, optiga_lib_status);
    return res;
}

static optiga_lib_status_t _optiga_crypt_random_sync(
    optiga_crypt_t* me,
    optiga_rng_type_t rng_type,
    uint8_t* random_data,
    uint16_t random_data_length)
{
    ABORT_IF_NULL(me);

    optiga_lib_status = OPTIGA_LIB_BUSY;
    optiga_lib_status_t res = optiga_crypt_random(me, rng_type, random_data, random_data_length);
    _WAIT(res, optiga_lib_status);
    return res;
}

static bool _write_config(void)
{
    //
    // Write platform binding secret to securechip
    //

    uint8_t platform_binding_secret[32];
    uint16_t len = sizeof(platform_binding_secret);
    optiga_lib_status_t res;
    pal_status_t pal_res;

    pal_res = pal_os_datastore_read(
        OPTIGA_PLATFORM_BINDING_SHARED_SECRET_ID, platform_binding_secret, &len);

    if (PAL_STATUS_SUCCESS != pal_res) {
        return false;
    }

    OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(util, OPTIGA_COMMS_NO_PROTECTION);
    res = _optiga_util_write_data_sync(
        util,
        OPTIGA_DATA_OBJECT_ID_PLATFORM_BINDING,
        OPTIGA_UTIL_ERASE_AND_WRITE,
        0,
        platform_binding_secret,
        sizeof(platform_binding_secret));
    if (res != OPTIGA_LIB_SUCCESS) {
        return false;
    }

    OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(util, OPTIGA_COMMS_NO_PROTECTION);
    res = _optiga_util_write_metadata_sync(
        util,
        OPTIGA_DATA_OBJECT_ID_PLATFORM_BINDING,
        platform_binding_shared_secret_metadata_final,
        sizeof(platform_binding_shared_secret_metadata_final));
    if (res != OPTIGA_LIB_SUCCESS) {
        return false;
    }

    //
    // Configure HMAC data object
    //

    OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(util, OPTIGA_COMMS_NO_PROTECTION);
    res = _optiga_util_write_metadata_sync(
        util, OPTIGA_DATA_OBJECT_ID_HMAC, hmac_metadata, sizeof(hmac_metadata));

    if (res != OPTIGA_LIB_SUCCESS) {
        return false;
    }

    return true;
}

static bool _factory_setup(void)
{
    optiga_lib_status_t res;

    util = optiga_util_create(OPTIGA_INSTANCE_ID_0, optiga_lib_callback, NULL);
    if (NULL == util) {
        traceln("%s", "util_create returned null");
        return 1;
    }

    crypt = optiga_crypt_create(OPTIGA_INSTANCE_ID_0, optiga_lib_callback, NULL);
    if (NULL == crypt) {
        traceln("%s", "crypt_create returned null");
        return 1;
    }

    OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(util, OPTIGA_COMMS_NO_PROTECTION);
    res = _optiga_util_open_application_sync(util, 0);
    if (res != OPTIGA_LIB_SUCCESS) {
        traceln("Failed to open application %d", res);
        return 1;
    }

    if (!_write_config()) {
        traceln("%s", "failed to write config to chip");
        return false;
    }

    res = _optiga_util_close_application_sync(util, 0);
    if (res != OPTIGA_LIB_SUCCESS) {
        traceln("Failed to open application %d", res);
        return 1;
    }

    if (NULL != crypt) {
        optiga_crypt_destroy(crypt);
        crypt = NULL;
    }

    if (NULL != util) {
        optiga_util_destroy(util);
        util = NULL;
    }

    return true;
}

static bool _verify_config(void)
{
    optiga_lib_status_t res;

    util = optiga_util_create(OPTIGA_INSTANCE_ID_0, optiga_lib_callback, NULL);
    if (NULL == util) {
        traceln("%s", "util_create returned null");
        return false;
    }

    crypt = optiga_crypt_create(OPTIGA_INSTANCE_ID_0, optiga_lib_callback, NULL);
    if (NULL == crypt) {
        traceln("%s", "crypt_create returned null");
        return false;
    }

    res = _optiga_util_open_application_sync(util, 0);
    if (res != OPTIGA_LIB_SUCCESS) {
        traceln("Failed to open application %d", res);
        return false;
    }
    traceln("%s", "Application open");
    return true;
}

int optiga_setup(const securechip_interface_functions_t* ifs)
{
    if (ifs == NULL) {
        return SC_ERR_IFS;
    }
    _ifs = ifs;

    // A timer is used to provide the OPTIGA library with the ability to schedule work on the main
    // event loop
    pal_timer_init();

#if true // FACTORYSETUP == 1
    bool res = _factory_setup();
    if (!res) {
        return res;
    }
    traceln("%s", "factory setup done");
#endif

    if (_verify_config()) {
        return 0;
    }
    return SC_ERR_INVALID_ARGS;
}

static bool _update_hmac_key(void)
{
    ABORT_IF_NULL(util);
    ABORT_IF_NULL(_ifs);
    ABORT_IF_NULL(_ifs->random_32_bytes);

    uint8_t new_key[32] = {0};
    _ifs->random_32_bytes(new_key);

    traceln("new hmac key: %s", util_uint8_to_hex_alloc(new_key, sizeof(new_key)));

    return _optiga_util_write_data_sync(
               util,
               OPTIGA_DATA_OBJECT_ID_HMAC,
               OPTIGA_UTIL_ERASE_AND_WRITE,
               0x00,
               new_key,
               sizeof(new_key)) == OPTIGA_LIB_SUCCESS;
}

int optiga_hmac(const uint8_t* msg, size_t len, uint8_t* mac_out)
{
    ABORT_IF_NULL(crypt);
    // The equivalient of python `mac_out = hmac.new(key, msg[:len], hashlib.sha256).digest()`

    _update_hmac_key();
    uint32_t mac_out_len = 32;

    optiga_lib_status_t res = _optiga_crypt_hmac_sync(
        crypt, OPTIGA_HMAC_SHA_256, OPTIGA_DATA_OBJECT_ID_HMAC, msg, len, mac_out, &mac_out_len);

    if (mac_out_len != 32) {
        traceln("%s", "Unexpected MAC length");
    }

    return res == OPTIGA_LIB_SUCCESS;
}

// rand_out must be 32 bytes
bool optiga_random(uint8_t* rand_out)
{
    return _optiga_crypt_random_sync(crypt, OPTIGA_RNG_TYPE_TRNG, rand_out, 32) ==
           OPTIGA_LIB_SUCCESS;
}

bool optiga_model(securechip_model_t* model_out)
{
    *model_out = OPTIGA_TRUST_M_V3;
    return true;
}

// bool _ecc_write_priv_key(uint8_t* priv_key) {
//
// }
//
// bool securitufunctions_ecc_generate_public_key(uint8_t* priv_key, uint8_t* pub_key) {
//     _ecc_write_priv_key(priv_key
// }

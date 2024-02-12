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
#include "u2f.h"
#include "u2f/u2f_app.h"

#include <stdio.h>
#include <string.h>

#include <atecc/atecc.h>
#include <hardfault.h>
#include <keystore.h>
#include <memory/memory.h>
#include <random.h>
#include <rust/rust.h>
#include <ui/component.h>
#include <ui/components/confirm.h>
#include <ui/components/info_centered.h>
#include <ui/screen_process.h>
#include <ui/screen_stack.h>
#include <usb/u2f/u2f.h>
#include <usb/u2f/u2f_hid.h>
#include <usb/u2f/u2f_keys.h>
#include <usb/usb_packet.h>
#include <usb/usb_processing.h>
#include <wally_crypto.h>

#ifndef TESTING
#include <hal_timer.h>
extern struct timer_descriptor TIMER_0;
#endif

typedef struct {
    uint8_t cla, ins, p1, p2;
    uint8_t lc1, lc2, lc3;
    uint8_t data[];
} USB_APDU;

#define APDU_LEN(A) (uint32_t)(((A).lc1 << 16) + ((A).lc2 << 8) + ((A).lc3))
#define U2F_KEYHANDLE_LEN (U2F_NONCE_LENGTH + SHA256_LEN)

#if (U2F_EC_KEY_SIZE != SHA256_LEN) || (U2F_EC_KEY_SIZE != U2F_NONCE_LENGTH)
#error "Incorrect macro values for u2f"
#endif

typedef enum {
    U2F_REGISTER_IDLE = 0,
    U2F_REGISTER_UNLOCKING,
    U2F_REGISTER_WAIT_REFRESH,
    U2F_REGISTER_CONFIRMING
} u2f_reg_state_t;

typedef enum {
    U2F_AUTHENTICATE_IDLE = 0,
    U2F_AUTHENTICATE_UNLOCKING,
    U2F_AUTHENTICATE_WAIT_REFRESH,
    U2F_AUTHENTICATE_CONFIRMING
} u2f_auth_state_t;

typedef struct {
    uint32_t cid;
    /**
     * Command that is currently executing
     * (blocking) on the U2F stack.
     */
    uint8_t last_cmd;
    /**
     * Keeps track of whether there is an outstanding
     * U2F operation going on in the background.
     * This is not strictly necessary, but it's useful
     * to have as a sanity checking mechanism.
     */
    bool locked;
    /**
     * Keeps track of which part of a registration we're currently in.
     */
    u2f_reg_state_t reg;
    /**
     * Keeps track of which part of authentication we're currently in.
     */
    u2f_auth_state_t auth;
    /** "Refresh webpage" component */
    component_t* refresh_webpage;
    /**
     * Timer increased during u2f_process if we're waiting for a page refresh.
     * Will drop the refresh_webpage() screen after a few ticks.
     */
    uint16_t refresh_webpage_timeout;
} u2f_state_t;

static u2f_state_t _state = {0};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpacked"
#pragma GCC diagnostic ignored "-Wattributes"

typedef struct __attribute__((__packed__)) {
    uint8_t reserved;
    uint8_t appId[U2F_APPID_SIZE];
    uint8_t challenge[U2F_NONCE_LENGTH];
    uint8_t keyHandle[U2F_KEYHANDLE_LEN];
    uint8_t pubKey[U2F_EC_POINT_SIZE];
} U2F_REGISTER_SIG_STR;

typedef struct __attribute__((__packed__)) {
    uint8_t appId[U2F_APPID_SIZE];
    uint8_t flags;
    uint8_t ctr[4];
    uint8_t challenge[U2F_NONCE_LENGTH];
} U2F_AUTHENTICATE_SIG_STR;

#pragma GCC diagnostic pop

static component_t* _create_refresh_webpage(void)
{
    return info_centered_create("Refresh webpage", NULL);
}

/* Resets the internal state to idle. */
static void _clear_state(void)
{
    _state.reg = U2F_REGISTER_IDLE;
    _state.auth = U2F_AUTHENTICATE_IDLE;
    _state.locked = false;
}

/**
 * Unlocks the USB stack. Resets the U2F state.
 */
static void _unlock(void)
{
    usb_processing_unlock();
    _clear_state();
}

/**
 * Locks the USB stack to process the given
 * U2F request.
 *
 * @param apdu U2F packet that will own the lock on the USB stack. No other request
 *             will be processed by the USB stack until this request completes.
 */
static void _lock(const USB_APDU* apdu)
{
    usb_processing_lock(usb_processing_u2f());
    _state.locked = true;
    _state.last_cmd = apdu->ins;
}

static component_t* _nudge_label = NULL;

static void _nudge_label_cb(component_t* component)
{
    if (ui_screen_stack_top() == component->parent) {
        _nudge_label = NULL;
        ui_screen_stack_pop();
    }
}

static void _create_nudge_label(void)
{
    if (!_nudge_label) {
        _nudge_label =
            info_centered_create("Initialize with BitBoxApp\nto use U2F", _nudge_label_cb);
    }
    if (ui_screen_stack_top() != _nudge_label) {
        ui_screen_stack_push(_nudge_label);
    }
}

static void _start_refresh_webpage_screen(void)
{
    // Unfortunately unlocking takes more time than U2F is allowed to take. With the current
    // architecture of the firmware we cannot run it concurrently to other requests. Therefore
    // we will call it here, make the user unlock the device and then ask the user to refresh
    // the webpage. (refreshing is only needed for some browsers)
    _state.refresh_webpage = _create_refresh_webpage();
    ui_screen_stack_push(_state.refresh_webpage);
    _state.refresh_webpage_timeout = 0;
}

/** Pop the "refresh webpage" screen, if any. */
static void _stop_refresh_webpage_screen(void)
{
    if (ui_screen_stack_top() && ui_screen_stack_top() == _state.refresh_webpage) {
        _state.refresh_webpage = NULL;
        ui_screen_stack_pop();
    }
}

/**
 * Unlock the BB02 if needed.
 * If the BB02 is alreay unlocked, don't do anything.
 * If the BB02 is locked, try to unlock it and on success start the
 * "Refresh webpage" screen.
 *
 * @return Unlock success status:
 *           * ASYNC_OP_TRUE if the BB02 is unlocked;
 *           * ASYNC_OP_NOT_READY if the BB02 wasn't unlocked, but is now
 *                                ("Refresh webpage" screen was started).
 *           * ASYNC_OP_FALSE if the BB02 couldn't be unlocked.
 */
static bool _unlock_if_locked(void)
{
    if (keystore_is_locked()) {
        rust_workflow_spawn_unlock();
        return false;
    }
    /* Pop the "refresh webpage" screen if any */
    _stop_refresh_webpage_screen();
    return true;
}

static uint32_t _next_cid(void)
{
    do {
        _state.cid = (random_byte_mcu() << 0) + (random_byte_mcu() << 8) +
                     (random_byte_mcu() << 16) + (random_byte_mcu() << 24);
    } while (_state.cid == 0 || _state.cid == U2FHID_CID_BROADCAST);
    return _state.cid;
}

static void _fill_message(const uint8_t* data, const uint32_t len, Packet* out_packet)
{
    util_zero(out_packet->data_addr, sizeof(out_packet->data_addr));
    memcpy(out_packet->data_addr, data, len);
    out_packet->cid = _state.cid;
    out_packet->cmd = U2FHID_MSG;
    out_packet->len = len;
}

static void _error_hid(uint32_t fcid, uint8_t err, Packet* out_packet)
{
    util_zero(out_packet->data_addr, sizeof(out_packet->data_addr));
    out_packet->data_addr[0] = err;
    out_packet->cid = fcid;
    out_packet->cmd = U2FHID_ERROR;
    out_packet->len = 1;
}

static void _error(const uint16_t err, Packet* out_packet)
{
    uint8_t data[2];
    data[0] = err >> 8 & 0xFF;
    data[1] = err & 0xFF;
    _fill_message(data, sizeof(data), out_packet);
}

static void _version(const USB_APDU* a, Packet* out_packet)
{
    if (APDU_LEN(*a) != 0) {
        _error(U2F_SW_WRONG_LENGTH, out_packet);
        return;
    }

    static const uint8_t version_response[] = {'U', '2', 'F', '_', 'V', '2', 0x90, 0x00};
    _fill_message(version_response, sizeof(version_response), out_packet);
}

/**
 * Generates a key for the given app id, salted with the passed nonce.
 * @param[in] appId The app id of the RP which requests a registration or authentication process.
 * @param[in] nonce A random nonce with which the seed for the private key is salted.
 * @param[out] privkey The generated private key. Size must be HMAC_SHA256_LEN.
 * @param[out] mac The message authentication code for the private key. Size must be
 * HMAC_SHA256_LEN.
 */
USE_RESULT static bool _keyhandle_gen(
    const uint8_t* appId,
    uint8_t* nonce,
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

static int _sig_to_der(const uint8_t* sig, uint8_t* der)
{
    int i;
    uint8_t *p = der, *len, *len1, *len2;
    *p = 0x30;
    p++; // sequence
    *p = 0x00;
    len = p;
    p++; // len(sequence)

    *p = 0x02;
    p++; // integer
    *p = 0x00;
    len1 = p;
    p++; // len(integer)

    // process R
    i = 0;
    while (sig[i] == 0 && i < 32) {
        i++; // skip leading zeroes
    }
    if (sig[i] >= 0x80) { // put zero in output if MSB set
        *p = 0x00;
        p++;
        *len1 = *len1 + 1;
    }
    while (i < 32) { // copy bytes to output
        *p = sig[i];
        p++;
        *len1 = *len1 + 1;
        i++;
    }

    *p = 0x02;
    p++; // integer
    *p = 0x00;
    len2 = p;
    p++; // len(integer)

    // process S
    i = 32;
    while (sig[i] == 0 && i < 64) {
        i++; // skip leading zeroes
    }
    if (sig[i] >= 0x80) { // put zero in output if MSB set
        *p = 0x00;
        p++;
        *len2 = *len2 + 1;
    }
    while (i < 64) { // copy bytes to output
        *p = sig[i];
        p++;
        *len2 = *len2 + 1;
        i++;
    }

    *len = *len1 + *len2 + 4;
    return *len + 2;
}

/**
 * Checks the device is unlocked. Abort if it isn't.
 * This is used as a sanity check when we receive a U2F
 * request retry and we're showing the "Refresh webpage"
 * screen. If we arrived there, it means that the BB02 has
 * already been unlocked.
 */
static void _assert_unlocked(void)
{
    bool was_unlocked = _unlock_if_locked();
    if (!was_unlocked) {
        Abort("Bad BB02 lock status after refresh");
    }
}

/**
 * Checks that request data contained into the given authentication request is valid.
 * This will check that the common parameters of the given request (length etc) are sensible,
 * and that the keyhandle
 *
 * @param req Request to check.
 * @return error code.
 */
static uint16_t _register_sanity_check_req(const USB_APDU* apdu)
{
    if (APDU_LEN(*apdu) < U2F_KEYHANDLE_LEN) { // actual size could vary
        return U2F_SW_WRONG_LENGTH;
    }

    if (!memory_is_initialized()) {
        _create_nudge_label();
        return U2F_SW_CONDITIONS_NOT_SATISFIED;
    }
    return 0;
}

/**
 * Starts the registration "confirm" screen.
 */
static void _register_start_confirm(const uint8_t* app_id)
{
    _state.reg = U2F_REGISTER_CONFIRMING;
    u2f_app_confirm_start(U2F_APP_REGISTER, app_id);
}

/**
 * Initiates the U2F registration workflow.
 * @param[in] apdu The APDU packet.
 */
static void _register_start(const USB_APDU* apdu, Packet* out_packet)
{
    const U2F_REGISTER_REQ* reg_request = (const U2F_REGISTER_REQ*)apdu->data;
    uint16_t req_error = _register_sanity_check_req(apdu);
    if (req_error) {
        _unlock();
        _error(req_error, out_packet);
        return;
    }

    // If it fails to unlock it will call _unlock()
    bool is_unlocked = _unlock_if_locked();
    if (!is_unlocked) {
        _state.reg = U2F_REGISTER_UNLOCKING;
    } else {
        _register_start_confirm(reg_request->appId);
    }
    _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
}

static void _register_wait_refresh(const USB_APDU* apdu, Packet* out_packet)
{
    _assert_unlocked();
    const U2F_REGISTER_REQ* reg_request = (const U2F_REGISTER_REQ*)apdu->data;
    _register_start_confirm(reg_request->appId);
    _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
}

static void _register_continue(const USB_APDU* apdu, Packet* out_packet)
{
    uint8_t privkey[U2F_EC_KEY_SIZE] = {0};
    uint8_t nonce[U2F_NONCE_LENGTH] = {0};
    uint8_t mac[HMAC_SHA256_LEN] = {0};
    uint8_t sig[64] = {0};
    U2F_REGISTER_SIG_STR sig_base;
    uint8_t data[sizeof(U2F_REGISTER_RESP) + 2] = {0};
    const U2F_REGISTER_REQ* reg_request = (const U2F_REGISTER_REQ*)apdu->data;
    U2F_REGISTER_RESP* response = (U2F_REGISTER_RESP*)data;

    async_op_result_t async_result = u2f_app_confirm_retry(U2F_APP_REGISTER, reg_request->appId);
    if (async_result == ASYNC_OP_NOT_READY) {
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }

    /* No more pending operations for U2F register */
    _unlock();

    if (async_result == ASYNC_OP_FALSE) {
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }

    // Generate keys until a valid one is found
    int i = 0;
    for (;; ++i) {
        if (i == 10) {
            _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
            return;
        }
        random_32_bytes(nonce);
        if (!_keyhandle_gen(reg_request->appId, nonce, privkey, mac)) {
            continue;
        }
        if (securechip_ecc_generate_public_key(privkey, (uint8_t*)&response->pubKey.x)) {
            break;
        }
    }

    response->pubKey.format = U2F_UNCOMPRESSED_POINT;

    response->registerId = U2F_REGISTER_ID;
    response->keyHandleLen = U2F_KEYHANDLE_LEN;

    memcpy(response->keyHandleCertSig, mac, sizeof(mac));
    memcpy(response->keyHandleCertSig + sizeof(mac), nonce, sizeof(nonce));
    memcpy(response->keyHandleCertSig + response->keyHandleLen, U2F_ATT_CERT, sizeof(U2F_ATT_CERT));

    // Add signature using attestation key
    sig_base.reserved = 0;
    memcpy(sig_base.appId, reg_request->appId, U2F_APPID_SIZE);
    memcpy(sig_base.challenge, reg_request->challenge, U2F_NONCE_LENGTH);
    memcpy(sig_base.keyHandle, &response->keyHandleCertSig, U2F_KEYHANDLE_LEN);
    memcpy(sig_base.pubKey, &response->pubKey, U2F_EC_POINT_SIZE);

    uint8_t hash[SHA256_LEN] = {0};
    wally_sha256((uint8_t*)&sig_base, sizeof(sig_base), hash, SHA256_LEN);

    if (!securechip_ecc_unsafe_sign(U2F_ATT_PRIV_KEY, hash, sig)) {
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }

    uint8_t* resp_sig = response->keyHandleCertSig + response->keyHandleLen + sizeof(U2F_ATT_CERT);
    int der_len = _sig_to_der(sig, resp_sig);
    size_t kh_cert_sig_len = response->keyHandleLen + sizeof(U2F_ATT_CERT) + der_len;

    // Append success bytes
    memcpy(response->keyHandleCertSig + kh_cert_sig_len, "\x90\x00", 2);

    size_t len =
        1 /* registerId */ + U2F_EC_POINT_SIZE + 1 /* keyhandleLen */ + kh_cert_sig_len + 2;
    _fill_message(data, len, out_packet);
}

/**
 * Checks that request data contained into the given authentication request is valid.
 * This will check that the common parameters of the given request (length etc) are sensible,
 * and that the keyhandle
 *
 * @param req Request to check.
 * @return error code.
 */
static uint16_t _authenticate_sanity_check_req(const USB_APDU* apdu)
{
    if (APDU_LEN(*apdu) < U2F_KEYHANDLE_LEN) { // actual size could vary
        return U2F_SW_WRONG_LENGTH;
    }

    if (!memory_is_initialized()) {
        _create_nudge_label();
        return U2F_SW_CONDITIONS_NOT_SATISFIED;
    }
    return 0;
}

static uint16_t _authenticate_verify_key_valid(const USB_APDU* apdu)
{
    uint8_t nonce[U2F_NONCE_LENGTH];
    uint8_t mac[HMAC_SHA256_LEN];
    uint8_t privkey[U2F_EC_KEY_SIZE];
    const U2F_AUTHENTICATE_REQ* auth_request = (const U2F_AUTHENTICATE_REQ*)apdu->data;
    memcpy(nonce, auth_request->keyHandle + sizeof(mac), sizeof(nonce));
    if (!_keyhandle_gen(auth_request->appId, nonce, privkey, mac)) {
        return U2F_SW_WRONG_DATA;
    }
    if (!MEMEQ(auth_request->keyHandle, mac, SHA256_LEN)) {
        return U2F_SW_WRONG_DATA;
    }
    if (apdu->p1 == U2F_AUTH_CHECK_ONLY) {
        // success: "error:test-of-user-presense"
        return U2F_SW_CONDITIONS_NOT_SATISFIED;
    }
    if (apdu->p1 != U2F_AUTH_ENFORCE) {
        return U2F_SW_INS_NOT_SUPPORTED;
    }
    return 0;
}

static uint16_t _authenticate_start_confirm(const USB_APDU* apdu)
{
    const U2F_AUTHENTICATE_REQ* auth_request = (const U2F_AUTHENTICATE_REQ*)apdu->data;
    uint16_t key_error = _authenticate_verify_key_valid(apdu);
    if (key_error) {
        return key_error;
    }
    _state.auth = U2F_AUTHENTICATE_CONFIRMING;
    u2f_app_confirm_start(U2F_APP_AUTHENTICATE, auth_request->appId);
    return 0;
}

static void _authenticate_start(const USB_APDU* apdu, Packet* out_packet)
{
    uint16_t req_error = _authenticate_sanity_check_req(apdu);
    if (req_error) {
        _unlock();
        _error(req_error, out_packet);
        return;
    }

    // If it fails to unlock it will call _unlock()
    bool is_unlocked = _unlock_if_locked();
    if (!is_unlocked) {
        _state.auth = U2F_AUTHENTICATE_UNLOCKING;
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }
    uint16_t key_error = _authenticate_start_confirm(apdu);
    if (key_error) {
        _unlock();
        _error(key_error, out_packet);
        return;
    }
    _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
}

static void _authenticate_wait_refresh(const USB_APDU* apdu, Packet* out_packet)
{
    _assert_unlocked();
    uint16_t key_error = _authenticate_start_confirm(apdu);
    if (key_error) {
        _unlock();
        _error(key_error, out_packet);
        return;
    }
    _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
}

static void _authenticate_continue(const USB_APDU* apdu, Packet* out_packet)
{
    uint8_t privkey[U2F_EC_KEY_SIZE];
    uint8_t nonce[U2F_NONCE_LENGTH];
    uint8_t mac[HMAC_SHA256_LEN];
    uint8_t sig[64] = {0};
    U2F_AUTHENTICATE_SIG_STR sig_base;
    uint16_t req_error = _authenticate_sanity_check_req(apdu);
    if (req_error) {
        _error(req_error, out_packet);
        return;
    }

    const U2F_AUTHENTICATE_REQ* auth_request = (const U2F_AUTHENTICATE_REQ*)apdu->data;
    async_op_result_t async_result =
        u2f_app_confirm_retry(U2F_APP_AUTHENTICATE, auth_request->appId);
    if (async_result == ASYNC_OP_NOT_READY) {
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }

    /* No more blocking operations pending for authentication. */
    _unlock();

    if (async_result == ASYNC_OP_FALSE) {
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }

    memcpy(nonce, auth_request->keyHandle + sizeof(mac), sizeof(nonce));
    if (!_keyhandle_gen(auth_request->appId, nonce, privkey, mac)) {
        _error(U2F_SW_WRONG_DATA, out_packet);
        return;
    }
    if (!MEMEQ(auth_request->keyHandle, mac, SHA256_LEN)) {
        _error(U2F_SW_WRONG_DATA, out_packet);
        return;
    }
    if (apdu->p1 == U2F_AUTH_CHECK_ONLY) {
        // success: "error:test-of-user-presense"
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }
    if (apdu->p1 != U2F_AUTH_ENFORCE) {
        _error(U2F_SW_INS_NOT_SUPPORTED, out_packet);
        return;
    }

    uint8_t buf[sizeof(U2F_AUTHENTICATE_RESP) + 2] = {0};
    U2F_AUTHENTICATE_RESP* response = (U2F_AUTHENTICATE_RESP*)&buf;

    uint32_t counter;
    if (!securechip_u2f_counter_inc(&counter)) {
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }

    response->flags = U2F_AUTH_FLAG_TUP;
    response->ctr[0] = (counter >> 24) & 0xff;
    response->ctr[1] = (counter >> 16) & 0xff;
    response->ctr[2] = (counter >> 8) & 0xff;
    response->ctr[3] = counter & 0xff;

    // Sign
    memset(&sig_base, 0, sizeof(sig_base));
    memcpy(sig_base.appId, auth_request->appId, U2F_APPID_SIZE);
    sig_base.flags = response->flags;
    memcpy(sig_base.ctr, response->ctr, 4);
    memcpy(sig_base.challenge, auth_request->challenge, U2F_NONCE_LENGTH);

    uint8_t hash[SHA256_LEN] = {0};
    wally_sha256((uint8_t*)&sig_base, sizeof(sig_base), hash, SHA256_LEN);

    if (!securechip_ecc_unsafe_sign(privkey, hash, sig)) {
        _error(U2F_SW_WRONG_DATA, out_packet);
        return;
    }

    int der_len = _sig_to_der(sig, response->sig);
    size_t auth_packet_len = sizeof(U2F_AUTHENTICATE_RESP) - U2F_MAX_EC_SIG_SIZE + der_len;

    // Append success bytes
    memcpy(buf + auth_packet_len, "\x90\x00", 2);

    _fill_message(buf, auth_packet_len + 2, out_packet);
}

static void _cmd_ping(const Packet* in_packet, Packet* out_packet, const size_t max_out_len)
{
    (void)max_out_len;

    // 0 and broadcast are reserved
    if (in_packet->cid == U2FHID_CID_BROADCAST || in_packet->cid == 0) {
        _error_hid(in_packet->cid, U2FHID_ERR_INVALID_CID, out_packet);
        return;
    }

    util_zero(out_packet->data_addr, sizeof(out_packet->data_addr));
    size_t max = MIN(in_packet->len, USB_DATA_MAX_LEN);
    memcpy(out_packet->data_addr, in_packet->data_addr, max);
    out_packet->len = in_packet->len;
    out_packet->cmd = U2FHID_PING;
    out_packet->cid = in_packet->cid;
}

static void _cmd_wink(const Packet* in_packet, Packet* out_packet, const size_t max_out_len)
{
    (void)max_out_len;

    // 0 and broadcast are reserved
    if (in_packet->cid == U2FHID_CID_BROADCAST || in_packet->cid == 0) {
        _error_hid(in_packet->cid, U2FHID_ERR_INVALID_CID, out_packet);
        return;
    }

    if (in_packet->len > 0) {
        _error_hid(in_packet->cid, U2FHID_ERR_INVALID_LEN, out_packet);
        return;
    }

    util_zero(out_packet->data_addr, sizeof(out_packet->data_addr));
    out_packet->len = 0;
    out_packet->cmd = U2FHID_WINK;
    out_packet->cid = in_packet->cid;
}

/**
 * Synchronize a channel and optionally requests a unique 32-bit channel identifier (CID)
 * that can be used by the requesting application during its lifetime.
 *
 * If the CID is the U2FHID_CID_BROADCAST then the application is requesting a CID from the device.
 * Otherwise the application has chosen the CID.
 */
static void _cmd_init(const Packet* in_packet, Packet* out_packet, const size_t max_out_len)
{
    if (U2FHID_INIT_RESP_SIZE >= max_out_len) {
        _error_hid(in_packet->cid, U2FHID_ERR_OTHER, out_packet);
        return;
    }

    // Channel 0 is reserved
    if (in_packet->cid == 0) {
        _error_hid(in_packet->cid, U2FHID_ERR_INVALID_CID, out_packet);
        return;
    }

    const U2FHID_INIT_REQ* init_req = (const U2FHID_INIT_REQ*)&in_packet->data_addr;
    U2FHID_INIT_RESP response;

    out_packet->cid = in_packet->cid;
    out_packet->cmd = U2FHID_INIT;
    out_packet->len = U2FHID_INIT_RESP_SIZE;

    util_zero(&response, sizeof(response));
    memcpy(response.nonce, init_req->nonce, sizeof(init_req->nonce));
    response.cid = in_packet->cid == U2FHID_CID_BROADCAST ? _next_cid() : in_packet->cid;
    response.versionInterface = U2FHID_IF_VERSION;
    response.versionMajor = DIGITAL_BITBOX_VERSION_MAJOR;
    response.versionMinor = DIGITAL_BITBOX_VERSION_MINOR;
    response.versionBuild = DIGITAL_BITBOX_VERSION_PATCH;
    response.capFlags = U2FHID_CAPFLAG_WINK;
    util_zero(out_packet->data_addr, sizeof(out_packet->data_addr));
    memcpy(out_packet->data_addr, &response, sizeof(response));
}

/**
 * Processes an incoming registration request.
 */
static void _cmd_register(const Packet* in_packet, Packet* out_packet)
{
    const USB_APDU* apdu = (const USB_APDU*)in_packet->data_addr;
    /* Sanity-check our state. */
    if (_state.reg != U2F_REGISTER_IDLE &&
        (_state.last_cmd != U2F_REGISTER || _state.cid != in_packet->cid)) {
        Abort("U2F reg arbitration failed.");
    }

    switch (_state.reg) {
    case U2F_REGISTER_IDLE:
        _lock(apdu);
        _register_start(apdu, out_packet);
        break;
    case U2F_REGISTER_UNLOCKING:
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        break;
    case U2F_REGISTER_WAIT_REFRESH:
        _register_wait_refresh(apdu, out_packet);
        break;
    case U2F_REGISTER_CONFIRMING:
        _register_continue(apdu, out_packet);
        break;
    default:
        Abort("Bad U2F register status");
    }
}

/**
 * Abort an existing registration request.
 */
static void _abort_register(void)
{
    switch (_state.reg) {
    case U2F_REGISTER_UNLOCKING:
        rust_workflow_abort_current();
        _clear_state();
        break;
    case U2F_REGISTER_CONFIRMING:
        u2f_app_confirm_abort();
        _clear_state();
        break;
    case U2F_REGISTER_WAIT_REFRESH:
        _stop_refresh_webpage_screen();
        _clear_state();
        break;
    default:
        Abort("Bad U2F register abort status");
    }
}

/**
 * Processes an incoming registration request.
 */
static void _cmd_authenticate(const Packet* in_packet, Packet* out_packet)
{
    const USB_APDU* apdu = (const USB_APDU*)in_packet->data_addr;
    /* Sanity-check our state. */
    if (_state.auth != U2F_AUTHENTICATE_IDLE &&
        (_state.last_cmd != U2F_AUTHENTICATE || _state.cid != in_packet->cid)) {
        Abort("U2F auth arbitration failed.");
    }

    switch (_state.auth) {
    case U2F_AUTHENTICATE_IDLE:
        _lock(apdu);
        _authenticate_start(apdu, out_packet);
        break;
    case U2F_AUTHENTICATE_UNLOCKING:
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        break;
    case U2F_AUTHENTICATE_WAIT_REFRESH:
        _authenticate_wait_refresh(apdu, out_packet);
        break;
    case U2F_AUTHENTICATE_CONFIRMING:
        _authenticate_continue(apdu, out_packet);
        break;
    default:
        Abort("Bad U2F authentication status");
    }
}

/**
 * Abort an existing authentication request.
 */
static void _abort_authenticate(void)
{
    switch (_state.auth) {
    case U2F_AUTHENTICATE_UNLOCKING:
        rust_workflow_abort_current();
        _clear_state();
        break;
    case U2F_AUTHENTICATE_CONFIRMING:
        u2f_app_confirm_abort();
        _clear_state();
        break;
    case U2F_AUTHENTICATE_WAIT_REFRESH:
        _stop_refresh_webpage_screen();
        _clear_state();
        break;
    default:
        Abort("Bad U2F register abort status");
    }
}

/**
 * Process a U2F message
 */
static void _cmd_msg(const Packet* in_packet, Packet* out_packet, const size_t max_out_len)
{
    (void)max_out_len;
    // By default always use the recieved cid
    _state.cid = in_packet->cid;

    const USB_APDU* apdu = (const USB_APDU*)in_packet->data_addr;

    if ((APDU_LEN(*apdu) + sizeof(USB_APDU)) > in_packet->len) {
        return;
    }

    if (apdu->cla != 0) {
        _error(U2F_SW_CLA_NOT_SUPPORTED, out_packet);
        return;
    }

    switch (apdu->ins) {
    case U2F_REGISTER:
        _cmd_register(in_packet, out_packet);
        break;
    case U2F_AUTHENTICATE:
        _cmd_authenticate(in_packet, out_packet);
        break;
    case U2F_VERSION:
        _version(apdu, out_packet);
        break;
    default:
        _error(U2F_SW_INS_NOT_SUPPORTED, out_packet);
        return;
    }
}

bool u2f_blocking_request_can_go_through(const Packet* in_packet)
{
    if (!_state.locked) {
        Abort("USB stack thinks we're busy, but we're not.");
    }
    /*
     * Check if this request is the same one we're currently operating on.
     * For now, this checks the request type and channel ID only.
     * FUTURE: Maybe check that the key handle is maintained between requests?
     *         so that when we're asking for confirmation, we ask to confirm
     *         "a particular key handle" instead of "a particular tab".
     */
    const USB_APDU* apdu = (const USB_APDU*)in_packet->data_addr;
    return apdu->ins == _state.last_cmd && in_packet->cid == _state.cid;
}

void u2f_blocked_req_error(Packet* out_packet, const Packet* in_packet)
{
    (void)in_packet;
    _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
}

static void _process_register_wait_unlock(void)
{
    bool unlock_result = false;
    if (rust_workflow_unlock_poll(&unlock_result)) {
        if (!unlock_result) {
            Abort("Unlock failed");
        }
        _start_refresh_webpage_screen();
        _state.reg = U2F_REGISTER_WAIT_REFRESH;
    }
}

static void _process_authenticate_wait_unlock(void)
{
    bool unlock_result = false;
    if (rust_workflow_unlock_poll(&unlock_result)) {
        if (!unlock_result) {
            Abort("Unlock failed");
        }
        _start_refresh_webpage_screen();
        _state.auth = U2F_AUTHENTICATE_WAIT_REFRESH;
    }
}

/**
 * Show the refresh page for a limited amount
 * of time. Either we receive another request
 * (firefox), or the user will refresh the
 * webpage and we need to timeout.
 */
static void _process_wait_refresh(void)
{
    if (_state.refresh_webpage_timeout == 25000) {
        _stop_refresh_webpage_screen();
        _unlock();
    } else {
        _state.refresh_webpage_timeout++;
        /* Prevent the USB watchdog from killing this workflow. */
        usb_processing_timeout_reset();
    }
}

static void _process_register(void)
{
    switch (_state.reg) {
    case U2F_REGISTER_UNLOCKING:
        _process_register_wait_unlock();
        break;
    case U2F_REGISTER_WAIT_REFRESH:
        _process_wait_refresh();
        break;
    case U2F_REGISTER_IDLE:
    case U2F_REGISTER_CONFIRMING:
        break;
    default:
        Abort("Invalid U2F process register status.");
    }
}

static void _process_authenticate(void)
{
    switch (_state.auth) {
    case U2F_AUTHENTICATE_UNLOCKING:
        _process_authenticate_wait_unlock();
        break;
    case U2F_AUTHENTICATE_WAIT_REFRESH:
        _process_wait_refresh();
        break;
    case U2F_AUTHENTICATE_IDLE:
    case U2F_AUTHENTICATE_CONFIRMING:
        break;
    default:
        Abort("Invalid U2F process auth status.");
    }
}

void u2f_process(void)
{
    if (!_state.locked) {
        return;
    }
    switch (_state.last_cmd) {
    case U2F_REGISTER:
        _process_register();
        break;
    case U2F_AUTHENTICATE:
        _process_authenticate();
        break;
    default:
        Abort("Bad U2F process state.");
    }
}

/**
 * Set up the U2F commands.
 */
void u2f_device_setup(void)
{
    const CMD_Callback u2f_cmd_callbacks[] = {
        {U2FHID_PING, _cmd_ping},
        {U2FHID_WINK, _cmd_wink},
        {U2FHID_INIT, _cmd_init},
        {U2FHID_MSG, _cmd_msg},
    };
    usb_processing_register_cmds(
        usb_processing_u2f(), u2f_cmd_callbacks, sizeof(u2f_cmd_callbacks) / sizeof(CMD_Callback));
}

void u2f_abort_outstanding_op(void)
{
    if (!_state.locked) {
        Abort("USB stack thinks U2F is busy, but it's not.");
    }
    switch (_state.last_cmd) {
    case U2F_REGISTER:
        _abort_register();
        break;
    case U2F_AUTHENTICATE:
        _abort_authenticate();
        break;
    default:
        Abort("Invalid U2F status on abort.");
    }
}

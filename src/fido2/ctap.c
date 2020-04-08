// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ctap.h"

#include "cbor.h"
#include "cose_key.h"
#include "ctaphid.h"
#include "ctap_parse.h"
#include "device.h"
#include "extensions.h"
#include "fido2_keys.h"
#include "storage.h"

#include <memory/memory.h>
#include <crypto/sha2/sha256.h>
#include <screen.h>
#include <securechip/securechip.h>
#include <ui/workflow_stack.h>
#include <usb/usb_packet.h>
#include <util.h>
#include <workflow/confirm.h>
#include <workflow/select_ctap_credential.h>
#include <workflow/status.h>
#include <workflow/unlock.h>

/**
 * CTAP request codes.
 */
#define CTAP_REQ_MAKE_CREDENTIAL (0x01)
#define CTAP_REQ_GET_ASSERTION   (0x02)
#define CTAP_REQ_CANCEL          (0x03)
#define CTAP_REQ_GET_INFO        (0x04)
#define CTAP_REQ_CLIENT_PIN      (0x06)
#define CTAP_REQ_RESET           (0x07)
#define CTAP_REQ_GET_NEXT_ASSERTION   (0x08)
#define CTAP_REQ_VENDOR_FIRST    (0x40)
#define CTAP_REQ_VENDOR_LAST     (0xBF)

/**
 * Auth data flags, defined in [WebAuthn] sec. 6.1. Authenticator Data.
 */
/**
 * User is present/not present.
 */
#define CTAP_AUTH_DATA_FLAG_USER_PRESENT (1 << 0)
/**
 * User is verified/not verified.
 */
#define CTAP_AUTH_DATA_FLAG_USER_VERIFIED (1 << 2)
/**
 * Indicates whether the authenticator added attested credential data.
 */
#define CTAP_AUTH_DATA_FLAG_ATTESTED_CRED_DATA_INCLUDED (1 << 6)
/**
 * Indicates if the authenticator data has extensions.
 */
#define CTAP_AUTH_DATA_FLAG_EXTENSION_DATA_INCLUDED (1 << 7)

/**
 * Response tags.
 */
#define CTAP_RESP_VERSIONS (0x1)
#define CTAP_RESP_EXTENSIONS (0x2)
#define CTAP_RESP_AAGUID (0x3)
#define CTAP_RESP_OPTIONS (0x4)
#define CTAP_RESP_MAX_MSG_SIZE (0x5)
#define CTAP_RESP_PIN_PROTOCOLS (0x6)

#define CTAP_RESP_FMT (0x01)
#define CTAP_RESP_AUTH_DATA (0x02)
#define CTAP_RESP_ATT_STMT (0x03)

#define CTAP_RESP_CREDENTIAL (0x01)
#define CTAP_RESP_SIGNATURE (0x03)
#define CTAP_RESP_PUBKEY_CREDENTIAL_USER_ENTITY (0x04)
#define CTAP_RESP_NUM_CREDENTIALS (0x05)

#define CTAP_RESP_KEY_AGREEMENT (0x01)
#define CTAP_RESP_PIN_TOKEN (0x02)
#define CTAP_RESP_RETRIES (0x03)


typedef struct {
    enum {
        CTAP_MAKE_CREDENTIAL_STARTED,
        CTAP_MAKE_CREDENTIAL_UNLOCKED,
        CTAP_MAKE_CREDENTIAL_WAIT_CONFIRM,
        CTAP_MAKE_CREDENTIAL_FINISHED,
        CTAP_MAKE_CREDENTIAL_FAILED,
    } state;
    ctap_make_credential_req_t req;
} ctap_make_credential_state_t;

typedef struct {
    enum {
        CTAP_GET_ASSERTION_STARTED,
        CTAP_GET_ASSERTION_UNLOCKED,
        CTAP_GET_ASSERTION_WAIT_CONFIRM,
        CTAP_GET_ASSERTION_CONFIRMED,
        CTAP_GET_ASSERTION_SELECT_CREDENTIAL,
        CTAP_GET_ASSERTION_SELECTED_CREDENTIAL,
        /** User aborted the request */
        CTAP_GET_ASSERTION_DENIED,
        /** No valid credentials were found. */
        CTAP_GET_ASSERTION_NO_CREDENTIALS,
        CTAP_GET_ASSERTION_FINISHED,
    } state;
    /** Key handle that was selected for authentication. */
    u2f_keyhandle_t auth_credential;
    /** Private key corresponding to auth_credential. */
    uint8_t auth_privkey[HMAC_SHA256_LEN];
    /** User ID corresponding to auth_credential.
     *
     * When no allow list is present, it's mandatory that
     * we add a user ID to the credential we return.
     */
    uint8_t user_id[CTAP_USER_ID_MAX_SIZE];
    /** Actual size of the user ID. */
    size_t user_id_size;
    /**
     * List of valid credentials for this GA request.
     */
    ctap_credential_display_list_t cred_list;
    /**
     * For each credential in cred_list, save the index
     * that that credential has in the RK memory.
     */
    int cred_idx[CTAP_CREDENTIAL_LIST_MAX_SIZE];
    ctap_get_assertion_req_t req;
} ctap_get_assertion_state_t;

static struct {
    enum {
        CTAP_BLOCKING_OP_NONE,
        CTAP_BLOCKING_OP_MAKE_CRED,
        CTAP_BLOCKING_OP_GET_ASSERTION
    } blocking_op;
    union {
        ctap_make_credential_state_t make_cred;
        ctap_get_assertion_state_t get_assertion;
    } data;
} _state = {0};

static uint8_t ctap_get_info(CborEncoder * encoder)
{
    (void)_state;
    int ret;
    CborEncoder array;
    CborEncoder map;
    CborEncoder options;
    CborEncoder pins;
    uint8_t aaguid[16];
    device_read_aaguid(aaguid);

    ret = cbor_encoder_create_map(encoder, &map, 6);
    check_ret(ret);
    {
        ret = cbor_encode_uint(&map, CTAP_RESP_VERSIONS);     //  versions key
        check_ret(ret);
        {
            ret = cbor_encoder_create_array(&map, &array, 2);
            check_ret(ret);
            {
                ret = cbor_encode_text_stringz(&array, "U2F_V2");
                check_ret(ret);
                ret = cbor_encode_text_stringz(&array, "FIDO_2_0");
                check_ret(ret);
            }
            ret = cbor_encoder_close_container(&map, &array);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, CTAP_RESP_EXTENSIONS);
        check_ret(ret);
        {
            ret = cbor_encoder_create_array(&map, &array, 1);
            check_ret(ret);
            {
                ret = cbor_encode_text_stringz(&array, "hmac-secret");
                check_ret(ret);
            }
            ret = cbor_encoder_close_container(&map, &array);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, CTAP_RESP_AAGUID);
        check_ret(ret);
        {
            ret = cbor_encode_byte_string(&map, aaguid, 16);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, CTAP_RESP_OPTIONS);
        check_ret(ret);
        {
            ret = cbor_encoder_create_map(&map, &options, 4);
            check_ret(ret);
            {
                ret = cbor_encode_text_string(&options, "rk", 2);
                check_ret(ret);
                {
                    ret = cbor_encode_boolean(&options, 1);     // Capable of storing keys locally
                    check_ret(ret);
                }

                ret = cbor_encode_text_string(&options, "up", 2);
                check_ret(ret);
                {
                    ret = cbor_encode_boolean(&options, 1);     // Capable of testing user presence
                    check_ret(ret);
                }

                ret = cbor_encode_text_string(&options, "uv", 2); // Capable of verifying user
                check_ret(ret);
                {
                    /*
                     * The option should be true/false based on whether the UV function has already
                     * been initialized.
                     */
                    ret = cbor_encode_boolean(&options, true);
                    check_ret(ret);
                }

                ret = cbor_encode_text_string(&options, "plat", 4);
                check_ret(ret);
                {
                    ret = cbor_encode_boolean(&options, 0);     // Not attached to platform
                    check_ret(ret);
                }
                /*
                 * We're not capable of PIN authentication, so the clientPin option
                 * should be unset.
                 */
            }
            ret = cbor_encoder_close_container(&map, &options);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, CTAP_RESP_MAX_MSG_SIZE);
        check_ret(ret);
        {
            ret = cbor_encode_int(&map, CTAP_MAX_MESSAGE_SIZE);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, CTAP_RESP_PIN_PROTOCOLS);
        check_ret(ret);
        {
            ret = cbor_encoder_create_array(&map, &pins, 1);
            check_ret(ret);
            {
                ret = cbor_encode_int(&pins, 1);
                check_ret(ret);
            }
            ret = cbor_encoder_close_container(&map, &pins);
            check_ret(ret);
        }
    }
    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);

    return CTAP1_ERR_SUCCESS;
}



static int ctap_add_cose_key(CborEncoder* cose_key, uint8_t* x, uint8_t* y, int32_t algtype)
{
    int ret;
    CborEncoder map;

    ret = cbor_encoder_create_map(cose_key, &map, 5);
    check_ret(ret);


    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_KTY);
        check_ret(ret);
        ret = cbor_encode_int(&map, COSE_KEY_KTY_EC2);
        check_ret(ret);
    }

    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_ALG);
        check_ret(ret);
        ret = cbor_encode_int(&map, algtype);
        check_ret(ret);
    }

    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_CRV);
        check_ret(ret);
        ret = cbor_encode_int(&map, COSE_KEY_CRV_P256);
        check_ret(ret);
    }


    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_X);
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, x, 32);
        check_ret(ret);
    }

    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_Y);
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, y, 32);
        check_ret(ret);
    }

    ret = cbor_encoder_close_container(cose_key, &map);
    check_ret(ret);

    return 0;
}

/**
 * Encode the 32bit U2F counter value as a big-endian
 * sequence of bytes.
 * @param counter Counter to encode.
 * @param buf_out Buffer in which to encode the counter. Must be 4 bytes wide.
 */
static void _encode_u2f_counter(uint32_t counter, uint8_t* buf_out)
{
    *buf_out++ = (counter >> 24) & 0xff;
    *buf_out++ = (counter >> 16) & 0xff;
    *buf_out++ = (counter >> 8) & 0xff;
    *buf_out++ = (counter >> 0) & 0xff;
}

/**
 * Copy the source string into the destination buffer.
 * If the string is too long to fit the destination buffer,
 * truncate the string with "...", so that the resulting
 * string is always a valid NULL-terminated string.
 */
static void _copy_or_truncate(char* dst, size_t dst_size, const char* src)
{
    size_t src_size = strlen(src);
    bool truncate = false;

    const char* padding = "...";
    size_t padding_size = strlen(padding);

    if (dst_size < src_size + 1) {
        /*
         * String is too long.
         * Truncate the source string to the biggest possible size.
         */
        truncate = true;
        src_size = dst_size - 1 - padding_size;
    }
    strncpy(dst, src, src_size);
    if (!truncate) {
        dst[src_size] = '\0';
    } else {
        strcpy(dst + src_size, padding);
        dst[src_size + padding_size] = '\0';
    }
}

static int _is_matching_rk(ctap_resident_key_t* rk, ctap_resident_key_t* rk2)
{
    return (memcmp(rk->rp_id_hash, rk2->rp_id_hash, 32) == 0) &&
            (memcmp(rk->rp_id, rk2->rp_id, CTAP_STORAGE_RP_ID_MAX_SIZE) == 0) &&
            (memcmp(rk->user_name, rk2->user_name, CTAP_STORAGE_USER_NAME_LIMIT) == 0);
}

static void _get_assertion_unlock_cb(bool result, void* param) {
    (void)param;
    if (!result) {
        /*
         * User didn't authenticate.
         * Let's count this as a "user denied" error.
         */
        _state.data.get_assertion.state = CTAP_GET_ASSERTION_DENIED;
        return;
    }
    _state.data.get_assertion.state = CTAP_GET_ASSERTION_UNLOCKED;
}

static void _get_assertion_allow_cb(bool result, void* param)
{
    (void)param;
    ctap_get_assertion_state_t* state = &_state.data.get_assertion;
    if (result) {
        state->state = CTAP_GET_ASSERTION_CONFIRMED;
    } else {
        state->state = CTAP_GET_ASSERTION_DENIED;
    }
}

static workflow_t* _get_assertion_confirm(ctap_rp_id_t* rp)
{
    char prompt_buf[100];
    size_t prompt_size;
    if (rp->name && rp->name[0] != '\0') {
        /* There is a human-readable name attached to this domain. */
        prompt_size = snprintf(prompt_buf, 100, "Authenticate on\n%s\n(%.*s)\nsize %u",
                               rp->name, (int)rp->size, rp->id, sizeof(_state));
    } else {
        prompt_size = snprintf(prompt_buf, 100, "Authenticate on\n%.*s\nsize %u",
                               (int)rp->size, rp->id, sizeof(_state));
    }
    if (prompt_size >= 100) {
        prompt_buf[99] = '\0';
    }

    const confirm_params_t params = {
        .title = "FIDO2",
        .body = prompt_buf,
        .scrollable = false,
    };
    return workflow_confirm(&params, _get_assertion_allow_cb, NULL);
}

/**
 * @param sig[in] Location to deposit signature (must be 64 bytes)
 * @param out_encoded_sig[in] Location to deposit der signature (must be 72 bytes)
 * @return Length of DER encoded signature.
 * // FIXME add tests for maximum and minimum length of the input and output
 */
static int _encode_der_sig(const uint8_t* sig, uint8_t* out_encoded_sig)
{
    // Need to caress into dumb der format ..
    uint8_t lead_s = 0;  // leading zeros
    uint8_t lead_r = 0;
    for (int i=0; i < 32; i++) {
        if (sig[i] == 0) {
            lead_r++;
        }
        else {
            break;
        }
    }

    for (int i=0; i < 32; i++) {
        if (sig[i+32] == 0) {
            lead_s++;
        }
        else {
            break;
        }
    }

    int8_t pad_s = ((sig[32 + lead_s] & 0x80) == 0x80);
    int8_t pad_r = ((sig[0 + lead_r] & 0x80) == 0x80);

    memset(out_encoded_sig, 0, 72);
    out_encoded_sig[0] = 0x30;
    out_encoded_sig[1] = 0x44 + pad_s + pad_r - lead_s - lead_r;

    // R ingredient
    out_encoded_sig[2] = 0x02;
    out_encoded_sig[3 + pad_r] = 0;
    out_encoded_sig[3] = 0x20 + pad_r - lead_r;
    memmove(out_encoded_sig + 4 + pad_r, sig + lead_r, 32u - lead_r);

    // S ingredient
    out_encoded_sig[4 + 32 + pad_r - lead_r] = 0x02;
    out_encoded_sig[5 + 32 + pad_r + pad_s - lead_r] = 0;
    out_encoded_sig[5 + 32 + pad_r - lead_r] = 0x20 + pad_s - lead_s;
    memmove(out_encoded_sig + 6 + 32 + pad_r + pad_s - lead_r, sig + 32u + lead_s, 32u - lead_s);

    return 0x46 + pad_s + pad_r - lead_r - lead_s;
}

/**
 * Computes the EC256 
 * See [WebAuthn], 8.2 "Signing procedure"
 * require load_key prior to this
 * @param[in] auth_data Authenticator data for the attestation.
 * @param[in] auth_data_len Length of auth_data.
 * @param[in] client_data_hash Hash of the serialized client data.
 * @param[out] sigbuf_out Buffer in which to store the computed signature
 */
static bool _calculate_signature(const uint8_t* privkey, uint8_t* auth_data, size_t auth_data_len, uint8_t* client_data_hash, uint8_t* sigbuf_out)
{
    uint8_t hash_buf[SHA256_LEN];

    sha256_context_t ctx;
    sha256_reset(&ctx);
    noise_sha256_update(&ctx, auth_data, auth_data_len);
    noise_sha256_update(&ctx, client_data_hash, CLIENT_DATA_HASH_SIZE);
    sha256_finish(&ctx, hash_buf);
    if (!securechip_ecc_unsafe_sign(privkey, hash_buf, sigbuf_out)) {
        return false;
    }
    return true;
}

/**
 * Adds the encoding of an attestation statement into a CBOR encoder.
 *
 * @param map[in] Encoder in which to append the attestation statement.
 * @param signature[in] Signature to add to the statement.
 * @param len[in] Length of signature.
 * @return Error code (or 0 for success).
 */
static uint8_t _add_attest_statement(CborEncoder* map, const uint8_t* signature, int len)
{
    int ret;
    /* TODO: simo: generate another cert? */
    const uint8_t *cert = FIDO2_ATT_CERT;
    uint16_t cert_size = FIDO2_ATT_CERT_SIZE;

    CborEncoder stmtmap;
    CborEncoder x5carr;

    ret = cbor_encode_int(map, CTAP_RESP_ATT_STMT);
    check_ret(ret);
    ret = cbor_encoder_create_map(map, &stmtmap, 3);
    check_ret(ret);
    {
        ret = cbor_encode_text_stringz(&stmtmap,"alg");
        check_ret(ret);
        ret = cbor_encode_int(&stmtmap, COSE_ALG_ES256);
        check_ret(ret);
    }
    {
        ret = cbor_encode_text_stringz(&stmtmap,"sig");
        check_ret(ret);
        ret = cbor_encode_byte_string(&stmtmap, signature, len);
        check_ret(ret);
    }
    {
        ret = cbor_encode_text_stringz(&stmtmap,"x5c");
        check_ret(ret);
        ret = cbor_encoder_create_array(&stmtmap, &x5carr, 1);
        check_ret(ret);
        {
            ret = cbor_encode_byte_string(&x5carr, cert, cert_size);
            check_ret(ret);
            ret = cbor_encoder_close_container(&stmtmap, &x5carr);
            check_ret(ret);
        }
    }

    ret = cbor_encoder_close_container(map, &stmtmap);
    check_ret(ret);
    return 0;
}

/**
 * Computes the sha256 hash of the given RP id.
 * @param rp_hash_out Buffer in which to store the computed hash.
 *                    Must be SHA256_LEN bytes wide.
 */
static void _compute_rpid_hash(ctap_rp_id_t* rp, uint8_t* rp_hash_out) {
    if (wally_sha256(rp->id, rp->size, rp_hash_out, SHA256_LEN) != WALLY_OK) {
        Abort("wally_sha256 failed");
    }
}


/**
 * Asks the user for confirmation when
 * a stored FIDO2 credential is about
 * to be overwritten with a new one for
 * the same user.
 */
static bool _confirm_overwrite_credential(void) {
    /* TODO */
    return true;
}

/**
 * Check if any of the keys in a MakeCredential's
 * exclude_list belong to our device.
 *
 * @param req MakeCredential request to analyze.
 * @return Verification status:
 *             - 0 if no invalid key was found;
 *             - CTAP2_ERR_CREDENTIAL_EXCLUDED if an excluded key belongs to us;
 *             - other errors if we failed to parse the exclude list.
 */
static uint8_t _verify_exclude_list(ctap_make_credential_req_t* req)
{
    for (size_t i = 0; i < req->exclude_list_size; i++) {
        u2f_keyhandle_t excl_cred;
        bool cred_valid;
        uint8_t ret = ctap_parse_credential_descriptor(&req->exclude_list, &excl_cred, &cred_valid);
        if (!cred_valid || ret == CTAP2_ERR_CBOR_UNEXPECTED_TYPE) {
            /* Skip credentials that fail to parse. */
            continue;
        }
        if (ret != CborNoError) {
            return ret;
        }

        uint8_t privkey[HMAC_SHA256_LEN];
        UTIL_CLEANUP_32(privkey);
        bool key_is_ours = u2f_keyhandle_verify(req->rp.id, (uint8_t*)&excl_cred, sizeof(excl_cred), privkey);
        if (key_is_ours)
        {
            return true;
        }

        ret = cbor_value_advance(&req->exclude_list);
        check_ret(ret);
    }
    return false;
}

static bool _ask_generic_authorization(void) {
    const confirm_params_t params = {
        .title = "FIDO2",
        .body = "Proceed?",
    };
    return workflow_confirm_blocking(&params);
}

/**
 * Called after the user has confirmed (or declined) the
 * creation of a new credential.
 */
static void _make_credential_allow_cb(bool result, void* param) {
    (void)param;
    if (result) {
        _state.data.make_cred.state = CTAP_MAKE_CREDENTIAL_FINISHED;
    } else {
        _state.data.make_cred.state = CTAP_MAKE_CREDENTIAL_FAILED;
    }
}

/**
 * Asks the user whether he wants to proceed
 * with the creation of a new credential.
 * @param req MakeCredential CTAP request.
 * @return Confirmation workflow.
 */
static workflow_t* _make_credential_allow(ctap_make_credential_req_t* req)
{
    char prompt_buf[100];
    size_t prompt_size;
    if (req->rp.name && req->rp.name[0] != '\0') {
        /* There is a human-readable name attached to this domain. */
        prompt_size = snprintf(prompt_buf, 100, "Create credential for\n%s\n(%.*s)\n",
                               req->rp.name, (int)req->rp.size, req->rp.id);
    } else {
        prompt_size = snprintf(prompt_buf, 100, "Create credential for\n%.*s\n",
                               (int)req->rp.size, req->rp.id);
    }
    if (prompt_size >= 100) {
        prompt_buf[99] = '\0';
    }
    const confirm_params_t params = {
        .title = "FIDO2",
        .body = prompt_buf,
    };
    return workflow_confirm(&params, _make_credential_allow_cb, NULL);
}

static void _make_credential_unlock_cb(bool result, void* param) {
    (void)param;
    //screen_sprintf_debug(1000, "UNLOCK CB %d", result);
    if (!result) {
        /*
         * User didn't authenticate.
         * Let's count this as a "user denied" error.
         */
        _state.data.make_cred.state = CTAP_MAKE_CREDENTIAL_FAILED;
        return;
    }
    _state.data.make_cred.state = CTAP_MAKE_CREDENTIAL_UNLOCKED;
}

static void _make_credential_init_state(ctap_make_credential_req_t* req)
{
    _state.data.make_cred.state = CTAP_MAKE_CREDENTIAL_STARTED;
    memcpy(&_state.data.make_cred.req, req, sizeof(*req));
}

static void _make_credential_free_state(void)
{
}

static uint8_t ctap_make_credential(CborEncoder * encoder, const in_buffer_t* in_buffer) {
    ctap_make_credential_req_t MC;
    int ret;

    ret = ctap_parse_make_credential(&MC,encoder, in_buffer);

    if (ret != 0) {
        return ret;
    }
    if (MC.pin_auth_empty) {
        /*
         * pin_auth was present and was an empty string.
         * The client is asking us if we support pin
         * (and asks to check for user presence before we move on).
         */
        bool result = _ask_generic_authorization();
        if (!result) {
            return CTAP2_ERR_OPERATION_DENIED;
        }
        /* We don't support PIN semantics. */
        return CTAP2_ERR_PIN_NOT_SET;
    }

    if (MC.pin_auth_present) {
        /* We don't support pin_auth. */
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

    if (MC.up == 1 || MC.up == 0) {
        /*
         * The UP flag can't be set for authenticatorMakeCredential.
         * It must always be unset (0xFF).
         */
        return CTAP2_ERR_INVALID_OPTION;
    }

    _make_credential_init_state(&MC);
    workflow_stack_start_workflow(workflow_unlock(_make_credential_unlock_cb, NULL));
    return CTAP1_ERR_SUCCESS;
}

/**
 * Generates a new credential in response to a MakeCredential request.
 * Only called when the user has already accepted and identified with the device.
 *
 * @return CTAP status code.
 */

static int _make_credential_complete(buffer_t* out_buf)
{
    ctap_make_credential_state_t* state = &_state.data.make_cred;
    /*
     * The exclude list contains a list of credentials that we
     * must check. If any credential was generated by our device,
     * we must return with an error. This allows the server to avoid
     * us creating more than one credential for the same user/device pair.
     */
    int ret = _verify_exclude_list(&state->req);
    if (ret != CborNoError) {
        return CTAP2_ERR_CBOR_PARSING;
    }

    /* Update the U2F counter. */
    uint32_t u2f_counter;
    if (!securechip_u2f_counter_inc(&u2f_counter)) {
        workflow_status_blocking("Failed to create key.", false);
        return CTAP2_ERR_OPERATION_DENIED;
    }

    ctap_auth_data_t auth_data;
    _compute_rpid_hash(&state->req.rp, auth_data.head.rp_id_hash);

    /* Generate the key. */
    memset((uint8_t*)&auth_data.attest.id, 0, sizeof(u2f_keyhandle_t));
    uint8_t* nonce = auth_data.attest.id.nonce;
    uint8_t* mac = auth_data.attest.id.mac;
    uint8_t pubkey[64];
    uint8_t privkey[HMAC_SHA256_LEN];
    UTIL_CLEANUP_32(privkey);
    bool key_create_success = u2f_keyhandle_create_key(state->req.rp.id, nonce, privkey, mac, pubkey);
    if (!key_create_success) {
        /* TODO: simo: do something. */
        Abort("Failed to create new FIDO2 key.");
    }

    /*
     * Find where to store this key.
     * If it's new, store it in the first
     * available location. Otherwise, overwrite
     * the existing key (after confirming with the user).
     */
    if (state->req.cred_info.rk) {
        ctap_resident_key_t rk_to_store;
        memset(&rk_to_store, 0, sizeof(rk_to_store));
        memcpy(&rk_to_store.key_handle, &auth_data.attest.id, sizeof(rk_to_store.key_handle));
        memcpy(&rk_to_store.rp_id_hash, auth_data.head.rp_id_hash, sizeof(auth_data.head.rp_id_hash));
        _copy_or_truncate((char*)rk_to_store.rp_id, sizeof(rk_to_store.rp_id), (const char*)state->req.rp.id);
        _copy_or_truncate((char*)rk_to_store.user_name, sizeof(rk_to_store.user_name), (const char*)state->req.cred_info.user.name);
        _copy_or_truncate((char*)rk_to_store.display_name, sizeof(rk_to_store.display_name), (const char*)state->req.cred_info.user.display_name);
        rk_to_store.valid = CTAP_RESIDENT_KEY_VALID;
        rk_to_store.creation_time = u2f_counter;
        if (state->req.cred_info.user.id_size > CTAP_USER_ID_MAX_SIZE) {
            /* We can't store such a big user ID.
             * But we can't even truncate it... So nothing we can do, alas.
             */
            return CTAP2_ERR_REQUEST_TOO_LARGE;
        }
        //screen_sprintf_debug(2000, "UID (%u): %02x%02x",
        //state->req.cred_info.user.id_size,
        //state->req.cred_info.user.id[0], state->req.cred_info.user.id[state->req.cred_info.user.id_size - 1]
        //);
        rk_to_store.user_id_size = state->req.cred_info.user.id_size;
        memcpy(rk_to_store.user_id, state->req.cred_info.user.id, state->req.cred_info.user.id_size);

        int store_location = 0;
        bool must_overwrite = false;
        bool free_spot_found = false;

        for (int i = 0; i < MEMORY_CTAP_RESIDENT_KEYS_MAX; i++) {
            /* Check if we want to overwrite */
            ctap_resident_key_t this_key;
            bool mem_result = memory_get_ctap_resident_key(i, &this_key);
            if (!mem_result) {
                /* Skip on error */
                continue;
            }
            if (this_key.valid != CTAP_RESIDENT_KEY_VALID) {
                /* Skip invalid keys, mark spot as free */
                if (!free_spot_found) {
                    store_location = i;
                    free_spot_found = true;
                }
                continue;
            }
            if (_is_matching_rk(&rk_to_store, &this_key)) {
                /* Found a matching key. Need to overwrite. */
                free_spot_found = true;
                must_overwrite = true;
                store_location = i;
                break;
            }
        }
        if (!free_spot_found) {
            workflow_status_blocking("Out of memory for resident keys", false);
            return CTAP2_ERR_KEY_STORE_FULL;
        }
        if (must_overwrite) {
            if (!_confirm_overwrite_credential()) {
                workflow_status_blocking("Operation cancelled", false);
                return CTAP2_ERR_OPERATION_DENIED;
            }
        }
        memory_store_ctap_resident_key(store_location, &rk_to_store);
        //screen_sprintf_debug(500, "Stored key #%d\n", store_location);
        //uint8_t* cred_raw = (uint8_t*)&rk_to_store.key_handle;
        //screen_sprintf_debug(3000, "KH: %02x..%02x",
        //cred_raw[0], cred_raw[15]);
    } else {
        //screen_print_debug("Not stored key\n", 500);
    }

    /*
     * Now create the response.
     * This is an attestation object, as defined
     * in [WebAuthn], 6.4 (Figure 5).
     */
    CborEncoder encoder;
    CborEncoder attest_obj;
    memset(&encoder,0,sizeof(CborEncoder));
    cbor_encoder_init(&encoder, out_buf->data, out_buf->max_len, 0);
    ret = cbor_encoder_create_map(&encoder, &attest_obj, 3);
    check_ret(ret);

    /*
     * First comes the Authenticator Data.
     * (Note: the rpId has already been stored at the start of auth_data...)
     */
    auth_data.head.flags = CTAP_AUTH_DATA_FLAG_ATTESTED_CRED_DATA_INCLUDED |
        CTAP_AUTH_DATA_FLAG_USER_VERIFIED | CTAP_AUTH_DATA_FLAG_USER_PRESENT;

    _encode_u2f_counter(u2f_counter, (uint8_t*)&auth_data.head.signCount);

    device_read_aaguid(auth_data.attest.aaguid);
 
    /* Encode the length of the key handle in big endian. */
    uint16_t key_length = sizeof(u2f_keyhandle_t);
    auth_data.attest.cred_len[0] = (key_length & 0xFF00) >> 8;
    auth_data.attest.cred_len[1] =  (key_length & 0x00FF);

    CborEncoder cose_key;
    uint8_t* cose_key_buf = auth_data.other;
    cbor_encoder_init(&cose_key, cose_key_buf, sizeof(auth_data.other), 0);
    ret = ctap_add_cose_key(&cose_key, pubkey, pubkey + 32, COSE_ALG_ES256);
    if (ret != CborNoError) {
        return ret;
    }
    size_t cose_key_len = cbor_encoder_get_buffer_size(&cose_key, cose_key_buf);
    size_t actual_auth_data_len = sizeof(auth_data) - sizeof(auth_data.other) + cose_key_len;

    /* FUTURE: manage extensions if we want to. */

    /*
     * 3 fields in an attestation object:
     * - fmt
     * - authData
     * - attStmt
     */
    {
        ret = cbor_encode_int(&attest_obj, CTAP_RESP_FMT);
        check_ret(ret);
        ret = cbor_encode_text_stringz(&attest_obj, "packed");
        check_ret(ret);
    }


    {
        ret = cbor_encode_int(&attest_obj, CTAP_RESP_AUTH_DATA);
        check_ret(ret);
        ret = cbor_encode_byte_string(&attest_obj, (uint8_t*)&auth_data, actual_auth_data_len);
        check_ret(ret);
    }

    /* Compute the attestation statement. */
    uint8_t sigbuf[32];
    bool sig_success = _calculate_signature(FIDO2_ATT_PRIV_KEY, (uint8_t*)&auth_data, actual_auth_data_len, state->req.client_data_hash, sigbuf);
    if (!sig_success) {
        return CTAP1_ERR_OTHER;
    }
    uint8_t attest_signature[72];
    int attest_sig_size = _encode_der_sig(sigbuf, attest_signature);

    ret = _add_attest_statement(&attest_obj, attest_signature, attest_sig_size);
    if (ret != CborNoError) {
        return ret;
    }

    ret = cbor_encoder_close_container(&encoder, &attest_obj);
    check_ret(ret);
    //workflow_status_create("Registration\ncompleted.", true);
    out_buf->len = cbor_encoder_get_buffer_size(&encoder, out_buf->data);
    return CTAP1_ERR_SUCCESS;
}

static ctap_request_result_t _make_credential_continue(buffer_t* out_buf) {
    ctap_request_result_t result = {.status = 0, .request_completed = true};
    ctap_make_credential_state_t* state = &_state.data.make_cred;

    switch (state->state) {
        case CTAP_MAKE_CREDENTIAL_UNLOCKED:
            /*
            * Request permission to the user.
            * This must be done before checking for excluded credentials etc.
            * so that we don't reveal the existance of credentials without
            * the user's consent.
            */
            workflow_stack_start_workflow(_make_credential_allow(&_state.data.make_cred.req));
            state->state = CTAP_MAKE_CREDENTIAL_WAIT_CONFIRM;
            result.request_completed = false;
            return result;
        case CTAP_MAKE_CREDENTIAL_FINISHED:
            result.status = _make_credential_complete(out_buf);
            return result;
        case CTAP_MAKE_CREDENTIAL_FAILED:
            workflow_status_blocking("Operation cancelled", false);
            result.status = CTAP2_ERR_OPERATION_DENIED;
            return result;
        case CTAP_MAKE_CREDENTIAL_STARTED:
        case CTAP_MAKE_CREDENTIAL_WAIT_CONFIRM:
            result.request_completed = false;
            return result;
        default:
            Abort("Invalid make_credential state");
    }
}

static uint8_t ctap_add_credential_descriptor(CborEncoder* map, u2f_keyhandle_t* key_handle)
{
    CborEncoder desc;
    int ret = cbor_encode_int(map, CTAP_RESP_CREDENTIAL);
    check_ret(ret);

    ret = cbor_encoder_create_map(map, &desc, 2);
    check_ret(ret);

    {
        ret = cbor_encode_text_string(&desc, "id", 2);
        check_ret(ret);

        ret = cbor_encode_byte_string(&desc, (uint8_t*)key_handle,
                sizeof(*key_handle));
        check_ret(ret);
    }

    {
        ret = cbor_encode_text_string(&desc, "type", 4);
        check_ret(ret);

        ret = cbor_encode_text_string(&desc, "public-key", 10);
        check_ret(ret);
    }


    ret = cbor_encoder_close_container(map, &desc);
    check_ret(ret);

    return 0;
}

/**
 * Comparator function used to qsort() the credentials.
 * @return >0 if b is more recent than a, 0 if they have the same age (should never happen!),
 *         <0 otherwise.
 */
static int _compare_display_credentials(const void * _a, const void * _b)
{
    const ctap_credential_display_t* a = (const ctap_credential_display_t* )_a;
    const ctap_credential_display_t* b = (const ctap_credential_display_t* )_b;
    return b->creation_time - a->creation_time;
}

/**
 * Adds the "publickKeyCredentialUserEntity" field to a CBOR
 * object, containing the specified user id as its only field.
 *
 * @param user_id must be at least user_id_size wide.
 * @param user_id_size Length of user_id.
 */
static uint8_t _encode_user_id(CborEncoder* map, const uint8_t* user_id, size_t user_id_size)
{
    CborEncoder entity;
    int ret = cbor_encode_int(map, CTAP_RESP_PUBKEY_CREDENTIAL_USER_ENTITY);
    check_ret(ret);

    ret = cbor_encoder_create_map(map, &entity, 1);
    check_ret(ret);

    {
        ret = cbor_encode_text_string(&entity, "id", 2);
        check_ret(ret);

        ret = cbor_encode_byte_string(&entity, user_id, user_id_size);
        check_ret(ret);
    }

    ret = cbor_encoder_close_container(map, &entity);
    check_ret(ret);

    return 0;
}

/**
 * Fills a getAssertion response, as defined in the FIDO2 specs, 5.2.
 *
 * The response map contains: 
 *    - Credential descriptor
 *    - Auth data
 *    - Signature
 *    - User ID (if present)
 *
 * Note that we don't include any user data as there is no need for that
 * (the user has already been selected on the device).
 */
static uint8_t ctap_end_get_assertion(CborEncoder* encoder, u2f_keyhandle_t* key_handle, uint8_t* auth_data_buf, unsigned int auth_data_buf_sz, uint8_t* privkey, uint8_t* client_data_hash, const uint8_t* user_id, size_t user_id_size)
{
    int ret;
    uint8_t signature[64];
    uint8_t encoded_sig[72];
    int encoded_sig_size;

    CborEncoder map;
    int map_size = 3;
    if (user_id_size) {
        map_size++;
    }
    
    ret = cbor_encoder_create_map(encoder, &map, map_size);
    check_ret(ret);

    ret = ctap_add_credential_descriptor(&map, key_handle);  // 1
    if (ret != CborNoError) {
        return ret;
    }

    {
        ret = cbor_encode_int(&map, CTAP_RESP_AUTH_DATA);  // 2
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, auth_data_buf, auth_data_buf_sz);
        check_ret(ret);
    }

    bool sig_success = _calculate_signature(privkey, auth_data_buf, auth_data_buf_sz, client_data_hash, signature);
    if (!sig_success) {
        return CTAP1_ERR_OTHER;
    }
    encoded_sig_size = _encode_der_sig(signature, encoded_sig);

    {
        ret = cbor_encode_int(&map, CTAP_RESP_SIGNATURE);  // 3
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, encoded_sig, encoded_sig_size);
        check_ret(ret);
    }
    if (user_id_size)
    {
        ret = _encode_user_id(&map, user_id, user_id_size);  // 4
        if (ret != CborNoError) {
            return ret;
        }
    }
    ret = cbor_encoder_close_container(encoder, &map);
    return 0;
}

/**
 * Selects one of the matching credentials in the given credential list.
 *
 * @param GA getAssertion request that must be examined. Must contain
 *           an allow list.
 * @param chosen_credential_out Will be filled with a pointer to the chosen credential,
 *                              or NULL if no key was found.
 * @param chosen_privkey Will be filled with the the private key corresponding to chosen_credential.
 *                       Must be at least HMAC_SHA256_LEN bytes wide.
 */
static void _authenticate_with_allow_list(ctap_get_assertion_req_t* GA, u2f_keyhandle_t** chosen_credential_out, uint8_t* chosen_privkey)
{
    /*
     * We can just pick the first credential that we're able to authenticate with.
     * No need to ask the user to select one if many credentials match.
     * See Client to Authenticator Protocol, 5.2, point 9.
     */
    for (int i = 0; i < GA->cred_len; i++) {
        u2f_keyhandle_t* this_key = GA->creds + i;
        bool key_valid = u2f_keyhandle_verify(GA->rp.id, (uint8_t*)this_key, sizeof(*this_key), chosen_privkey);
        if (key_valid) {
            /* Found an applicable credential. */
            *chosen_credential_out = this_key;
            return;
        }
    }
    /* No keys were found. */
    util_zero(chosen_privkey, HMAC_SHA256_LEN);
    *chosen_credential_out = NULL;
}

/**
 * Called when the user has selected one of the credentials from
 * the available credential list for an authentication request.
 *
 * This function will decode the selected authentication key and
 * move to the CTAP_GET_ASSERTION_SELECTED_CREDENTIAL state.
 */
static void _auth_credential_selected(int selected_cred, void* param)
{
    (void)param;
    ctap_get_assertion_state_t* state = &_state.data.get_assertion;

    if (selected_cred < 0) {
        /* User aborted. */
        state->state = CTAP_GET_ASSERTION_DENIED;
        return;
    }

    /* Now load the credential that was selected in the output buffer. */
    ctap_resident_key_t selected_key;
    //screen_sprintf_debug(500, "Selected cred #%d", cred_idx[selected_cred]);
    bool mem_result = memory_get_ctap_resident_key(state->cred_list.creds[selected_cred].mem_id, &selected_key);

    if (!mem_result) {
        /* Shouldn't happen, but if it does we effectively don't have any valid credential to provide. */
        state->state = CTAP_GET_ASSERTION_NO_CREDENTIALS;
        return;
    }
    /* Sanity check the stored credential. */
    if (selected_key.valid != CTAP_RESIDENT_KEY_VALID ||
        selected_key.user_id_size > CTAP_USER_ID_MAX_SIZE) {
        state->state = CTAP_GET_ASSERTION_NO_CREDENTIALS;
        return;
    }
    memcpy(&state->auth_credential, &selected_key.key_handle, sizeof(selected_key.key_handle));
    state->user_id_size = selected_key.user_id_size;
    memcpy(state->user_id, selected_key.user_id, state->user_id_size);

    /* Sanity check the key and extract the private key. */
    bool key_valid = u2f_keyhandle_verify(state->req.rp.id, (const uint8_t*)&state->auth_credential, sizeof(state->auth_credential), state->auth_privkey);
    if (!key_valid) {
        workflow_status_blocking("Internal error. Keyhandle verification failed.", false);
        state->state = CTAP_GET_ASSERTION_NO_CREDENTIALS;
        return;
    }
    state->state = CTAP_GET_ASSERTION_SELECTED_CREDENTIAL;
}


/**
 * Selects one of the stored credentials for authentication.
 *
 * @param GA getAssertion request that must be examined. Must contain
 *           an allow list.
 * @param chosen_credential_out Will be filled with the chosen credential.
 * @param chosen_privkey Will be filled with the the private key corresponding to chosen_credential.
 *                       Must be at least HMAC_SHA256_LEN bytes wide.
 * @param user_id_out Will be filled with the stored User ID corresponding to the
 *                    chosen credential. Must be CTAP_STORAGE_USER_NAME_LIMIT bytes long.
 * @param user_id_size_out Will be filled with the size of user_id.
 *
 * @return true if authentication was successful (operation should continue), false otherwise.
 */
static bool _authenticate_with_rk(ctap_get_assertion_req_t* GA)
{
    ctap_get_assertion_state_t* state = &_state.data.get_assertion;
    state->cred_list.n_elems = 0;

    /*
     * Compute the hash of the RP id so that we
     * can match it against the keys we have in memory.
     */
    uint8_t rp_id_hash[SHA256_LEN];
    _compute_rpid_hash(&GA->rp, rp_id_hash);
    /* Check all keys that match this RP. */
    for (int i = 0; i < MEMORY_CTAP_RESIDENT_KEYS_MAX; i++) {
        ctap_resident_key_t this_key;
        bool mem_result = memory_get_ctap_resident_key(i, &this_key);
        if (!mem_result || this_key.valid != CTAP_RESIDENT_KEY_VALID) {
            continue;
        }
        if (!memcmp(this_key.rp_id_hash, rp_id_hash, SHA256_LEN)) {
            /*
             * This key matches the RP! Add its user information to
             * our list.
             */
            ctap_credential_display_t* this_cred = state->cred_list.creds + state->cred_list.n_elems;
            this_cred->mem_id = i;
            memcpy(this_cred->username, this_key.user_name, sizeof(this_key.user_name));
            memcpy(this_cred->display_name, this_key.display_name, sizeof(this_key.display_name));
            state->cred_list.n_elems++;
            if (state->cred_list.n_elems == CTAP_CREDENTIAL_LIST_MAX_SIZE) {
                /* No more space */
                break;
            }
        }
    }
    if (state->cred_list.n_elems == 0) {
        return false;
    }
    /* Sort credentials by creation time. */
    qsort(state->cred_list.creds, state->cred_list.n_elems, sizeof(*state->cred_list.creds), _compare_display_credentials);
    if (state->cred_list.n_elems > 1) {
        workflow_t* wf = workflow_select_ctap_credential(&state->cred_list, _auth_credential_selected, NULL);
        workflow_stack_start_workflow(wf);
        state->state = CTAP_GET_ASSERTION_SELECT_CREDENTIAL;
    } else {
        _auth_credential_selected(0, NULL);
    }
    return true;
}

/**
 * @param auth_data_buf Must be at least sizeof(ctap_auth_data_t) bytes wide.
 * @param data_buf_len_out Will be filled with the actual auth data size.
 */
static uint8_t _make_authentication_response(ctap_get_assertion_req_t* GA, uint8_t* auth_data_buf, size_t* data_buf_len_out) {
    ctap_auth_data_header_t* auth_data_header = (ctap_auth_data_header_t*)auth_data_buf;

    auth_data_header->flags = 0;
    if (GA->up) {
        auth_data_header->flags |= CTAP_AUTH_DATA_FLAG_USER_PRESENT;        // User presence
    }
    if (GA->uv) {
        auth_data_header->flags |= CTAP_AUTH_DATA_FLAG_USER_VERIFIED;        // User presence
    }

    _compute_rpid_hash(&GA->rp, auth_data_header->rp_id_hash);

    /* Update the U2F counter. */
    uint32_t u2f_counter;
    if (!securechip_u2f_counter_inc(&u2f_counter)) {
        return CTAP2_ERR_OPERATION_DENIED;
    }
    _encode_u2f_counter(u2f_counter, (uint8_t*)&auth_data_header->signCount);

    uint32_t actual_auth_data_size = sizeof(ctap_auth_data_header_t);

    /* FUTURE: manage extensions if we want to. */
    *data_buf_len_out = actual_auth_data_size;
    return CTAP1_ERR_SUCCESS;
}

static void _get_assertion_init_state(ctap_get_assertion_req_t* req)
{
    _state.data.get_assertion.state = CTAP_GET_ASSERTION_STARTED;
    memcpy(&_state.data.get_assertion.req, req, sizeof(*req));
}

static void _get_assertion_free_state(void)
{
    util_zero(_state.data.get_assertion.auth_privkey,
        sizeof(_state.data.get_assertion.auth_privkey)
        );
}

static uint8_t ctap_get_assertion(const in_buffer_t* in_buffer)
{
    ctap_get_assertion_req_t req;

    int ret = ctap_parse_get_assertion(&req, in_buffer);

    if (ret != 0) {
        return ret;
    }

    if (req.pin_auth_empty) {
        bool result = _ask_generic_authorization();
        if (!result) {
            return CTAP2_ERR_OPERATION_DENIED;
        }
        return CTAP2_ERR_PIN_NOT_SET;
    }
    if (req.pin_auth_present) {
        /* We don't support pin_auth. */
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

    if (!req.rp.size || !req.client_data_hash_present) {
        /* Both parameters are mandatory. */
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    /*
     * Ask the user to confirm that he wants to authenticate.
     * This must be done before we check for credentials so that
     * we don't disclose the existance of credentials before the
     * user has proven his identity (See 5.2, point 7).
     */
    _get_assertion_init_state(&req);
    workflow_stack_start_workflow(workflow_unlock(_get_assertion_unlock_cb, NULL));
    return CTAP1_ERR_SUCCESS;
}

/**
 * Generates a new assertion in response to a GetAssertion request.
 * Only called when the user has already accepted and identified with the device.
 */
static ctap_request_result_t _get_assertion_select_credential(void)
{
    ctap_get_assertion_state_t* state = &_state.data.get_assertion;

    if (state->req.cred_len) {
        // allowlist is present -> check all the credentials that were actually generated by us.
        u2f_keyhandle_t* chosen_credential = NULL;
        _authenticate_with_allow_list(&state->req, &chosen_credential, state->auth_privkey);
        if (!chosen_credential) {
            /* No credential selected (or no credential was known to the device). */
            ctap_request_result_t result = {.status = CTAP2_ERR_NO_CREDENTIALS, .request_completed = true};
            return result;
        }
        memcpy(&state->auth_credential, chosen_credential, sizeof(state->auth_credential));
        state->state = CTAP_GET_ASSERTION_SELECTED_CREDENTIAL;
    } else {
        // No allowList, so use all matching RK's matching rpId
        bool rk_result = _authenticate_with_rk(&state->req);
        if (!rk_result) {
            ctap_request_result_t result = {.status = CTAP2_ERR_NO_CREDENTIALS, .request_completed = true};
            return result;
        }
    }
    ctap_request_result_t result = {.status = 0, .request_completed = false};
    return result;
}

static uint8_t _get_assertion_complete(buffer_t* out_buf)
{
    size_t actual_auth_data_size;
    uint8_t auth_data_buf[sizeof(ctap_auth_data_header_t) + 80];
    ctap_get_assertion_state_t* state = &_state.data.get_assertion;
    uint8_t ret = _make_authentication_response(&state->req, auth_data_buf, &actual_auth_data_size);
    if (ret != CborNoError) {
        return ret;
    }

    /* Encode the resulting assertion in the output buffer. */
    CborEncoder encoder;
    memset(&encoder, 0, sizeof(CborEncoder));
    cbor_encoder_init(&encoder, out_buf->data, out_buf->max_len, 0);
    ret = ctap_end_get_assertion(&encoder, &state->auth_credential, auth_data_buf, actual_auth_data_size, state->auth_privkey, state->req.client_data_hash, state->user_id, state->user_id_size);
    if (ret != CborNoError) {
        return ret;
    }

    out_buf->len = cbor_encoder_get_buffer_size(&encoder, out_buf->data);

    return CTAP1_ERR_SUCCESS;
}

static ctap_request_result_t _get_assertion_continue(buffer_t* out_buf)
{
    ctap_request_result_t result = {.status = 0, .request_completed = true};
    ctap_get_assertion_state_t* state = &_state.data.get_assertion;
    switch (state->state) {
        case CTAP_GET_ASSERTION_CONFIRMED:
            result = _get_assertion_select_credential();
            return result;
        case CTAP_GET_ASSERTION_DENIED:
            result.status = CTAP2_ERR_OPERATION_DENIED;
            return result;
        case CTAP_GET_ASSERTION_NO_CREDENTIALS:
            workflow_status_blocking("No credentials found on this device.", false);
            result.status = CTAP2_ERR_NO_CREDENTIALS;
            return result;
        case CTAP_GET_ASSERTION_UNLOCKED:
            /*
            * Request permission to the user.
            * This must be done before checking for excluded credentials etc.
            * so that we don't reveal the existance of credentials without
            * the user's consent.
            */
            workflow_stack_start_workflow(_get_assertion_confirm(&_state.data.get_assertion.req.rp));
            state->state = CTAP_MAKE_CREDENTIAL_WAIT_CONFIRM;
            result.request_completed = false;
            return result;
        case CTAP_GET_ASSERTION_SELECTED_CREDENTIAL:
            result.status = _get_assertion_complete(out_buf);
            return result;
        case CTAP_GET_ASSERTION_STARTED:
        case CTAP_GET_ASSERTION_WAIT_CONFIRM:
        case CTAP_GET_ASSERTION_SELECT_CREDENTIAL:
            result.request_completed = false;
            return result;
        default:
            Abort("Invalid get_assertion state.");
    }
}

void ctap_response_init(ctap_response_t* resp)
{
    memset(resp, 0, sizeof(*resp));
    resp->data_size = CTAP_RESPONSE_BUFFER_SIZE;
}

ctap_request_result_t ctap_request(const in_buffer_t* in_buf, buffer_t* out_buf)
{
    CborEncoder encoder;
    memset(&encoder,0,sizeof(CborEncoder));

    uint8_t cmd = *in_buf->data;
    in_buffer_t in_req_data = {
        .data = in_buf->data + 1,
        .len = in_buf->len - 1
    };

    cbor_encoder_init(&encoder, out_buf->data, out_buf->max_len, 0);
    ctap_request_result_t result = {.status = 0, .request_completed = true};

    switch(cmd)
    {
        case CTAP_REQ_MAKE_CREDENTIAL:
            result.status = ctap_make_credential(&encoder, &in_req_data);
            if (result.status == CTAP1_ERR_SUCCESS) {
                /* MakeCredential started successfully, don't reply yet. */
                _state.blocking_op = CTAP_BLOCKING_OP_MAKE_CRED;
                result.request_completed = false;
            }
            break;
        case CTAP_REQ_GET_ASSERTION:
            result.status = ctap_get_assertion(&in_req_data);
            if (result.status == CTAP1_ERR_SUCCESS) {
                _state.blocking_op = CTAP_BLOCKING_OP_GET_ASSERTION;
                result.request_completed = false;
            }
            break;
        case CTAP_REQ_CANCEL:
            break;
        case CTAP_REQ_GET_INFO:
            result.status = ctap_get_info(&encoder);
            out_buf->len = cbor_encoder_get_buffer_size(&encoder, out_buf->data);
            break;
        case CTAP_REQ_CLIENT_PIN:
        case CTAP_REQ_RESET:
        case CTAP_REQ_GET_NEXT_ASSERTION:
            result.status = CTAP2_ERR_NOT_ALLOWED;
            break;
        default:
            result.status = CTAP1_ERR_INVALID_COMMAND;
    }

    if (result.status != CTAP1_ERR_SUCCESS || !result.request_completed) {
        out_buf->len = 0;
    }
    return result;
}

ctap_request_result_t ctap_retry(buffer_t* out_buf)
{
    ctap_request_result_t result = {.status = 0, .request_completed = true};

    switch (_state.blocking_op) {
        case CTAP_BLOCKING_OP_MAKE_CRED:
            result = _make_credential_continue(out_buf);
            if (result.request_completed) {
                _state.blocking_op = CTAP_BLOCKING_OP_NONE;
                _make_credential_free_state();
            }
            break;
        case CTAP_BLOCKING_OP_GET_ASSERTION:
            result = _get_assertion_continue(out_buf);
            if (result.request_completed) {
                _state.blocking_op = CTAP_BLOCKING_OP_NONE;
                _get_assertion_free_state();
            }
            break;
        case CTAP_BLOCKING_OP_NONE:
        default:
            Abort("Invalid status in ctap_retry");
    }
    return result;
}

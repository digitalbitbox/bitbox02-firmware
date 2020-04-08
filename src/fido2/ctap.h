// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _CTAP_H
#define _CTAP_H

#include <crypto/sha2/sha256.h>
#include <hardfault.h>
#include <u2f/u2f_keyhandle.h>
#include <util.h>

#ifdef assert
#undef assert
#endif

/*
 * TinyCBOR will use the default definition for assert.
 * The USB driver will include its own definition though...
 *
 * Replace it with our custom definition (i.e. Abort if condition
 * is false).
 */
#define assert(cond) \
    do { \
        if (!(cond)) { \
            Abort("Assertion failed:\n" #cond); \
        } \
    } while(0);

#include <cbor.h>

#undef assert

#include <usb/usb_packet.h>

/**
 * Authenticator Status, transmitted through keepalive messages.
 */
#define CTAPHID_STATUS_IDLE         0
#define CTAPHID_STATUS_PROCESSING   1
#define CTAPHID_STATUS_UPNEEDED     2

#define EXT_HMAC_SECRET_COSE_KEY    0x01
#define EXT_HMAC_SECRET_SALT_ENC    0x02
#define EXT_HMAC_SECRET_SALT_AUTH   0x03

#define EXT_HMAC_SECRET_REQUESTED   0x01
#define EXT_HMAC_SECRET_PARSED      0x02

#define CLIENT_DATA_HASH_SIZE       (SHA256_LEN)
#define DOMAIN_NAME_MAX_SIZE        253
#define RP_NAME_LIMIT               32  // application limit, name parameter isn't needed.
#define CTAP_USER_ID_MAX_SIZE            64

/**
 * Maximum length of the CTAP username getting stored
 * in a resident credential.
 * Can be longer than 32B, but we only store this
 * data for displaying it when authenticating.
 * So if the actual length is longer we can just display
 * a truncated string.
 */
#define CTAP_STORAGE_USER_NAME_LIMIT (20)

/**
 * Maximum length of the CTAP username getting stored
 * in a resident credential.
 * Can be longer than 32B, but we only store this
 * data for displaying it when authenticating.
 * So if the actual length is longer we can just display
 * a truncated string.
 */
#define CTAP_STORAGE_RP_ID_MAX_SIZE (20)

/**
 * Maximum length of the CTAP username getting stored
 * in a resident credential. It could be truncated.
 */
#define CTAP_STORAGE_DISPLAY_NAME_LIMIT (20)

/** Maximum length of the CTAP username. */
#define CTAP_USER_NAME_LIMIT             (64)
#define DISPLAY_NAME_LIMIT          32  // Must be minimum of 64 bytes but can be more.
#define ICON_LIMIT                  128 // Must be minimum of 64 bytes but can be more.
#define CTAP_MAX_MESSAGE_SIZE       1200

#define CREDENTIAL_RK_FLASH_PAD     2   // size of RK should be 8-byte aligned to store in flash easily.
    #define CREDENTIAL_TAG_SIZE         16
    #define CREDENTIAL_NONCE_SIZE       (16 + CREDENTIAL_RK_FLASH_PAD)
    #define CREDENTIAL_COUNTER_SIZE     (4)
    #define CREDENTIAL_ENC_SIZE         176  // pad to multiple of 16 bytes

    #define PUB_KEY_CRED_PUB_KEY        0x01
    #define PUB_KEY_CRED_CTAP1          0x41
    #define PUB_KEY_CRED_CUSTOM         0x42
    #define PUB_KEY_CRED_UNKNOWN        0x3F

    #define CREDENTIAL_IS_SUPPORTED     1
    #define CREDENTIAL_NOT_SUPPORTED    0

    #define CTAP_CREDENTIAL_LIST_MAX_SIZE 20

    #define NEW_PIN_ENC_MAX_SIZE        256     // includes NULL terminator
    #define NEW_PIN_ENC_MIN_SIZE        64
    #define NEW_PIN_MAX_SIZE            64
    #define NEW_PIN_MIN_SIZE            4

    #define CTAP_RESPONSE_BUFFER_SIZE   4096

    #define PIN_LOCKOUT_ATTEMPTS        8       // Number of attempts total
    #define PIN_BOOT_ATTEMPTS           3       // number of attempts per boot

    #define CTAP2_UP_DELAY_MS           29000

    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wpacked"
    #pragma GCC diagnostic ignored "-Wattributes"

typedef struct {
    uint8_t id[CTAP_USER_ID_MAX_SIZE];
    uint8_t id_size;
    uint8_t name[CTAP_USER_NAME_LIMIT];
    uint8_t display_name[DISPLAY_NAME_LIMIT];
    uint8_t icon[ICON_LIMIT];
} ctap_user_entity_t;

#define CTAP_RESIDENT_KEY_VALID (0x01)

/**
 * Invalid keys have their "valid" field
 * set to 0xFF so that erased flash is invalid.
 */
#define CTAP_RESIDENT_KEY_INVALID (0xff)

typedef struct __attribute__((__packed__)) {
    uint8_t valid;

    /** Key handle (credential ID) */
    u2f_keyhandle_t key_handle;

    /**
     * Human-readable ID of the RP that created the credential.
     * This is a NULL-terminated string.
     */
    uint8_t rp_id[CTAP_STORAGE_RP_ID_MAX_SIZE];
    /**
     * sha256 hash of the original RP id.
     * This is necessary (together with the ID) so
     * that we can make check RP ids for matching values
     * even if the actual RP id is longer than 32 bytes.
     */
    uint8_t rp_id_hash[32];
    /**
     * User ID that the RP has assigned to our user.
     * We need to store this and send it back together
     * with our keyhandle when we're asked to authenticate.
     */
    uint8_t user_id[CTAP_USER_ID_MAX_SIZE];
    /**
     * Size of user_id.
     */
    uint8_t user_id_size;
    /**
     * Username belonging to this credential.
     * This is a NULL terminated string.
     * Side effect: if a credential is created
     * which matches the first CTAP_STORAGE_USER_NAME_LIMIT
     * characters of the user and display name of an existing
     * credential, the latter is going to be overwritten.
     * Can this be used for evil purposes? (it shouldn't).
     */
    uint8_t user_name[CTAP_STORAGE_USER_NAME_LIMIT];
    /**
     * Display name of the user. Same considerations apply
     * as for the user_name.
     */
    uint8_t display_name[CTAP_STORAGE_DISPLAY_NAME_LIMIT];
    /**
     * Creation "time" of the key.
     * This is the value that the U2F counter had when the
     * key got created. We must not store any real timestamp,
     * but we must be able to sort keys by creation time.
     */
    uint32_t creation_time;
} ctap_resident_key_t;

/**
 * Attested credential data, defined
 * in [WebAuthn] 6.4.1.
 */
typedef struct __attribute__((packed)) {
    /** The AAGUID of the authenticator. */
    uint8_t aaguid[16];
    /** Length of the credential ID (big-endian) */
    uint8_t cred_len[2];
    /**  Credential ID */
    u2f_keyhandle_t id;
} ctap_attest_data_t;

/**
 * Authenticator data structure, to use
 * for authentication operations. It is
 * missing the attestedCredentialData
 * field. Defined in The WebAuthn specs, 6.1.
 */
typedef struct __attribute__((packed)) {
    uint8_t rp_id_hash[32];
    uint8_t flags;
    uint32_t signCount;
} ctap_auth_data_header_t;

/**
 * Authenticator data structure, including
 * the attestedCredentialData field.
 * Defined in The WebAuthn specs, 6.1.
 */
typedef struct __attribute__((packed)) {
    ctap_auth_data_header_t head;
    ctap_attest_data_t attest;
    /* COSE-encoded pubkey and extension data */
    uint8_t other[310 - sizeof(ctap_auth_data_header_t) - sizeof(ctap_attest_data_t)];
} ctap_auth_data_t;

#pragma GCC diagnostic pop

typedef struct
{
    uint8_t data[CTAP_RESPONSE_BUFFER_SIZE];
    uint16_t data_size;
    uint16_t length;
} ctap_response_t;

typedef struct {
    uint8_t id[DOMAIN_NAME_MAX_SIZE + 1];     // extra for NULL termination
    /* TODO change to id_size */
    size_t size;
    uint8_t name[RP_NAME_LIMIT];
} ctap_rp_id_t;

typedef struct
{
    struct{
        uint8_t x[32];
        uint8_t y[32];
    } pubkey;

    int kty;
    int crv;
} COSE_key;

typedef struct
{
    uint8_t saltLen;
    uint8_t saltEnc[64];
    uint8_t saltAuth[32];
    COSE_key keyAgreement;
    u2f_keyhandle_t* key_handle;
} CTAP_hmac_secret;

typedef struct
{
    uint8_t hmac_secret_present;
    CTAP_hmac_secret hmac_secret;
} ctap_extensions_t;

typedef struct
{
    ctap_user_entity_t user;
    uint8_t publicKeyCredentialType;
    int32_t COSEAlgorithmIdentifier;
    uint8_t rk;
} ctap_cred_info_t;

typedef struct
{
    uint32_t param_parsed;
    uint8_t client_data_hash[CLIENT_DATA_HASH_SIZE];
    ctap_rp_id_t rp;

    ctap_cred_info_t cred_info;

    CborValue exclude_list;
    size_t exclude_list_size;

    uint8_t uv;
    uint8_t up;

    uint8_t pin_auth[16];
    uint8_t pin_auth_present;
    // pin_auth_empty is true iff an empty bytestring was provided as pin_auth.
    // This is exclusive with |pin_auth_present|. It exists because an empty
    // pin_auth is a special signal to block for touch. See
    // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#using-pinToken-in-authenticatorMakeCredential
    uint8_t pin_auth_empty;
    int pin_protocol;
    ctap_extensions_t extensions;

} ctap_make_credential_req_t;



typedef struct
{
    uint32_t param_parsed;
    uint8_t client_data_hash[CLIENT_DATA_HASH_SIZE];
    uint8_t client_data_hash_present;

    ctap_rp_id_t rp;

    uint8_t rk;
    uint8_t uv;
    uint8_t up;

    /* TODO remove pin_auth, we don't use it anyway. */
    uint8_t pin_auth[16];
    uint8_t pin_auth_present;
    /**
     * pin_auth_empty is true iff an empty bytestring was provided as pin_auth.
     * This is exclusive with |pin_auth_present|. It exists because an empty
     * pin_auth is a special signal to block for touch. See
     * https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#using-pinToken-in-authenticatorGetAssertion
     */
    uint8_t pin_auth_empty;
    int pin_protocol;

    /**
     * List of allowed credential descriptors for authentication.
     * If this parameter is present, then the authenticator MUST
     * use one of these credentials to authenticate.
     */
    u2f_keyhandle_t creds[CTAP_CREDENTIAL_LIST_MAX_SIZE];
    /** Number of credential descriptors present in this request. */
    int cred_len;

    uint8_t allowListPresent;

    ctap_extensions_t extensions;
} ctap_get_assertion_req_t;

typedef struct {
    /** CTAP_* success/error code. */
    uint8_t status;
    /** If true, a response for this request can be sent. */
    bool request_completed;
} ctap_request_result_t;

void ctap_response_init(ctap_response_t* resp);

ctap_request_result_t ctap_request(const in_buffer_t* in_buf, buffer_t* out_buf);

/**
 * Polls an outstanding operation for completion.
 *
 * @param out_data Buffer to fill with a response (if any is ready).
 * @param out_len[out] Length of the response contained in out_data.
 * @return Request status.
 */
ctap_request_result_t ctap_retry(buffer_t* out_buf);

// Run ctap related power-up procedures (init pinToken, generate shared secret)
void ctap_init(void);

void make_auth_tag(uint8_t* rp_id_hash, uint8_t* nonce, uint32_t count, uint8_t* tag);

#endif // _CTAP_H

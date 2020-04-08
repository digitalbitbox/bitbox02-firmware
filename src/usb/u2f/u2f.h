// Copyright 2014 Google Inc. All rights reserved.
// Copyright 2017-2019 Shift Cryptosecurity AG
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#ifndef __U2F_H_INCLUDED__
#define __U2F_H_INCLUDED__

#include <stdint.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpacked"
#pragma GCC diagnostic ignored "-Wattributes"

// General constants
/* Size of one of the point coordinates on the EC */
#define U2F_EC_KEY_SIZE (32)
#define U2F_EC_POINT_SIZE ((U2F_EC_KEY_SIZE * 2) + 1)
#define U2F_MAX_KH_SIZE 128 // Max size of key handle
#define U2F_MAX_ATT_CERT_SIZE 1024 // Max size of attestation certificate
#define U2F_MAX_EC_SIG_SIZE 72 // Max size of ANS.1 DER encoded EC signature
#define U2F_CTR_SIZE 4 // Size of counter field
#define U2F_FRAME_SIZE (3 + U2F_CTR_SIZE) // 1-byte flag | 4-byte counter | 2-byte status
#define U2F_APPID_SIZE 32 // Size of application id
#define U2F_NONCE_LENGTH 32 // Size of challenge nonce
#define U2F_UNCOMPRESSED_POINT 0x04 // Uncompressed point format

typedef struct {
    uint8_t format;
    uint8_t x[U2F_EC_KEY_SIZE];
    uint8_t y[U2F_EC_KEY_SIZE];
} U2F_EC_POINT;

// U2F native commands
#define U2F_REGISTER 0x01
#define U2F_AUTHENTICATE 0x02
#define U2F_VERSION 0x03
#define U2F_VENDOR_FIRST 0x40
#define U2F_VENDOR_LAST 0x7f

// U2F_CMD_REGISTER command defines
#define U2F_REGISTER_ID 0x05 // Version 2 registration identifier
#define U2F_REGISTER_HASH_ID 0x00 // Version 2 hash identintifier

typedef struct {
    uint8_t challenge[U2F_NONCE_LENGTH];
    uint8_t appId[U2F_APPID_SIZE];
} U2F_REGISTER_REQ;

typedef struct __attribute__((__packed__)) {
    uint8_t registerId; // U2F_REGISTER_ID_V2
    U2F_EC_POINT pubKey;
    uint8_t keyHandleLen;
    uint8_t keyHandleCertSig[U2F_MAX_KH_SIZE + U2F_MAX_ATT_CERT_SIZE + U2F_MAX_EC_SIG_SIZE];
} U2F_REGISTER_RESP;

// U2F_AUTHENTICATE instruction defines
#define U2F_AUTH_ENFORCE 0x03 // Enforce user presence and sign
#define U2F_AUTH_CHECK_ONLY 0x07
#define U2F_AUTH_FLAG_TUP 0x01 // Test of user presence set

typedef struct {
    uint8_t challenge[U2F_NONCE_LENGTH];
    uint8_t appId[U2F_APPID_SIZE];
    uint8_t keyHandleLength;
    uint8_t keyHandle[U2F_MAX_KH_SIZE];
} U2F_AUTHENTICATE_REQ;

typedef struct __attribute__((__packed__)) {
    uint8_t flags;
    uint8_t ctr[U2F_CTR_SIZE];
    uint8_t sig[U2F_MAX_EC_SIG_SIZE];
} U2F_AUTHENTICATE_RESP;

// Common raw message format (ISO 7816-4:2005)
typedef struct {
    uint8_t cla; // Class - reserved
    uint8_t ins; // U2F instruction
    uint8_t p1; // U2F parameter 1
    uint8_t p2; // U2F parameter 2
    uint8_t lc1; // Length field, set to zero
    uint8_t lc2; // Length field, MSB
    uint8_t lc3; // Length field, LSB
    uint8_t data[1];
} U2F_MSG;

// Command status responses
#define U2F_SW_NO_ERROR 0x9000
#define U2F_SW_WRONG_LENGTH 0x6700
#define U2F_SW_DATA_INVALID 0x6984
#define U2F_SW_CONDITIONS_NOT_SATISFIED 0x6985
#define U2F_SW_WRONG_DATA 0x6a80
#define U2F_SW_INS_NOT_SUPPORTED 0x6d00
#define U2F_SW_CLA_NOT_SUPPORTED 0x6e00

#pragma GCC diagnostic pop

#endif

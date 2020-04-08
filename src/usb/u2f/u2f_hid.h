// Copyright 2014 Google Inc. All rights reserved.
// Copyright 2019 Shift Cryptosecurity AG
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#ifndef __U2FHID_H_INCLUDED__
#define __U2FHID_H_INCLUDED__

#include <stdint.h>

#define U2FHID_CID_BROADCAST 0xffffffff // Broadcast channel id

#define U2FHID_TYPE_MASK 0x80 // Frame type mask
#define U2FHID_TYPE_INIT 0x80 // Initial frame identifier
#define U2FHID_TYPE_CONT 0x00 // Continuation frame identifier

#define U2FHID_FRAME_TYPE(f) ((f).type & U2FHID_TYPE_MASK)
#define U2FHID_FRAME_CMD(f) ((f).init.cmd & ~U2FHID_TYPE_MASK)
#define U2FHID_FRAME_SEQ(f) ((f).cont.seq & ~U2FHID_TYPE_MASK)
#define U2FHID_MSG_LEN(f) (((f).init.bcnth << 8) + (f).init.bcntl)

// General constants
#define U2FHID_IF_VERSION 2 // Current interface implementation version
#define U2FHID_FRAME_TIMEOUT 500 // Default frame timeout in ms
#define U2FHID_TRANS_TIMEOUT 3000 // Default message timeout in ms

// U2FHID native commands
#define U2FHID_PING         (U2FHID_TYPE_INIT | 0x01) // Echo data
#define U2FHID_MSG          (U2FHID_TYPE_INIT | 0x03) // Send U2F message frame
#define U2FHID_LOCK         (U2FHID_TYPE_INIT | 0x04) // Send lock channel command
#define U2FHID_INIT         (U2FHID_TYPE_INIT | 0x06) // Channel initialization
#define U2FHID_WINK         (U2FHID_TYPE_INIT | 0x08) // Send device identification wink
#define U2FHID_CBOR         (U2FHID_TYPE_INIT | 0x10)
#define U2FHID_CANCEL       (U2FHID_TYPE_INIT | 0x11)
#define U2FHID_KEEPALIVE    (U2FHID_TYPE_INIT | 0x3b)
#define U2FHID_SYNC         (U2FHID_TYPE_INIT | 0x3c) // Send sync command
#define U2FHID_ERROR        (U2FHID_TYPE_INIT | 0x3f) // Error response
#define U2FHID_VENDOR_FIRST (U2FHID_TYPE_INIT | 0x40) // First vendor defined command
#define U2FHID_VENDOR_LAST  (U2FHID_TYPE_INIT | 0x7f) // Last vendor defined command

// U2FHID vendor defined commands
#define U2FHID_HWW (U2FHID_VENDOR_FIRST + 0x01) // Hardware wallet command

// U2FHID_INIT command defines
#define U2FHID_INIT_NONCE_SIZE 8
#define U2FHID_CAPFLAG_WINK 0x01 // Device supports WINK command
#define U2FHID_CAPFLAG_LOCK 0x02 // Device supports LOCK command
#define U2FHID_CAPFLAG_CBOR 0x04 // Device supports CBOR (FIDO2) commands

// Error codes; return as negatives
#define U2FHID_ERR_NONE 0x00
#define U2FHID_ERR_INVALID_CMD 0x01
#define U2FHID_ERR_INVALID_PAR 0x02
#define U2FHID_ERR_INVALID_LEN 0x03
#define U2FHID_ERR_INVALID_SEQ 0x04
#define U2FHID_ERR_MSG_TIMEOUT 0x05
#define U2FHID_ERR_CHANNEL_BUSY 0x06
#define U2FHID_ERR_LOCK_REQUIRED 0x0a
#define U2FHID_ERR_INVALID_CID 0x0b
#define U2FHID_ERR_OTHER 0x7f

typedef struct {
    uint8_t nonce[U2FHID_INIT_NONCE_SIZE];
} U2FHID_INIT_REQ;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpacked"
#pragma GCC diagnostic ignored "-Wattributes"
typedef struct __attribute__((__packed__)) {
    uint8_t nonce[U2FHID_INIT_NONCE_SIZE];
    uint32_t cid;
    uint8_t versionInterface;
    uint8_t versionMajor;
    uint8_t versionMinor;
    uint8_t versionBuild;
    uint8_t capFlags; // Capabilities flags
} U2FHID_INIT_RESP;
#pragma GCC diagnostic pop

#define U2FHID_INIT_RESP_SIZE 17

#endif

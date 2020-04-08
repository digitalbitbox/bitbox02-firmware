// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _CTAP_PARSE_H
#define _CTAP_PARSE_H

#include "ctap_errors.h"

#define check_ret(r) \
    do { \
        if ((r) != CborNoError) { \
            return CTAP2_ERR_CBOR_PARSING; \
        } \
    } while(0);

const char* cbor_value_get_type_string(const CborValue *value);

uint8_t ctap_parse_make_credential(ctap_make_credential_req_t* MC, CborEncoder * encoder, const in_buffer_t* in_buffer);
uint8_t ctap_parse_get_assertion(ctap_get_assertion_req_t* GA, const in_buffer_t* in_buffer);
uint8_t ctap_parse_credential_descriptor(CborValue * arr, u2f_keyhandle_t* cred, bool* cred_valid_out);

#endif

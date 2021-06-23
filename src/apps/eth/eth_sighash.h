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

#ifndef _APPS_ETH_SIGHASH_H
#define _APPS_ETH_SIGHASH_H

#include <compiler_util.h>
#include <hww.pb.h>

#include <stdbool.h>
#include <stdint.h>

#include <util.h>

typedef struct {
    in_buffer_t nonce;
    in_buffer_t gas_price;
    in_buffer_t gas_limit;
    in_buffer_t recipient;
    in_buffer_t value;
    in_buffer_t data;
    // EIP155 chain id.
    uint8_t chain_id;
} eth_sighash_params_t;

/**
 * Computes the sighash of an Ethereum transaction, using the chain_id as described in EIP155.
 * @param[in] params transaction data. nonce, gas_price, gas_limit, and value are big endian and are
 * not allowed to have leading zeros (unchecked).
 * @param[out] sighash_out 32 bytes hash to be signed.
 */
USE_RESULT bool app_eth_sighash(eth_sighash_params_t params, uint8_t* sighash_out);

/**
 * Computes the sighash of an Ethereum Classic transaction.
 * @param[in] params transaction data. nonce, gas_price, gas_limit, and value are big endian and are
 * not allowed to have leading zeros (unchecked).
 * @param[out] sighash_out 32 bytes hash to be signed.
 */
USE_RESULT bool app_eth_sighash_etc(eth_sighash_params_t params, uint8_t* sighash_out);

#endif

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

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <stdio.h>

#include <apps/btc/btc_sign.h>
#include <apps/btc/confirm_locktime_rbf.h>
#include <keystore.h>
#include <wally_bip32.h>

bool __wrap_workflow_verify_recipient(const char* recipient, const char* amount)
{
    check_expected(recipient);
    check_expected(amount);
    return mock();
}

bool __wrap_workflow_verify_total(const char* total, const char* fee)
{
    check_expected(total);
    check_expected(fee);
    return mock();
}

bool __wrap_apps_btc_confirm_locktime_rbf(uint32_t locktime, enum apps_btc_rbf_flag rbf)
{
    check_expected(locktime);
    check_expected(rbf);
    return mock();
}

bool __wrap_btc_common_format_amount(uint64_t satoshi, const char* unit, char* out, size_t out_len)
{
    check_expected(satoshi);
    check_expected(unit);
    snprintf(out, out_len, "%s", (const char*)(mock()));
    return true;
}

bool __real_btc_common_is_valid_keypath_address_simple(
    BTCScriptConfig_SimpleType script_type,
    const uint32_t* keypath,
    size_t keypath_len,
    uint32_t expected_coin);
bool __wrap_btc_common_is_valid_keypath_address_simple(
    BTCScriptConfig_SimpleType script_type,
    const uint32_t* keypath,
    const size_t keypath_len,
    const uint32_t expected_coin)
{
    check_expected(script_type);
    check_expected(keypath);
    assert_int_equal(keypath_len, 5);
    return __real_btc_common_is_valid_keypath_address_simple(
        script_type, keypath, keypath_len, expected_coin);
}

static uint8_t _mock_seed[32] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
};

static uint8_t _mock_bip39_seed[64] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
};

static void _test_btc_sign_init(void** state)
{
    // establish valid request to modify
    const BTCSignInitRequest init_req_valid = {
        .coin = BTCCoin_BTC,
        .script_config =
            {
                .which_config = BTCScriptConfig_simple_type_tag,
                .config =
                    {
                        .simple_type = BTCScriptConfig_SimpleType_P2WPKH,
                    },
            },
        .keypath_account_count = 3,
        .keypath_account =
            {
                84 + BIP32_INITIAL_HARDENED_CHILD,
                0 + BIP32_INITIAL_HARDENED_CHILD,
                0 + BIP32_INITIAL_HARDENED_CHILD,
            },
        .version = 1,
        .num_inputs = 1,
        .num_outputs = 1,
        .locktime = 0,
    };
    BTCSignNextResponse next = {0};
    { // test valid
        assert_int_equal(APP_BTC_SIGN_OK, app_btc_sign_init(&init_req_valid, &next));
        assert_int_equal(next.type, BTCSignNextResponse_Type_INPUT);
        assert_int_equal(next.index, 0);
    }
    { // test invalid version
        btc_sign_reset();
        BTCSignInitRequest invalid = init_req_valid;
        for (invalid.version = 0; invalid.version < 10; invalid.version++) {
            if (invalid.version == 1 || invalid.version == 2) {
                continue;
            }
            assert_int_equal(APP_BTC_SIGN_ERR_INVALID_INPUT, app_btc_sign_init(&invalid, &next));
        }
    }
    { // test invalid locktime
        btc_sign_reset();
        BTCSignInitRequest invalid = init_req_valid;
        invalid.locktime = 500000000;
        assert_int_equal(APP_BTC_SIGN_ERR_INVALID_INPUT, app_btc_sign_init(&invalid, &next));
    }
    { // test invalid inputs
        btc_sign_reset();
        BTCSignInitRequest invalid = init_req_valid;
        invalid.num_inputs = 0;
        assert_int_equal(APP_BTC_SIGN_ERR_INVALID_INPUT, app_btc_sign_init(&invalid, &next));
    }
    { // test invalid outputs
        btc_sign_reset();
        BTCSignInitRequest invalid = init_req_valid;
        invalid.num_outputs = 0;
        assert_int_equal(APP_BTC_SIGN_ERR_INVALID_INPUT, app_btc_sign_init(&invalid, &next));
    }
    { // test invalid coin
        btc_sign_reset();
        BTCSignInitRequest invalid = init_req_valid;
        invalid.coin = _BTCCoin_MIN - 1;
        assert_int_equal(APP_BTC_SIGN_ERR_INVALID_INPUT, app_btc_sign_init(&invalid, &next));
        invalid.coin = _BTCCoin_MAX + 1;
        assert_int_equal(APP_BTC_SIGN_ERR_INVALID_INPUT, app_btc_sign_init(&invalid, &next));
    }
}

typedef struct {
    // true if the sigs should be checked against fixtures.
    bool check_sigs;
    // keystore seeded?
    bool seeded;
    BTCScriptConfig_SimpleType script_type;
    // all inputs should be the same coin type.
    bool wrong_coin_input;
    // all change outputs should be the same coin type.
    bool wrong_coin_change;
    // all inputs should be from the same account.
    bool wrong_account_input;
    // all change outputs should go the same account.
    bool wrong_account_change;
    // change num in bip44, should be 1.
    uint32_t bip44_change;
    // the sum of the inputs in the 2nd pass can't be higher than in the first
    // for all inputs.
    bool input_sum_changes;
    // at the last input, the sum of the inputs in the 2nd pass must be the same
    // as the sum of the inputs in the first pass
    bool input_sum_last_mismatch;
    // can't init twice in a row -> first input expected
    bool state_init_after_init;
    // wrong state transition
    bool state_output_after_init;
    // sequence number below 0xffffffff - 2
    bool wrong_sequence_number;
    // value 0 is invalid
    bool wrong_input_value;
    bool wrong_output_value;
    // when a user aborts on an output verification
    bool user_aborts_output;
    // rbf disabled on Litecoin
    bool litecoin_rbf_disabled;
    // check workflow when a locktime applies
    bool locktime_applies;
    // when a user aborts on a locktime verification
    bool user_aborts_locktime_rbf;
    // when a user aborts on total/fee verification.
    bool user_aborts_total;
    // if value addition in inputs would overflow
    bool overflow_input_values_pass1;
    bool overflow_input_values_pass2;
    // if outgoing sum overflows
    bool overflow_output_out;
    // if change overflows
    bool overflow_output_ours;
} _modification_t;

// _sign goes through the whole sign process of an example tx, successfully.
// The passed params malleate the behavior to induce expected failures.
static void _sign(const _modification_t* mod)
{
    // Need keystore to derive change and input scripts
    mock_state(mod->seeded ? _mock_seed : NULL, mod->seeded ? _mock_bip39_seed : NULL);

    uint32_t purpose;
    switch (mod->script_type) {
    case BTCScriptConfig_SimpleType_P2WPKH:
        purpose = 84 + BIP32_INITIAL_HARDENED_CHILD;
        break;
    case BTCScriptConfig_SimpleType_P2WPKH_P2SH:
        purpose = 49 + BIP32_INITIAL_HARDENED_CHILD;
        break;
    default:
        assert_true(false);
        return;
    }
    BTCSignInitRequest init_req = {
        .coin = BTCCoin_BTC,
        .script_config =
            {
                .which_config = BTCScriptConfig_simple_type_tag,
                .config =
                    {
                        .simple_type = mod->script_type,
                    },
            },
        .keypath_account_count = 3,
        .keypath_account =
            {
                purpose,
                0 + BIP32_INITIAL_HARDENED_CHILD,
                10 + BIP32_INITIAL_HARDENED_CHILD,
            },
        .version = 1,
        .num_inputs = 2,
        .num_outputs = 6,
        .locktime = 0,
    };

    BTCSignInputRequest inputs[2] = {
        {
            .prevOutHash =
                {
                    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                },
            .prevOutIndex = 2,
            .prevOutValue = 1010000000, // btc 10.1
            .sequence = 0xffffffff,
            .keypath_count = 5,
            .keypath =
                {
                    init_req.keypath_account[0],
                    init_req.keypath_account[1],
                    init_req.keypath_account[2],
                    0,
                    5,
                },
        },
        {
            .prevOutHash =
                {
                    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
                    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
                    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
                },
            .prevOutIndex = 5,
            .prevOutValue = 1020000000, // btc 10.2
            .sequence = 0xffffffff,
            .keypath_count = 5,
            .keypath =
                {
                    init_req.keypath_account[0],
                    init_req.keypath_account[1],
                    init_req.keypath_account[2],
                    0,
                    7,
                },
        },
    };

    if (mod->wrong_account_input) {
        inputs[0].keypath[2] = inputs[0].keypath[2] + 1;
    }
    if (mod->wrong_coin_input) {
        inputs[0].keypath[1] = 1 + BIP32_INITIAL_HARDENED_CHILD;
    }
    if (mod->wrong_sequence_number) {
        inputs[0].sequence = 0;
    }
    if (mod->locktime_applies) {
        init_req.locktime = 1;
        inputs[0].sequence = 0xffffffff - 1;
    }
    if (mod->user_aborts_locktime_rbf) {
        inputs[0].sequence = 0xffffffff - 2;
    }
    if (mod->wrong_input_value) {
        inputs[0].prevOutValue = 0;
    }
    if (mod->overflow_input_values_pass1) {
        inputs[1].prevOutValue = ULLONG_MAX - inputs[0].prevOutValue + 1;
    }

    BTCSignOutputRequest outputs[6] = {
        {
            .ours = false,
            .type = BTCOutputType_P2PKH,
            .value = 100000000, // btc 1
            .hash =
                {
                    .size = 20,
                    .bytes =
                        {
                            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                        },
                },
        },
        {
            .ours = false,
            .type = BTCOutputType_P2SH,
            .value = 1234567890, // btc 12.3456789
            .hash =
                {
                    .size = 20,
                    .bytes =
                        {
                            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                        },
                },
        },
        {
            .ours = false,
            .type = BTCOutputType_P2WPKH,
            .value = 6000, // btc .00006
            .hash =
                {
                    .size = 20,
                    .bytes =
                        {
                            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                        },
                },
        },
        {
            .ours = false,
            .type = BTCOutputType_P2WSH,
            .value = 7000, // btc .00007
            .hash =
                {
                    .size = 32,
                    .bytes =
                        {
                            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                        },
                },
        },
        {
            // change
            .ours = true,
            .value = 690000000, // btc 6.9
            .keypath_count = 5,
            .keypath =
                {
                    init_req.keypath_account[0],
                    init_req.keypath_account[1],
                    init_req.keypath_account[2],
                    mod->bip44_change,
                    3,
                },
        },
        {
            // change #2
            .ours = true,
            .value = 100,
            .keypath_count = 5,
            .keypath =
                {
                    init_req.keypath_account[0],
                    init_req.keypath_account[1],
                    init_req.keypath_account[2],
                    mod->bip44_change,
                    30,
                },
        },
    };
    const uint64_t total = 1339999900; // sum of all non-change outputs + fee
    const uint64_t fee = 5419010; // sum of all inputs - sum of all outputs

    if (mod->wrong_account_change) {
        outputs[4].keypath[2] = outputs[4].keypath[2] + 1;
    }
    if (mod->wrong_coin_change) {
        outputs[4].keypath[1] = 1 + BIP32_INITIAL_HARDENED_CHILD;
    }
    if (mod->wrong_output_value) {
        outputs[0].value = 0;
    }
    if (mod->overflow_output_out) {
        outputs[0].value = ULLONG_MAX;
    }
    if (mod->overflow_output_ours) {
        outputs[4].value = ULLONG_MAX;
    }
    if (mod->litecoin_rbf_disabled) {
        init_req.coin = BTCCoin_LTC;
        init_req.locktime = 1;
        init_req.keypath_account[1] = 2 + BIP32_INITIAL_HARDENED_CHILD;
        inputs[0].sequence = 0xffffffff - 2;
        inputs[0].keypath[1] = 2 + BIP32_INITIAL_HARDENED_CHILD;
        inputs[1].keypath[1] = 2 + BIP32_INITIAL_HARDENED_CHILD;
        outputs[4].keypath[1] = 2 + BIP32_INITIAL_HARDENED_CHILD;
        outputs[5].keypath[1] = 2 + BIP32_INITIAL_HARDENED_CHILD;
    }

    BTCSignNextResponse next = {0};
    assert_int_equal(APP_BTC_SIGN_OK, app_btc_sign_init(&init_req, &next));
    assert_int_equal(next.type, BTCSignNextResponse_Type_INPUT);
    assert_int_equal(next.index, 0);
    assert_false(next.has_signature);

    if (mod->state_init_after_init) {
        assert_int_equal(APP_BTC_SIGN_ERR_STATE, app_btc_sign_init(&init_req, &next));
        return;
    }
    if (mod->state_output_after_init) {
        assert_int_equal(APP_BTC_SIGN_ERR_STATE, app_btc_sign_output(&outputs[0], &next));
        return;
    }

    // === Inputs Pass 1

    // First input, pass1.
    if (!mod->wrong_sequence_number && !mod->wrong_input_value) {
        expect_value(
            __wrap_btc_common_is_valid_keypath_address_simple,
            script_type,
            init_req.script_config.config.simple_type);
        expect_memory(
            __wrap_btc_common_is_valid_keypath_address_simple,
            keypath,
            inputs[0].keypath,
            inputs[0].keypath_count * sizeof(uint32_t));
    }
    if (mod->wrong_coin_input || mod->wrong_account_input || mod->wrong_sequence_number ||
        mod->wrong_input_value) {
        assert_int_equal(APP_BTC_SIGN_ERR_INVALID_INPUT, app_btc_sign_input(&inputs[0], &next));
        return;
    }
    assert_int_equal(APP_BTC_SIGN_OK, app_btc_sign_input(&inputs[0], &next));
    assert_int_equal(next.type, BTCSignNextResponse_Type_INPUT);
    assert_int_equal(next.index, 1);
    assert_false(next.has_signature);

    // Second input, pass1.
    expect_value(
        __wrap_btc_common_is_valid_keypath_address_simple,
        script_type,
        init_req.script_config.config.simple_type);
    expect_memory(
        __wrap_btc_common_is_valid_keypath_address_simple,
        keypath,
        inputs[1].keypath,
        inputs[1].keypath_count * sizeof(uint32_t));
    if (mod->overflow_input_values_pass1) {
        assert_int_equal(APP_BTC_SIGN_ERR_INVALID_INPUT, app_btc_sign_input(&inputs[1], &next));
        return;
    }
    assert_int_equal(APP_BTC_SIGN_OK, app_btc_sign_input(&inputs[1], &next));
    assert_int_equal(next.type, BTCSignNextResponse_Type_OUTPUT);
    assert_int_equal(next.index, 0);
    assert_false(next.has_signature);

    // === Outputs

    // First output
    if (mod->wrong_output_value) {
        assert_int_equal(APP_BTC_SIGN_ERR_INVALID_INPUT, app_btc_sign_output(&outputs[0], &next));
        return;
    }
    expect_value(__wrap_btc_common_format_amount, satoshi, outputs[0].value);
    if (!mod->litecoin_rbf_disabled) {
        expect_string(__wrap_btc_common_format_amount, unit, "BTC");
    } else {
        expect_string(__wrap_btc_common_format_amount, unit, "LTC");
    }
    will_return(__wrap_btc_common_format_amount, "amount0");
    if (!mod->litecoin_rbf_disabled) {
        expect_string(
            __wrap_workflow_verify_recipient, recipient, "12ZEw5Hcv1hTb6YUQJ69y1V7uhcoDz92PH");
    } else {
        expect_string(
            __wrap_workflow_verify_recipient, recipient, "LLnCCHbSzfwWquEdaS5TF2Yt7uz5Qb1SZ1");
    }
    expect_string(__wrap_workflow_verify_recipient, amount, "amount0");
    will_return(__wrap_workflow_verify_recipient, true);
    assert_int_equal(APP_BTC_SIGN_OK, app_btc_sign_output(&outputs[0], &next));
    assert_int_equal(next.type, BTCSignNextResponse_Type_OUTPUT);
    assert_int_equal(next.index, 1);
    assert_false(next.has_signature);

    // Second output
    if (mod->overflow_output_out) {
        assert_int_equal(APP_BTC_SIGN_ERR_INVALID_INPUT, app_btc_sign_output(&outputs[1], &next));
        return;
    }
    expect_value(__wrap_btc_common_format_amount, satoshi, outputs[1].value);
    if (!mod->litecoin_rbf_disabled) {
        expect_string(__wrap_btc_common_format_amount, unit, "BTC");
    } else {
        expect_string(__wrap_btc_common_format_amount, unit, "LTC");
    }
    will_return(__wrap_btc_common_format_amount, "amount1");
    if (!mod->litecoin_rbf_disabled) {
        expect_string(
            __wrap_workflow_verify_recipient, recipient, "34oVnh4gNviJGMnNvgquMeLAxvXJuaRVMZ");
    } else {
        expect_string(
            __wrap_workflow_verify_recipient, recipient, "MB1e6aUeL3Zj4s4H2ZqFBHaaHd7kvvzTco");
    }
    expect_string(__wrap_workflow_verify_recipient, amount, "amount1");
    will_return(__wrap_workflow_verify_recipient, !mod->user_aborts_output);
    if (mod->user_aborts_output) {
        assert_int_equal(APP_BTC_SIGN_ERR_USER_ABORT, app_btc_sign_output(&outputs[1], &next));
        // Check the process is really aborted, can't proceed to next expected output.
        assert_int_equal(APP_BTC_SIGN_ERR_STATE, app_btc_sign_output(&outputs[2], &next));
        return;
    }
    assert_int_equal(APP_BTC_SIGN_OK, app_btc_sign_output(&outputs[1], &next));
    assert_int_equal(next.type, BTCSignNextResponse_Type_OUTPUT);
    assert_int_equal(next.index, 2);
    assert_false(next.has_signature);

    // Third output
    expect_value(__wrap_btc_common_format_amount, satoshi, outputs[2].value);
    if (!mod->litecoin_rbf_disabled) {
        expect_string(__wrap_btc_common_format_amount, unit, "BTC");
    } else {
        expect_string(__wrap_btc_common_format_amount, unit, "LTC");
    }
    will_return(__wrap_btc_common_format_amount, "amount2");
    if (!mod->litecoin_rbf_disabled) {
        expect_string(
            __wrap_workflow_verify_recipient,
            recipient,
            "bc1qxvenxvenxvenxvenxvenxvenxvenxven2ymjt8");
    } else {
        expect_string(
            __wrap_workflow_verify_recipient,
            recipient,
            "ltc1qxvenxvenxvenxvenxvenxvenxvenxvenwcpknh");
    }
    expect_string(__wrap_workflow_verify_recipient, amount, "amount2");
    will_return(__wrap_workflow_verify_recipient, true);
    assert_int_equal(APP_BTC_SIGN_OK, app_btc_sign_output(&outputs[2], &next));
    assert_int_equal(next.type, BTCSignNextResponse_Type_OUTPUT);
    assert_int_equal(next.index, 3);
    assert_false(next.has_signature);

    // Fourth output
    expect_value(__wrap_btc_common_format_amount, satoshi, outputs[3].value);
    if (!mod->litecoin_rbf_disabled) {
        expect_string(__wrap_btc_common_format_amount, unit, "BTC");
    } else {
        expect_string(__wrap_btc_common_format_amount, unit, "LTC");
    }
    will_return(__wrap_btc_common_format_amount, "amount3");
    if (!mod->litecoin_rbf_disabled) {
        expect_string(
            __wrap_workflow_verify_recipient,
            recipient,
            "bc1qg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zqd8sxw4");
    } else {
        expect_string(
            __wrap_workflow_verify_recipient,
            recipient,
            "ltc1qg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zqwr7k5s");
    }
    expect_string(__wrap_workflow_verify_recipient, amount, "amount3");
    will_return(__wrap_workflow_verify_recipient, true);
    assert_int_equal(APP_BTC_SIGN_OK, app_btc_sign_output(&outputs[3], &next));
    assert_int_equal(next.type, BTCSignNextResponse_Type_OUTPUT);
    assert_int_equal(next.index, 4);
    assert_false(next.has_signature);

    // Fifth output, change. Last output also invokes verification of total and
    // fee.
    expect_value(
        __wrap_btc_common_is_valid_keypath_address_simple,
        script_type,
        init_req.script_config.config.simple_type);
    expect_memory(
        __wrap_btc_common_is_valid_keypath_address_simple,
        keypath,
        outputs[4].keypath,
        outputs[4].keypath_count * sizeof(uint32_t));
    if (!mod->seeded) {
        assert_int_equal(APP_BTC_SIGN_ERR_UNKNOWN, app_btc_sign_output(&outputs[4], &next));
        return;
    }
    if (mod->wrong_coin_change || mod->wrong_account_change || mod->bip44_change != 1) {
        assert_int_equal(APP_BTC_SIGN_ERR_INVALID_INPUT, app_btc_sign_output(&outputs[4], &next));
        return;
    }
    assert_int_equal(APP_BTC_SIGN_OK, app_btc_sign_output(&outputs[4], &next));
    assert_int_equal(next.type, BTCSignNextResponse_Type_OUTPUT);
    assert_int_equal(next.index, 5);
    assert_false(next.has_signature);

    // Sixth output, change. Last output also invokes verification of total and
    // fee.
    expect_value(
        __wrap_btc_common_is_valid_keypath_address_simple,
        script_type,
        init_req.script_config.config.simple_type);
    expect_memory(
        __wrap_btc_common_is_valid_keypath_address_simple,
        keypath,
        outputs[5].keypath,
        outputs[5].keypath_count * sizeof(uint32_t));
    if (mod->overflow_output_ours) {
        assert_int_equal(APP_BTC_SIGN_ERR_INVALID_INPUT, app_btc_sign_output(&outputs[5], &next));
        return;
    }

    if (mod->litecoin_rbf_disabled) {
        expect_value(__wrap_apps_btc_confirm_locktime_rbf, locktime, 1);
        expect_value(__wrap_apps_btc_confirm_locktime_rbf, rbf, CONFIRM_LOCKTIME_RBF_DISABLED);
        will_return(__wrap_apps_btc_confirm_locktime_rbf, true);
    }

    if (mod->locktime_applies) {
        expect_value(__wrap_apps_btc_confirm_locktime_rbf, locktime, 1);
        expect_value(__wrap_apps_btc_confirm_locktime_rbf, rbf, CONFIRM_LOCKTIME_RBF_OFF);
        will_return(__wrap_apps_btc_confirm_locktime_rbf, true);
    }

    if (mod->user_aborts_locktime_rbf) {
        expect_value(__wrap_apps_btc_confirm_locktime_rbf, locktime, 0);
        expect_value(__wrap_apps_btc_confirm_locktime_rbf, rbf, CONFIRM_LOCKTIME_RBF_ON);
        will_return(__wrap_apps_btc_confirm_locktime_rbf, false);

        assert_int_equal(APP_BTC_SIGN_ERR_USER_ABORT, app_btc_sign_output(&outputs[5], &next));
        // Check the process is really aborted, can't proceed to next stage.
        assert_int_equal(APP_BTC_SIGN_ERR_STATE, app_btc_sign_input(&inputs[0], &next));
        return;
    }

    expect_value(__wrap_btc_common_format_amount, satoshi, total);
    if (!mod->litecoin_rbf_disabled) {
        expect_string(__wrap_btc_common_format_amount, unit, "BTC");
    } else {
        expect_string(__wrap_btc_common_format_amount, unit, "LTC");
    }
    will_return(__wrap_btc_common_format_amount, "amount total");
    expect_value(__wrap_btc_common_format_amount, satoshi, fee);
    if (!mod->litecoin_rbf_disabled) {
        expect_string(__wrap_btc_common_format_amount, unit, "BTC");
    } else {
        expect_string(__wrap_btc_common_format_amount, unit, "LTC");
    }
    will_return(__wrap_btc_common_format_amount, "amount fee");
    expect_string(__wrap_workflow_verify_total, total, "amount total");
    expect_string(__wrap_workflow_verify_total, fee, "amount fee");
    will_return(__wrap_workflow_verify_total, !mod->user_aborts_total);
    if (mod->user_aborts_total) {
        assert_int_equal(APP_BTC_SIGN_ERR_USER_ABORT, app_btc_sign_output(&outputs[5], &next));
        // Check the process is really aborted, can't proceed to next stage.
        assert_int_equal(APP_BTC_SIGN_ERR_STATE, app_btc_sign_input(&inputs[0], &next));
        return;
    }
    assert_int_equal(APP_BTC_SIGN_OK, app_btc_sign_output(&outputs[5], &next));
    assert_int_equal(next.type, BTCSignNextResponse_Type_INPUT);
    assert_int_equal(next.index, 0);
    assert_false(next.has_signature);

    // === Inputs Pass 2

    if (mod->input_sum_changes) {
        inputs[0].prevOutValue += inputs[1].prevOutValue + 1;
    }
    if (mod->input_sum_last_mismatch) {
        inputs[0].prevOutValue -= 1; // errors even if we decrease the amount
    }
    if (mod->overflow_input_values_pass2) {
        inputs[1].prevOutValue = ULLONG_MAX - inputs[0].prevOutValue + 1;
    }

    // First input, pass2.
    expect_value(
        __wrap_btc_common_is_valid_keypath_address_simple,
        script_type,
        init_req.script_config.config.simple_type);
    expect_memory(
        __wrap_btc_common_is_valid_keypath_address_simple,
        keypath,
        inputs[0].keypath,
        inputs[0].keypath_count * sizeof(uint32_t));
    if (mod->input_sum_changes) {
        assert_int_equal(APP_BTC_SIGN_ERR_INVALID_INPUT, app_btc_sign_input(&inputs[0], &next));
        return;
    }
    assert_int_equal(APP_BTC_SIGN_OK, app_btc_sign_input(&inputs[0], &next));
    assert_int_equal(next.type, BTCSignNextResponse_Type_INPUT);
    assert_int_equal(next.index, 1);
    assert_true(next.has_signature);
    if (mod->check_sigs) {
        switch (mod->script_type) {
        case BTCScriptConfig_SimpleType_P2WPKH: {
            const uint8_t expected_signature[64] =
                "\x91\x04\x8b\x6a\x46\x79\x89\x11\xfd\x2a\x11\x37\xc2\x8d\x1b\xa2\x66\x7e\x75\xf8"
                "\x42\x4c\x25\xfd\x38\x35\x3f\x5c\x6e\x51\x0f\xa9\x28\x49\x5c\xcd\x93\x51\x61\x21"
                "\xdd\xb3\xe7\xc4\xf6\xb8\x2b\x12\xe6\xb8\x3b\xb0\x9f\x09\x21\x49\x3c\xac\x0a\xa9"
                "\x54\xb9\xc5\x33";
            assert_memory_equal(next.signature, expected_signature, sizeof(next.signature));
            break;
        }
        case BTCScriptConfig_SimpleType_P2WPKH_P2SH: {
            const uint8_t expected_signature[64] =
                "\x2b\x78\x5c\x23\x21\x6a\x00\xca\xf9\x83\x62\xeb\x4e\xa2\x46\xf5\xf4\x90\xad\xc8"
                "\xe1\x1d\x3f\x42\x4b\xa2\x10\x5d\xea\x37\x0f\x55\x05\x85\xcc\x0b\x3a\x49\x1c\x0f"
                "\xb4\xe0\x62\xb4\x38\x14\xa6\x43\x37\x88\x09\xaf\x80\x92\x62\x71\x4b\x15\x2b\xb6"
                "\x1d\xfd\xaa\x85";
            assert_memory_equal(next.signature, expected_signature, sizeof(next.signature));
            break;
        }
        default:
            assert_true(false);
        }
    }

    // Second input, pass2.
    expect_value(
        __wrap_btc_common_is_valid_keypath_address_simple,
        script_type,
        init_req.script_config.config.simple_type);
    expect_memory(
        __wrap_btc_common_is_valid_keypath_address_simple,
        keypath,
        inputs[1].keypath,
        inputs[1].keypath_count * sizeof(uint32_t));
    if (mod->input_sum_last_mismatch || mod->overflow_input_values_pass2) {
        assert_int_equal(APP_BTC_SIGN_ERR_INVALID_INPUT, app_btc_sign_input(&inputs[1], &next));
        return;
    }
    assert_int_equal(APP_BTC_SIGN_OK, app_btc_sign_input(&inputs[1], &next));
    assert_int_equal(next.type, BTCSignNextResponse_Type_DONE);
    assert_true(next.has_signature);
    if (mod->check_sigs) {
        switch (mod->script_type) {
        case BTCScriptConfig_SimpleType_P2WPKH: {
            const uint8_t expected_signature[64] =
                "\x95\x09\x43\x09\xa2\xd2\x77\xd3\xa6\x8d\xde\xd3\x3d\x50\xa7\x47\xf2\xee\xfb\x3f"
                "\x54\x8a\x92\x45\x15\xdb\x62\xbe\x06\xa1\xae\xa4\x56\x92\x91\xe5\x2e\x6f\xea\x95"
                "\xf8\xb6\x75\x23\xb1\x9b\x35\x9a\x84\x85\xd8\xaa\x3c\xa0\x2d\xb3\x74\x70\x01\x0b"
                "\x19\x9b\x0c\xe3";
            assert_memory_equal(next.signature, expected_signature, sizeof(next.signature));
            break;
        }
        case BTCScriptConfig_SimpleType_P2WPKH_P2SH: {
            const uint8_t expected_signature[64] =
                "\x73\x18\xa7\x22\x5a\x53\xa7\x37\x67\x4c\x07\xb5\x9c\x46\xbe\x07\x38\xc5\x1b\x56"
                "\x3a\x90\x25\xf4\x71\x70\x8d\xac\x0a\x93\xa3\x12\x2d\xc5\x9f\xa5\x1c\xbc\xd6\xa4"
                "\xc0\xba\x16\xb5\xe4\x82\xc3\x92\x40\x1b\x99\x82\x05\x01\xb2\x35\x34\x70\x87\x8c"
                "\x59\x8c\x52\x8a";
            assert_memory_equal(next.signature, expected_signature, sizeof(next.signature));
            break;
        }
        default:
            assert_false(true);
        }
    }
}

static const _modification_t _valid = {
    .script_type = BTCScriptConfig_SimpleType_P2WPKH,
    .seeded = true,
    .bip44_change = 1,
};

static void _test_btc_sign(void** state)
{
    _modification_t valid = _valid;
    valid.check_sigs = true;
    _sign(&valid);
}
static void _test_seeded(void** state)
{
    _modification_t invalid = _valid;
    invalid.seeded = false;
    _sign(&invalid);
}
static void _test_script_type_p2wpkh_p2sh(void** state)
{
    _modification_t invalid = _valid;
    invalid.script_type = BTCScriptConfig_SimpleType_P2WPKH_P2SH;
    invalid.check_sigs = true;
    _sign(&invalid);
}
static void _test_wrong_coin_input(void** state)
{
    _modification_t invalid = _valid;
    invalid.wrong_coin_input = true;
    _sign(&invalid);
}
static void _test_wrong_coin_change(void** state)
{
    _modification_t invalid = _valid;
    invalid.wrong_coin_change = true;
    _sign(&invalid);
}
static void _test_wrong_account_input(void** state)
{
    _modification_t invalid = _valid;
    invalid.wrong_account_input = true;
    _sign(&invalid);
}
static void _test_wrong_account_change(void** state)
{
    _modification_t invalid = _valid;
    invalid.wrong_account_change = true;
    _sign(&invalid);
}
static void _test_btc_bip44_change(void** state)
{
    _modification_t invalid = _valid;
    invalid.bip44_change = 0;
    _sign(&invalid);
    invalid.bip44_change = 2;
    _sign(&invalid);
}
static void _test_input_sum_changes(void** state)
{
    _modification_t invalid = _valid;
    invalid.input_sum_changes = true;
    _sign(&invalid);
}
static void _test_input_sum_last_mismatch(void** state)
{
    _modification_t invalid = _valid;
    invalid.input_sum_last_mismatch = true;
    _sign(&invalid);
}
static void _test_state_init_after_init(void** state)
{
    _modification_t invalid = _valid;
    invalid.state_init_after_init = true;
    _sign(&invalid);
}
static void _test_state_output_after_init(void** state)
{
    _modification_t invalid = _valid;
    invalid.state_output_after_init = true;
    _sign(&invalid);
}
static void _test_wrong_sequence_number(void** state)
{
    _modification_t invalid = _valid;
    invalid.wrong_sequence_number = true;
    _sign(&invalid);
}
static void _test_wrong_input_value(void** state)
{
    _modification_t invalid = _valid;
    invalid.wrong_input_value = true;
    _sign(&invalid);
}
static void _test_wrong_output_value(void** state)
{
    _modification_t invalid = _valid;
    invalid.wrong_output_value = true;
    _sign(&invalid);
}
static void _test_user_aborts_output(void** state)
{
    _modification_t invalid = _valid;
    invalid.user_aborts_output = true;
    _sign(&invalid);
}
static void _test_litecoin_rbf_disabled(void** state)
{
    _modification_t invalid = _valid;
    invalid.litecoin_rbf_disabled = true;
    _sign(&invalid);
}
static void _test_locktime_applies(void** state)
{
    _modification_t invalid = _valid;
    invalid.locktime_applies = true;
    _sign(&invalid);
}
static void _test_user_aborts_locktime_rbf(void** state)
{
    _modification_t invalid = _valid;
    invalid.user_aborts_locktime_rbf = true;
    _sign(&invalid);
}
static void _test_user_aborts_total(void** state)
{
    _modification_t invalid = _valid;
    invalid.user_aborts_total = true;
    _sign(&invalid);
}
static void _test_overflow_input_values_pass1(void** state)
{
    _modification_t invalid = _valid;
    invalid.overflow_input_values_pass1 = true;
    _sign(&invalid);
}
static void _test_overflow_input_values_pass2(void** state)
{
    _modification_t invalid = _valid;
    invalid.overflow_input_values_pass2 = true;
    _sign(&invalid);
}
static void _test_overflow_output_out(void** state)
{
    _modification_t invalid = _valid;
    invalid.overflow_output_out = true;
    _sign(&invalid);
}
static void _test_overflow_output_ours(void** state)
{
    _modification_t invalid = _valid;
    invalid.overflow_output_ours = true;
    _sign(&invalid);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(_test_btc_sign),
        cmocka_unit_test(_test_btc_sign_init),

        cmocka_unit_test(_test_seeded),
        cmocka_unit_test(_test_script_type_p2wpkh_p2sh),
        cmocka_unit_test(_test_wrong_coin_input),
        cmocka_unit_test(_test_wrong_coin_change),
        cmocka_unit_test(_test_wrong_account_input),
        cmocka_unit_test(_test_wrong_account_change),
        cmocka_unit_test(_test_btc_bip44_change),
        cmocka_unit_test(_test_input_sum_changes),
        cmocka_unit_test(_test_input_sum_last_mismatch),
        cmocka_unit_test(_test_state_init_after_init),
        cmocka_unit_test(_test_state_output_after_init),
        cmocka_unit_test(_test_wrong_sequence_number),
        cmocka_unit_test(_test_wrong_input_value),
        cmocka_unit_test(_test_wrong_output_value),
        cmocka_unit_test(_test_user_aborts_output),
        cmocka_unit_test(_test_litecoin_rbf_disabled),
        cmocka_unit_test(_test_locktime_applies),
        cmocka_unit_test(_test_user_aborts_locktime_rbf),
        cmocka_unit_test(_test_user_aborts_total),
        cmocka_unit_test(_test_overflow_input_values_pass1),
        cmocka_unit_test(_test_overflow_input_values_pass2),
        cmocka_unit_test(_test_overflow_output_out),
        cmocka_unit_test(_test_overflow_output_ours),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

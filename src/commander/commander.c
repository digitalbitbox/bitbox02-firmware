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

#include <platform_config.h>

#include "commander.h"
#if APP_BTC == 1 || APP_LTC == 1
#include "commander/commander_btc.h"
#endif
#if APP_ETH == 1
#include "commander/commander_eth.h"
#endif
#include "commander/commander_states.h"
#if PRODUCT_BITBOX_BASE == 1
#include "rust/bitbox02_rust.h"
#endif

#include <flags.h>
#include <hardfault.h>
#include <memory/memory.h>
#include <platform_config.h>
#include <random.h>
#include <screen.h>
#include <sd.h>
#include <util.h>
#include <version.h>

#ifndef TESTING
#include <securechip/securechip.h>
#else
#include <test_commander.h>
#endif

#include <workflow/backup.h>
#include <workflow/confirm.h>
#include <workflow/create_seed.h>
#include <workflow/reboot.h>
#include <workflow/reset.h>
#include <workflow/restore.h>
#include <workflow/restore_from_mnemonic.h>
#include <workflow/sdcard.h>
#include <workflow/show_mnemonic.h>
#include <workflow/workflow.h>

#include "hww.pb.h"
#include <pb_decode.h>
#include <pb_encode.h>

#define X(a, b, c) b,
static const int32_t _error_code[] = {COMMANDER_ERROR_TABLE};
#undef X

#define X(a, b, c) c,
static const char* const _error_message[] = {COMMANDER_ERROR_TABLE};
#undef X

static void _report_error(Response* response, commander_error_t error_code)
{
    Error* error = &(response->response.error);
    error->code = _error_code[error_code];
    snprintf(error->message, sizeof(error->message), "%s", _error_message[error_code]);
    response->which_response = Response_error_tag;
}

// ------------------------------------ API ------------------------------------- //

#if PLATFORM_BITBOX02 == 1
/**
 * Retrieves a random number, displays it and encodes it into the passed stream.
 * Returns 0 if the encoding failed and the message length if the encoding was
 * successful.
 */
static void _api_process_random(RandomNumberResponse* response)
{
    uint8_t number[RANDOM_NUM_SIZE];
    random_32_bytes(number);

    static char number_hex[BB_HEX_SIZE(number)]; // TODO cleanup
    util_uint8_to_hex(number, sizeof(number), number_hex);

    char number_hex_formatted[BB_HEX_SIZE(number) + 3];
    snprintf(
        number_hex_formatted,
        sizeof(number_hex_formatted),
        "%.16s\n%.16s\n%.16s\n%.16s",
        number_hex,
        number_hex + 16,
        number_hex + 32,
        number_hex + 48);

    workflow_confirm_dismiss("Random", number_hex_formatted);

    memcpy(&response->number, number, sizeof(number));
}

static commander_error_t _api_get_info(DeviceInfoResponse* device_info)
{
    char get_name[MEMORY_DEVICE_NAME_MAX_LEN];
    memory_get_device_name(get_name);
    snprintf(device_info->name, sizeof(device_info->name), "%s", get_name);
    snprintf(
        device_info->version, sizeof(device_info->version), "%s", DIGITAL_BITBOX_VERSION_SHORT);
    device_info->initialized = commander_states_state() == COMMANDER_STATES_INITIALIZED;
    device_info->mnemonic_passphrase_enabled = memory_is_mnemonic_passphrase_enabled();
#ifndef TESTING
    if (!securechip_monotonic_increments_remaining(&device_info->monotonic_increments_remaining)) {
        return COMMANDER_ERR_GENERIC;
    }
#endif
    return COMMANDER_OK;
}

static commander_error_t _api_set_device_name(const SetDeviceNameRequest* request)
{
    if (!workflow_confirm_scrollable("Name", request->name, NULL, false)) {
        return COMMANDER_ERR_USER_ABORT;
    }
    if (!memory_set_device_name(request->name)) {
        return COMMANDER_ERR_MEMORY;
    }
    return COMMANDER_OK;
}

static commander_error_t _api_set_password(const SetPasswordRequest* request)
{
    if (!workflow_create_seed(request->entropy)) {
        return COMMANDER_ERR_GENERIC;
    }
    return COMMANDER_OK;
}

static commander_error_t _api_create_backup(const CreateBackupRequest* create_backup)
{
    if (!workflow_backup_create(create_backup)) {
        return COMMANDER_ERR_GENERIC;
    }
    return COMMANDER_OK;
}

static commander_error_t _api_list_backups(ListBackupsResponse* response)
{
    if (!workflow_list_backups(response)) {
        return COMMANDER_ERR_GENERIC;
    }
    return COMMANDER_OK;
}

static commander_error_t _api_restore_backup(const RestoreBackupRequest* request)
{
    if (!workflow_restore_backup(request)) {
        return COMMANDER_ERR_GENERIC;
    }
    return COMMANDER_OK;
}

static commander_error_t _api_check_backup(
    const CheckBackupRequest* request,
    CheckBackupResponse* response)
{
    if (!sd_card_inserted()) {
        return COMMANDER_ERR_INVALID_INPUT;
    }
    if (!workflow_backup_check(response->id, request->silent)) {
        return COMMANDER_ERR_GENERIC;
    }
    return COMMANDER_OK;
}

static commander_error_t _api_show_mnemonic(void)
{
    if (!workflow_show_mnemonic_create()) {
        return COMMANDER_ERR_GENERIC;
    }
    return COMMANDER_OK;
}

static commander_error_t _api_check_sdcard(CheckSDCardResponse* response)
{
    response->inserted = sd_card_inserted();
    return COMMANDER_OK;
}

static commander_error_t _api_insert_remove_sdcard(const InsertRemoveSDCardRequest* request)
{
    sdcard_handle(request);
    return COMMANDER_OK;
}

static commander_error_t _api_set_mnemonic_passphrase_enabled(
    const SetMnemonicPassphraseEnabledRequest* request)
{
    if (!workflow_confirm(
            request->enabled ? "Enable" : "Disable", "Optional\npassphrase", NULL, true, false)) {
        return COMMANDER_ERR_USER_ABORT;
    }
    if (!memory_set_mnemonic_passphrase_enabled(request->enabled)) {
        return COMMANDER_ERR_MEMORY;
    }
    return COMMANDER_OK;
}

static commander_error_t _api_reset(void)
{
    if (!workflow_reset()) {
        return COMMANDER_ERR_GENERIC;
    }
    return COMMANDER_OK;
}

static commander_error_t _api_restore_from_mnemonic(const RestoreFromMnemonicRequest* request)
{
    if (!workflow_restore_from_mnemonic(request)) {
        return COMMANDER_ERR_GENERIC;
    }
    return COMMANDER_OK;
}
#endif

static commander_error_t _api_reboot(void)
{
    if (!workflow_reboot()) {
        return COMMANDER_ERR_GENERIC;
    }
    return COMMANDER_OK;
}

// ------------------------------------ Parse ------------------------------------- //

/**
 * Parses a given protobuf input stream and prepares the request type.
 */
static commander_error_t _parse(pb_istream_t* in_stream, Request* request)
{
    bool status = pb_decode(in_stream, Request_fields, request);
    return status ? COMMANDER_OK : COMMANDER_ERR_INVALID_INPUT;
}

// ------------------------------------ Process ------------------------------------- //

/**
 * Processes the command and forwards it to the requested function.
 */
static commander_error_t _api_process(const Request* request, Response* response)
{
    switch (request->which_request) {
#if PLATFORM_BITBOX02 == 1
    case Request_random_number_tag:
        response->which_response = Response_random_number_tag;
        _api_process_random(&(response->response.random_number));
        return COMMANDER_OK;
    case Request_device_info_tag:
        response->which_response = Response_device_info_tag;
        return _api_get_info(&(response->response.device_info));
    case Request_device_name_tag:
        response->which_response = Response_success_tag;
        return _api_set_device_name(&(request->request.device_name));
    case Request_set_password_tag:
        response->which_response = Response_success_tag;
        return _api_set_password(&(request->request.set_password));
    case Request_create_backup_tag:
        response->which_response = Response_success_tag;
        return _api_create_backup(&(request->request.create_backup));
    case Request_show_mnemonic_tag:
        response->which_response = Response_success_tag;
        return _api_show_mnemonic();
#if APP_BTC == 1 || APP_LTC == 1
    case Request_btc_pub_tag:
        response->which_response = Response_pub_tag;
        return commander_btc_pub(&(request->request.btc_pub), &(response->response.pub));
    case Request_btc_sign_init_tag:
    case Request_btc_sign_input_tag:
    case Request_btc_sign_output_tag:
        return commander_btc_sign(request, response);
#else
    case Request_btc_pub_tag:
    case Request_btc_sign_init_tag:
    case Request_btc_sign_input_tag:
    case Request_btc_sign_output_tag:
        return COMMANDER_ERR_DISABLED;
#endif
    case Request_check_sdcard_tag:
        response->which_response = Response_check_sdcard_tag;
        return _api_check_sdcard(&(response->response.check_sdcard));
    case Request_insert_remove_sdcard_tag:
        response->which_response = Response_success_tag;
        _api_insert_remove_sdcard(&(request->request.insert_remove_sdcard));
        return COMMANDER_OK;
    case Request_set_mnemonic_passphrase_enabled_tag:
        response->which_response = Response_success_tag;
        return _api_set_mnemonic_passphrase_enabled(
            &(request->request.set_mnemonic_passphrase_enabled));
    case Request_list_backups_tag:
        response->which_response = Response_list_backups_tag;
        return _api_list_backups(&(response->response.list_backups));
    case Request_restore_backup_tag:
        response->which_response = Response_success_tag;
        return _api_restore_backup(&(request->request.restore_backup));
    case Request_check_backup_tag:
        response->which_response = Response_check_backup_tag;
        return _api_check_backup(
            &(request->request.check_backup), &(response->response.check_backup));
#if APP_ETH == 1
    case Request_eth_tag:
        response->which_response = Response_eth_tag;
        return commander_eth(&(request->request.eth), &(response->response.eth));
#else
    case Request_eth_tag:
        return COMMANDER_ERR_DISABLED;
#endif
    case Request_reset_tag:
        response->which_response = Response_success_tag;
        return _api_reset();
    case Request_restore_from_mnemonic_tag:
        response->which_response = Response_success_tag;
        return _api_restore_from_mnemonic(&(request->request.restore_from_mnemonic));
#endif
#if PRODUCT_BITBOX_BASE == 1
    case Request_bitboxbase_tag:
        response->which_response = Response_success_tag;
        return commander_bitboxbase(&(request->request.bitboxbase));
#endif
    case Request_reboot_tag:
        response->which_response = Response_success_tag;
        return _api_reboot();
    default:
        screen_print_debug("command unknown", 1000);
        return COMMANDER_ERR_INVALID_INPUT;
    }
}

/**
 * Receives and processes a command.
 */
size_t commander(
    const uint8_t* input,
    const size_t in_len,
    uint8_t* output,
    const size_t max_out_len)
{
    Response response = Response_init_zero;

    pb_istream_t in_stream = pb_istream_from_buffer(input, in_len);
    Request request;
    commander_error_t err = _parse(&in_stream, &request);
    if (err == COMMANDER_OK) {
        if (!commander_states_can_call(request.which_request)) {
            err = COMMANDER_ERR_INVALID_STATE;
        } else {
            // Since we will process the call now, so can clear the 'force next' info.
            // We do this before processing as the api call can potentially define the next api call
            // to be forced.
            commander_states_clear_force_next();

            err = _api_process(&request, &response);
            util_zero(&request, sizeof(request));
        }
    }
    if (err != COMMANDER_OK) {
        _report_error(&response, err);
    }

    pb_ostream_t out_stream = pb_ostream_from_buffer(output, max_out_len);
    if (!pb_encode(&out_stream, Response_fields, &response)) {
        Abort("Abort: pb_encode");
    }
    return out_stream.bytes_written;
}

#ifdef TESTING
commander_error_t commander_api_set_device_name(const SetDeviceNameRequest* request)
{
    return _api_set_device_name(request);
}
commander_error_t commander_api_set_mnemonic_passphrase_enabled(
    const SetMnemonicPassphraseEnabledRequest* request)
{
    return _api_set_mnemonic_passphrase_enabled(request);
}
#endif

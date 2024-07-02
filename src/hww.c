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

#include "hww.h"

#include <hardfault.h>
#include <keystore.h>
#include <memory/memory.h>

#include <platform_config.h>
#include <rust/rust.h>
#include <usb/usb_packet.h>
#include <usb/usb_processing.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/** Request command for HWW packets. */
typedef enum {
    HWW_REQ_NEW = 0,
    HWW_REQ_RETRY = 1,
    HWW_REQ_CANCEL = 2,
    HWW_REQ_INFO = ((uint8_t)'i'),
} hww_req_t;

/** Response status code for HWW packets. */
typedef enum {
    HWW_RSP_ACK = 0,
    HWW_RSP_NOT_READY = 1,
    HWW_RSP_BUSY = 2,
    HWW_RSP_NACK = 3,
} hww_rsp_t;

/** A HWW response is composed of a status code and a payload. */
typedef struct {
    /** Status byte. */
    hww_rsp_t status;
    /** Payload of the message. */
    buffer_t buffer;
} hww_packet_rsp_t;

/**
 * Serializes sytem information to the buffer.
 * The following bytes are written:
 * 1 byte: length of the version string that follows.
 * N bytes: short firmware version string, ascii encoded. E.g. "v4.12.2". Not null terminated.
 * 1 byte: platform code:
 * - 0x00 - BitBox02
 * - 0x01 - BitBoxBase (deprecated)
 * 1 byte: edition code:
 * - For the BitBox02 edition:
 * - - 0x00 - Multi
 * - - 0x01 - Bitcoin-only
 * - For the BitBoxBase platform (deprecated):
 " - 0x00 - Standard
 * 1 byte: 0x00 if the device is locked, 0x01 if the device is unlocked.
 * 1 byte: 0x00 if the device is uninitialized, 0x01 if the device is initialized.
 * @param[out] buf serialize info to this buffer.
 * @return number of bytes written
 */
static size_t _api_info(uint8_t* buf)
{
    uint8_t* current = buf;
    // version string, 1 byte len prefix
    size_t version_string_len = sizeof(DIGITAL_BITBOX_VERSION_SHORT) - 1;
    if (version_string_len > 255) {
        Abort("OP_INFO: version string too long");
    }
    *current = (uint8_t)version_string_len;
    current++;
    memcpy((char*)current, DIGITAL_BITBOX_VERSION_SHORT, version_string_len);
    current += version_string_len;

    // 1 byte platform code and 1 byte edition code
#if PRODUCT_BITBOX_MULTI == 1 || PRODUCT_BITBOX02_FACTORYSETUP == 1
    *current = 0x00;
    current++;
    *current = 0x00;
#elif PRODUCT_BITBOX_BTCONLY == 1
    *current = 0x00;
    current++;
    *current = 0x01;
#endif
    current++;

    // 1 byte locked status
    *current = keystore_is_locked() ? 0x00 : 0x01;
    current++;

    // 1 byte initialized status
    *current = memory_is_initialized() ? 0x01 : 0x00;
    current++;

    return current - buf;
}

/**
 * Polls the current operation (if any). If the current operation
 * is finished, respond appropriately.
 *
 * @param[out] response Response data to fill.
 */
static void _maybe_write_response(hww_packet_rsp_t* response)
{
    switch (rust_async_usb_copy_response(&response->buffer)) {
    case UsbResponseAck:
        response->status = HWW_RSP_ACK;
        usb_processing_unlock();
        break;
    case UsbResponseNotReady:
        response->status = HWW_RSP_NOT_READY;
        break;
    default:
        response->status = HWW_RSP_NACK;
        break;
    }
}

/**
 * Executes the HWW packet.
 * @param[in] in_req The incoming HWW packet.
 * @param[in] out_rsp The outgoing HWW packet.
 */
static void _process_packet(const in_buffer_t* in_req, hww_packet_rsp_t* out_rsp)
{
    out_rsp->status = HWW_RSP_NACK;
    // Spawn async task, which is polled in the main loop.
    rust_async_usb_on_request_hww(rust_util_bytes(in_req->data, in_req->len));
    // Lock USB stack so U2F requests get a BUSY response.
    usb_processing_lock(usb_processing_hww());
    // Some tasks have an 'early return' path that is not blocking. We spin the task once so we can
    // return immediately in if there is an early return, so the client does not have to wait ~200ms
    // for a response that can be made available immediately.
    rust_async_usb_spin();
    // Respond with NOT_READY if the async task needs more time, or ACK with the payload if the task
    // already completed (in this case, USB stack is unlocked again).
    _maybe_write_response(out_rsp);
}

/**
 * Aborts the current operation (if any). Reply with an
 * appropriate failure state, depending on what the cancelled
 * operation was.
 *
 * @param[out] response Response data to fill.
 */
static void _cancel_packet(hww_packet_rsp_t* response)
{
    response->status = HWW_RSP_NACK;
    // TODO: cancel async usb task.
}

static void _msg(const Packet* in_packet, Packet* out_packet, const size_t max_out_len)
{
    if (in_packet->len == 0) {
        out_packet->data_addr[0] = HWW_RSP_NACK;
        out_packet->len = 1;
        return;
    }

    hww_req_t cmd = in_packet->data_addr[0];
    if (cmd == HWW_REQ_INFO) {
        // HWW_REQ_INFO is treated as a special case: it has a direct response without a status
        // code, so it can be called independently of the firmware version and framing protocol.
        // Before v7.0.0, there was no HWW framing layer, and the info call was an api-call using
        // the same 'i' OP_INFO op code byte.
        out_packet->len = _api_info(out_packet->data_addr);
        return;
    }

    const in_buffer_t decoded_buffer = {
        .data = in_packet->data_addr + 1,
        .len = in_packet->len - 1,
    };
    hww_packet_rsp_t response = {
        .status = HWW_RSP_NACK,
        .buffer = {.data = out_packet->data_addr + 1, .len = 0, .max_len = max_out_len - 1}};
    switch (cmd) {
    case HWW_REQ_NEW:
        _process_packet(&decoded_buffer, &response);
        break;
    case HWW_REQ_CANCEL:
        /* We don't have anything to cancel yet. */
        _cancel_packet(&response);
        break;
    case HWW_REQ_RETRY:
        _maybe_write_response(&response);
        break;
    default:
        break;
    }
    out_packet->data_addr[0] = response.status;
    if (response.status == HWW_RSP_ACK) {
        out_packet->len = response.buffer.len + 1;
    } else {
        out_packet->len = 1;
    }
}

bool hww_blocking_request_can_go_through(const Packet* in_packet)
{
    if (in_packet->len != 1) {
        return false;
    }
    uint8_t cmd = in_packet->data_addr[0];
    return cmd == HWW_REQ_CANCEL || cmd == HWW_REQ_RETRY;
}

void hww_blocked_req_error(Packet* out_packet, const Packet* in_packet)
{
    (void)in_packet;
    out_packet->len = 1;
    out_packet->data_addr[0] = HWW_RSP_BUSY;
}

void hww_abort_outstanding_op(void)
{
    rust_async_usb_cancel();
}

void hww_process(void)
{
    /** Nothing to do. */
}

void hww_setup(void)
{
    const CMD_Callback hww_cmd_callbacks[] = {{HWW_MSG, _msg}};
    usb_processing_register_cmds(
        usb_processing_hww(), hww_cmd_callbacks, sizeof(hww_cmd_callbacks) / sizeof(CMD_Callback));
}

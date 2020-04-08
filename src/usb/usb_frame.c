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

#include "usb_frame.h"
#include "queue.h"
#if APP_U2F == 1
#include "u2f/u2f_packet.h"
#endif
#include "usb/u2f/u2f_hid.h"
#include "usb/usb_packet.h"
#include "util.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ERR_NONE 0

/**
 * Copies the given data to the buffer and either waits for more data to
 * arrive or iterates through the array of registered cmds and processes the
 * command.
 * @param[out] state The state to which the data is appended.
 */
static void _read_data(State* state, const uint8_t* data, size_t length)
{
    memcpy(state->buf_ptr, data, length);
    state->buf_ptr += length;
}

/**
 * Initializes the USB frame packet.
 */
static int32_t _cmd_init(const USB_FRAME* frame, State* state)
{
    // It is allowed to resynchronize a channel so only abort if another application tries to send
    // an init command
    if (state->initialized && frame->cid != state->cid && state->cmd == U2FHID_INIT) {
        return FRAME_ERR_CHANNEL_BUSY;
    }

    // The device is only busy if an app has successfully sent a complete INIT request. Any other
    // requests can be aborted by new requsts from other apps.
    if (state->initialized && frame->cid != state->cid && frame->type != U2FHID_INIT &&
        state->cmd != U2FHID_INIT) {
        return FRAME_ERR_CHANNEL_BUSY;
    }

    // Don't expect an initial usb report if we already have received one. Except if it is a
    // app trying to resynchronize.
    if (state->initialized && frame->cid == state->cid && (frame->type != U2FHID_INIT)) {
        return FRAME_ERR_INVALID_SEQ;
    }

    if ((unsigned)FRAME_MSG_LEN(*frame) > sizeof(state->data)) {
        return FRAME_ERR_INVALID_LEN;
    }

    // Enable timer for this packet
#if APP_U2F == 1
    if (frame->type < U2FHID_VENDOR_FIRST) {
        u2f_packet_timeout_enable(frame->cid);
    }
#endif

    memset(state, 0, sizeof(State));
    state->seq = 0;
    state->buf_ptr = state->data;
    state->len = FRAME_MSG_LEN(*frame);
    state->cmd = frame->type;
    state->cid = frame->cid;
    state->initialized = 1;

    _read_data(state, frame->init.data, MIN(state->len, sizeof(frame->init.data)));
    return ERR_NONE;
}

/**
 * Processes continuation frames.
 */
static int32_t _cmd_continue(const USB_FRAME* frame, State* state)
{
    // Silently drop unsolicited continuation frames
    if (!state->initialized) {
        return FRAME_ERR_IGNORE;
    }

    // expected a continuation frame with channel id 'cid', but received
    // another continuation frame
    if (state->cid != frame->cid) {
        return FRAME_ERR_CHANNEL_BUSY;
    }

    if (state->seq != FRAME_SEQ(*frame)) {
        return FRAME_ERR_INVALID_SEQ;
    }

    size_t already_read = (state->buf_ptr - state->data);
    // Check bounds
    if (already_read >= state->len ||
        (already_read + sizeof(frame->cont.data)) > sizeof(state->data)) {
        return FRAME_ERR_INVALID_LEN;
    }

    state->seq++;
    _read_data(state, frame->cont.data, MIN(state->len - already_read, sizeof(frame->cont.data)));
    return ERR_NONE;
}

/**
 * Prepares USB frames to be send to the host.
 * param[in] data The data is copied into one or more frames
 */
void usb_frame_reply(
    uint8_t cmd,
    const uint8_t* data,
    uint32_t len,
    uint32_t cid,
    struct queue* queue)
{
    USB_FRAME frame;
    uint32_t cnt = 0;
    uint32_t l = len;
    uint32_t psz;
    uint8_t seq = 0;

    memset(&frame, 0, sizeof(frame));
    frame.cid = cid;
    frame.init.cmd = cmd;
    frame.init.bcnth = len >> 8;
    frame.init.bcntl = len & 0xff;

    // Init frame
    psz = MIN(sizeof(frame.init.data), l);
    memcpy(frame.init.data, data, psz);
    queue_push_retry(queue, (const uint8_t*)&frame);
    l -= psz;
    cnt += psz;

    // Cont frame(s)
    for (; l > 0; l -= psz, cnt += psz) {
        memset(&frame.cont.data, 0, sizeof(frame.cont.data));
        frame.cont.seq = seq++;
        psz = MIN(sizeof(frame.cont.data), l);
        memcpy(frame.cont.data, data + cnt, psz);
        queue_push_retry(queue, (const uint8_t*)&frame);
    }
}

/**
 * Prepares an error USB frame, containing the channel id
 * and error code and adds it to the given callback.
 * @param[in] err The error send to the host.
 * @param[in] cid The channel id.
 * @param[in] add_frame_callback The callback to which we add the frame.
 */
void usb_frame_prepare_err(uint8_t err, uint32_t cid, struct queue* queue)
{
    USB_FRAME frame;

    memset(&frame, 0, sizeof(frame));
    frame.cid = cid;
    frame.init.cmd = FRAME_ERROR;
    frame.init.bcntl = 1;
    frame.init.data[0] = err;
    queue_push_retry(queue, (const uint8_t*)&frame);
}

/**
 * Processes USB frame requests.
 * @param[in] frame The frame that is processed.
 * @param[in] state The frame processing state.
 */
int32_t usb_frame_process(const USB_FRAME* frame, State* state)
{
    // USB initialization frames contain a command that begins with 0x80
    if ((frame->type & FRAME_TYPE_MASK) == FRAME_TYPE_INIT) {
        return _cmd_init(frame, state);
    }
    if ((frame->type & FRAME_TYPE_MASK) == FRAME_TYPE_CONT) {
        return _cmd_continue(frame, state);
    }
    return FRAME_ERR_INVALID_CMD;
}

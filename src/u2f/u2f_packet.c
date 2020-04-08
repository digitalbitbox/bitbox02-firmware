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

#include "u2f_packet.h"
#include "queue.h"
#include "screen.h"
#include "usb/usb_processing.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define ERR_NONE 0

// We can handle up to NUM_TIMEOUT_COUNTERS missing continuation frames
#define NUM_TIMEOUT_COUNTERS 3

struct frame_counter {
    uint32_t cid;
    uint8_t counter;
};

// cid == 0 indicates that there isn't any active timer for that slot
static volatile struct frame_counter _timeout_counters[NUM_TIMEOUT_COUNTERS];

static void _reset_timeout(uint32_t cid)
{
    for (int i = 0; i < NUM_TIMEOUT_COUNTERS; ++i) {
        if (_timeout_counters[i].cid == cid) {
            _timeout_counters[i].counter = 0;
        }
    }
}

static void _timeout_disable(uint32_t cid)
{
    for (int i = 0; i < NUM_TIMEOUT_COUNTERS; ++i) {
        if (_timeout_counters[i].cid == cid) {
            _timeout_counters[i].cid = 0;
            _timeout_counters[i].counter = 0;
        }
    }
}

/**
 * Keeps a state for the frame processing of incoming frames.
 */
static State _in_state;

/**
 * Resets the current state.
 */
static void _reset_state(void)
{
    queue_clear(queue_u2f_queue());
    _timeout_disable(_in_state.cid);
    memset(&_in_state, 0, sizeof(_in_state));
}

/**
 * Responds with an error.
 * @param[in] err The error.
 * @param[in] cid The channel identifier.
 * No return value needed as long as _reset_state clears the queue.
 */
static void _queue_err(const uint8_t err, uint32_t cid)
{
    usb_frame_prepare_err(err, cid, queue_u2f_queue());
}

static bool _need_more_data(void)
{
    return (_in_state.buf_ptr - _in_state.data) < (signed)_in_state.len;
}

void u2f_invalid_endpoint(struct queue* queue, uint32_t cid)
{
    // TODO: if U2F is disabled, we used to return a 'channel busy' command.
    // now we return an invalid cmd, because there is not going to be a matching
    // cmd in '_registered_cmds' if the U2F bit it not set (== U2F disabled).
    // TODO: figure out the consequences.
    usb_frame_prepare_err(FRAME_ERR_INVALID_CMD, cid, queue);
}

void u2f_packet_timeout_enable(uint32_t cid)
{
    for (int i = 0; i < NUM_TIMEOUT_COUNTERS; ++i) {
        if (_timeout_counters[i].cid == 0) {
            _timeout_counters[i].cid = cid;
            _timeout_counters[i].counter = 0;
            return;
        }
    }
}

#define U2F_TIMEOUT (500) // [msec]

bool u2f_packet_timeout_get(uint32_t* cid)
{
    for (int i = 0; i < NUM_TIMEOUT_COUNTERS; ++i) {
        *cid = _timeout_counters[i].cid;
        if (_timeout_counters[i].cid != 0 && _timeout_counters[i].counter >= (U2F_TIMEOUT / 50)) {
            return true;
        }
    }
    return false;
}

void u2f_packet_timeout_tick(void)
{
    for (int i = 0; i < NUM_TIMEOUT_COUNTERS; ++i) {
        if (_timeout_counters[i].cid != 0) {
            _timeout_counters[i].counter += 1;
        }
    }
}

void u2f_packet_timeout(uint32_t cid)
{
    _timeout_disable(cid);
    if (cid == _in_state.cid) {
        _reset_state();
    }
    usb_frame_prepare_err(FRAME_ERR_MSG_TIMEOUT, cid, queue_u2f_queue());
}

bool u2f_packet_process(const USB_FRAME* frame)
{
    struct usb_processing* ctx = usb_processing_u2f();
    switch (usb_frame_process(frame, &_in_state)) {
    case FRAME_ERR_IGNORE:
        // Ignore this frame, i.e. no response.
        break;
    case FRAME_ERR_INVALID_SEQ:
        // Reset the state becuase this error indicates that there is a host application bug
        _reset_state();
        _queue_err(FRAME_ERR_INVALID_SEQ, frame->cid);
        break;
    case FRAME_ERR_CHANNEL_BUSY:
        // We don't reset the state because this error doesn't indicate something wrong with the
        // "current" connection.
        _queue_err(FRAME_ERR_CHANNEL_BUSY, frame->cid);
        break;
    case FRAME_ERR_INVALID_LEN:
        // Reset the state becuase this error indicates that there is a host application bug
        _reset_state();
        _queue_err(FRAME_ERR_INVALID_LEN, frame->cid);
        break;
    case ERR_NONE:
        _reset_timeout(frame->cid);
        if (_need_more_data()) {
            // Do not send a message yet
            return true;
        }
        /* We have received a complete frame. Buffer it for processing. */
        if (usb_processing_enqueue(
                ctx, _in_state.data, _in_state.len, _in_state.cmd, _in_state.cid)) {
            // Queue filled and will be sent during usb processing
            _reset_state();
            return false;
        }
        // Else: Currently processing a message, reset the state and forget about this packet
        _timeout_disable(frame->cid);
        _reset_state();
        _queue_err(FRAME_ERR_CHANNEL_BUSY, frame->cid);
        break;
    default:
        // other errors
        _reset_state();
        _queue_err(FRAME_ERR_OTHER, frame->cid);
        break;
    }
    return false;
}

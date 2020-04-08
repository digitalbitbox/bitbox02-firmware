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

#ifndef _USB_PROCESSING_H_
#define _USB_PROCESSING_H_

#include "queue.h"
#include "usb_frame.h"
#include "usb_packet.h"

struct usb_processing;

/**
 * Register a command callback that is executed when a USB frame with
 * a specific cmd id is received.
 * @param[in] cmd_callbacks The available callbacks for incoming commands.
 * @param[in] num_cmds The number of registered commands.
 */
void usb_processing_register_cmds(
    struct usb_processing* ctx,
    const CMD_Callback* cmd_callbacks,
    int num_cmds);

/**
 * Prepares USB frames to be send to the host.
 * param[in] data The data is copied into one or more frames
 */
typedef void (*usb_frame_formatter_t)(
    const uint8_t cmd,
    const uint8_t* data,
    const uint32_t len,
    const uint32_t cid,
    struct queue* queue);

/**
 * Enqueues a usb packet for processing. Ownership is transferred, and the
 * memory will be freed in `usb_processing_dequeue`.
 * @param[in] in_state The packet is built from in_state and queued.
 * @return false if there is already a packet in the queue (need to process it
 * first).
 */
bool usb_processing_enqueue(
    struct usb_processing* ctx,
    const uint8_t* buf,
    size_t length,
    uint8_t cmd,
    uint32_t cid);
void usb_processing_process(struct usb_processing* ctx);

void usb_processing_set_send(struct usb_processing* ctx, void (*send)(void));

void usb_processing_send_packet(struct usb_processing* ctx, const Packet* out_packet);

struct usb_processing* usb_processing_u2f(void);
struct usb_processing* usb_processing_hww(void);

void usb_processing_init(void);

/**
 * Initializes a packet as a response to the given incoming
 * packet.
 */
void prepare_usb_packet(uint8_t cmd, uint32_t cid, Packet* out_packet);

#if !defined(BOOTLOADER)
void usb_processing_lock(struct usb_processing* ctx);

/**
 * Manually resets the USB lock watchdog.
 * No traffic on the USB bus will make any locked operation
 * timeout. However, if not receiving traffic is the
 * expected behaviour, one can call this function to prevent
 * the USB watchdog from aborting the outstanding operation.
 */
void usb_processing_timeout_reset(void);

void usb_processing_unlock(void);
#endif

#endif

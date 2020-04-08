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

#ifndef _USB_PACKET_H_
#define _USB_PACKET_H_

#include "usb_frame.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * The USB packet that contains a pointer to the packet data, the length, the
 * command identifier and the channel id.
 */
typedef struct {
    uint8_t data_addr[USB_DATA_MAX_LEN];
    size_t len;
    uint8_t cmd;
    uint32_t cid;
} Packet;

/**
 * Contains command callbacks
 */
typedef struct {
    uint8_t cmd;
    void (*process_cmd)(const Packet*);
} CMD_Callback;

/**
 * Processes an incoming USB packet.
 * @param[in] frame The frame that is to be processed.
 * @return true if we are waiting for more frames to complete a packet, false otherwise.
 */
bool usb_packet_process(const USB_FRAME* frame);

void usb_invalid_endpoint(struct queue* queue, uint32_t cid);

#endif

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

#ifndef _USB_FRAME_H_
#define _USB_FRAME_H_

#include <stdint.h>

#include "queue.h"
#include <usb/class/usb_desc.h>

#define FRAME_TYPE_MASK 0x80 // Frame type mask
#define FRAME_TYPE_INIT 0x80 // Initial frame identifier
#define FRAME_TYPE_CONT 0x00 // Continuation frame identifier

#define FRAME_TYPE(f) ((f).type & FRAME_TYPE_MASK)
#define FRAME_CMD(f) ((f).init.cmd & ~FRAME_TYPE_MASK)
#define FRAME_SEQ(f) ((f).cont.seq & ~FRAME_TYPE_MASK)
#define FRAME_MSG_LEN(f) (((f).init.bcnth << 8) + (f).init.bcntl)

#define FRAME_MSG (FRAME_TYPE_INIT | 0x03) // Send FRAME message frame
#define FRAME_ERROR (FRAME_TYPE_INIT | 0x3f) // Error response

#define FRAME_ERR_INVALID_CMD 0x01
#define FRAME_ERR_INVALID_PAR 0x02
#define FRAME_ERR_INVALID_LEN 0x03
#define FRAME_ERR_INVALID_SEQ 0x04
#define FRAME_ERR_MSG_TIMEOUT 0x05
#define FRAME_ERR_CHANNEL_BUSY 0x06
#define FRAME_ERR_OTHER 0x7f

// Internal error message to ignore a frame
#define FRAME_ERR_IGNORE 0x80

// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html
//
// Packets are one of two types, initialization packets and continuation packets.
// As the name suggests, the first packet sent in a message is an initialization
// packet, which also becomes the start of a transaction. If the entire message
// does not fit into one packet (including the U2FHID protocol overhead), one or
// more continuation packets have to be sent in strict ascending order to complete
// the message transfer.
//
// With this approach, a message with a payload less or equal to (s - 7) may be
// sent as one packet. A larger message is then divided into one or more
// continuation packets, starting with sequence number 0, which then increments
// by one to a maximum of 127.
//
// With a packet size of 64 bytes (max for full-speed devices), this means that
// the maximum message payload length is 64 - 7 + 128 * (64 - 5) = 7609 bytes.
#define USB_DATA_MAX_LEN 7609U

#define HID_VENDOR_FIRST (FRAME_TYPE_INIT | 0x40) // First vendor defined command
#define HID_VENDOR_LAST (FRAME_TYPE_INIT | 0x7f) // Last vendor defined command

__extension__ typedef struct {
    uint32_t cid; // Channel identifier
    union {
        uint8_t type; // Frame type - bit 7 defines type
        struct {
            uint8_t cmd; // Command - bit 7 set
            uint8_t bcnth; // Message byte count - high
            uint8_t bcntl; // Message byte count - low
            uint8_t data[USB_REPORT_SIZE - 7]; // Data payload
        } init;
        struct {
            uint8_t seq; // Sequence number - bit 7 cleared
            uint8_t data[USB_REPORT_SIZE - 5]; // Data payload
        } cont;
    };
} USB_FRAME;

/**
 * Holds the data, pointer into the buffer, data length, cmd, channel id and sequence
 * number in order to collect multiple frames into a processable command.
 */
typedef struct {
    uint8_t data[USB_DATA_MAX_LEN];
    uint8_t* buf_ptr;
    uint32_t len;
    uint8_t seq;
    uint8_t cmd;
    uint32_t cid;
    uint8_t initialized;
} State;

/**
 * Prepares frames and calls the add_frame_callback.
 * @param[in] cmd The HID command.
 * @param[in] data The data send to the host.
 * @param[in] len The length of the data.
 * @param[in] cid The channel ID.
 * @param[in] add_frame_callback The callback to which the prepared frames are passed to.
 */
void usb_frame_reply(
    uint8_t cmd,
    const uint8_t* data,
    uint32_t len,
    uint32_t cid,
    struct queue* queue);

/**
 * Takes data and a channel id and constructs USB frames that are added
 * to the USB queue and send back to the host as a FRAME_MSG.
 */
void usb_frame_send_message(const uint8_t* data, uint32_t len, uint8_t cid);

/**
 * Takes data and a channel id and constructs USB frames that are added
 * to the USB queue and send back to the host with the given cmd identifier.
 */
void usb_frame_send_cmd(uint8_t cmd, const uint8_t* data, uint32_t len, uint8_t cid);

/**
 * Prepares an error USB frame, containing the channel id
 * and error code and adds it to the given callback.
 * @param[in] cid The channel id.
 * @param[in] err The error send to the host.
 * @param[in] add_frame_callback The callback to which we add the frame.
 */
void usb_frame_prepare_err(uint8_t err, uint32_t cid, struct queue* queue);

/**
 * Processes usb frame requests.
 * @param[in] frame The frame that is processed.
 * @param[in] state The frame processing state.
 */
int32_t usb_frame_process(const USB_FRAME* frame, State* state);

/**
 * Resets the current state.
 */
void usb_frame_device_reset_state(void);

#endif

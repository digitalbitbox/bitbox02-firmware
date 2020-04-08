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

#include "usart_frame.h"

#include "hardfault.h"
#include "screen.h"
#include "usb/usb_processing.h"
#include "util.h"

#include <stdbool.h>

#define USART_FRAME_FLAG_BYTE ((uint8_t)0x7E)
#define USART_FRAME_ESCAPE_BYTE ((uint8_t)0x7D)
#define USART_FRAME_ESCAPE_MASK ((uint8_t)0x20)

typedef enum {
    USART_FRAME_ERROR_ENDPOINT_UNAVAILABLE = 0x01,
    USART_FRAME_ERROR_ENDPOINT_BUSY = 0x02,
    USART_FRAME_ERROR_INVALID_CMD = 0x03
} usart_frame_error_t;

/**
 * Minimum length of packets (V1).
 * 1B version + 1B endpoint + 2B checksum.
 */
#define USART_FRAME_MIN_LENGTH (4)

/** State of the USART frame unpacker state machine. */
typedef enum {
    /**
     * Waiting to synchronize to a packet start (0x7E).
     *
     * This state will be the starting state (to resync on the byte stream).
     * We also enter this state every time we think we've lost
     * track of where the packet start is (e.g. buffer overflow,
     * asked to reset).
     */
    USART_FRAME_PARSE_IDLE,
    /** Reading data. */
    USART_FRAME_PARSE_RX,
    /** Last byte was 0x7D: escape the next one. */
    USART_FRAME_PARSE_ESCAPING
} usart_parse_state_t;

/**
 * Keeps a state for the frame processing of incoming frames.
 */
static struct {
    usart_parse_state_t state;
    size_t packet_size;
    uint8_t buf[USART_FRAME_MAX_DATA_LEN];
} _usart_frame_parser_state;

/**
 * Resets the current state.
 */
static void _usart_frame_reset_state(void)
{
    _usart_frame_parser_state.state = USART_FRAME_PARSE_IDLE;
    util_zero(_usart_frame_parser_state.buf, _usart_frame_parser_state.packet_size);
    _usart_frame_parser_state.packet_size = 0;
}

void usart_frame_init(void)
{
    _usart_frame_parser_state.state = USART_FRAME_PARSE_IDLE;
    _usart_frame_parser_state.packet_size = 0;
    util_zero(_usart_frame_parser_state.buf, sizeof(_usart_frame_parser_state.buf));
}

static inline uint16_t _ones_complement_sum(uint16_t a, uint16_t b)
{
    uint32_t result = a + b;
    if (result & 0x10000) {
        result -= 0xFFFF;
    }
    return result;
}

static uint16_t _compute_checksum(const uint8_t* data, size_t payload_length)
{
    uint16_t cs = 0;
    size_t n_sums = (payload_length) / 2;
    bool round = (payload_length % 2) != 0;
    for (size_t i = 0; i < n_sums; ++i) {
        uint16_t element = ((const uint16_t*)data)[i];
        cs = _ones_complement_sum(cs, element);
    }
    // If we had an odd number of bytes, we
    // want to add the last byte on its own
    // (little endian, so this is equivalent
    // to padding with an additional 0x00 byte.
    if (round) {
        cs = _ones_complement_sum(cs, (uint16_t)(data[payload_length - 1]));
    }
    return cs;
}

/**
 * Computes the checksum of an outgoing packet.
 *
 * This is the same as _compute_checksum run over
 * the whole packet. However, information regarding the
 * metadata of the packet to be sent is not provided to us
 * in a contiguous buffer, so we use a separate function
 * to compute the checksum to send without having to repack
 * the frame first.
 *
 * @param[in] src_endpoint Source endpoint (U2F command byte) field
 * @param[in] data payload
 * @param[in] len len of the payload.
 */
static uint16_t _compute_send_checksum(
    const uint8_t version,
    const uint8_t src_endpoint,
    const uint8_t* data,
    const uint32_t len)
{
    // The packet will contain version information in the first byte.
    uint16_t header = version | (src_endpoint << 8);
    if (len == 0) {
        return header;
    }
    uint16_t cs = _ones_complement_sum(header, _compute_checksum(data, len));
    return cs;
}

static void _usart_send_frame_error(uint8_t error_code, struct queue* queue)
{
    uint8_t error_payload = error_code;
    usart_format_frame(0xFF, &error_payload, 1, 0x42 /* Unused */, queue);
}

/**
 * Manages frames according to the U2F-over-UART V1 protocol.
 */
static void _usart_manage_frame_v1(const uint8_t* buf, size_t packet_len)
{
    // Check the checksum, located in the last 2 bytes of the frame.
    size_t payload_length = packet_len - 2;
    uint16_t checksum = *((const uint16_t*)(buf + payload_length));
    uint16_t exp_checksum = _compute_checksum(_usart_frame_parser_state.buf, payload_length);
    if (exp_checksum != checksum) {
        return;
    }
    /*
     * The "U2F command" byte is used as an endpoint selection,
     * i.e. to select which API set will handle this request.
     */
    uint8_t dst_endpoint = _usart_frame_parser_state.buf[1];
    bool can_process = usb_processing_enqueue(
        usb_processing_hww(),
        _usart_frame_parser_state.buf + 2,
        payload_length - 2,
        dst_endpoint,
        /* We don't really have a CID... */ 0x42);
    if (!can_process) {
        _usart_send_frame_error(USART_FRAME_ERROR_ENDPOINT_BUSY, queue_hww_queue());
    }
}

void usart_invalid_endpoint(struct queue* queue, uint32_t cid)
{
    (void)cid;
    _usart_send_frame_error(USART_FRAME_ERROR_ENDPOINT_UNAVAILABLE, queue);
}

static void _usart_manage_full_rx_frame(void)
{
    // Check if this packet is correct
    if (_usart_frame_parser_state.packet_size < USART_FRAME_MIN_LENGTH) {
        /*
         * Packet too short.
         * FUTURE: for protocol v2 we might want to add
         * some sort of seqNumber + ACK mechanism,
         * so that packets are not just silently dropped...
         * Now we just drop invalid packets.
         */
        return;
    }
    // At the moment we only support version 1.
    uint8_t version = _usart_frame_parser_state.buf[0];
    if (version != 1) {
        return;
    }
    _usart_manage_frame_v1(_usart_frame_parser_state.buf, _usart_frame_parser_state.packet_size);
}

static void _usart_frame_packet_end(void)
{
    if (_usart_frame_parser_state.packet_size > 0) {
        _usart_manage_full_rx_frame();
    }
    _usart_frame_reset_state();
    _usart_frame_parser_state.state = USART_FRAME_PARSE_RX;
}

static void _usart_frame_append_data_byte(uint8_t b)
{
    if (_usart_frame_parser_state.packet_size == USART_FRAME_MAX_DATA_LEN) {
        /* Error. Start looking for a new packet and discard the current one. */
        _usart_frame_reset_state();
        return;
    }
    _usart_frame_parser_state.buf[_usart_frame_parser_state.packet_size] = b;
    _usart_frame_parser_state.packet_size++;
}

static void _usart_frame_process_byte(uint8_t b)
{
    switch (_usart_frame_parser_state.state) {
    case USART_FRAME_PARSE_IDLE:
        if (b == USART_FRAME_FLAG_BYTE) {
            // Found it!
            _usart_frame_reset_state();
            _usart_frame_parser_state.state = USART_FRAME_PARSE_RX;
        }
        break;
    case USART_FRAME_PARSE_RX:
        if (b == USART_FRAME_FLAG_BYTE) {
            // End of packet.
            _usart_frame_packet_end();
        } else if (b == USART_FRAME_ESCAPE_BYTE) {
            // Escape sequence.
            _usart_frame_parser_state.state = USART_FRAME_PARSE_ESCAPING;
        } else {
            // Everything else -> Data byte.
            _usart_frame_append_data_byte(b);
        }
        break;
    case USART_FRAME_PARSE_ESCAPING:
        if (b == USART_FRAME_FLAG_BYTE) {
            // Escaped flag: this means "force reset, ignore this packet."
            _usart_frame_reset_state();
        } else {
            // Everything else -> Data byte.
            _usart_frame_append_data_byte(b ^ USART_FRAME_ESCAPE_MASK);
            _usart_frame_parser_state.state = USART_FRAME_PARSE_RX;
        }
        break;
    default:
        Abort("_usart_frame_process_byte\nInvalid state!");
    }
}
static int total_n_rcv_bytes = 0;

void usart_frame_process_rx(const uint8_t* buf, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        _usart_frame_process_byte(buf[i]);
        total_n_rcv_bytes++;
    }
}

static size_t n_pushed = 0;
#define USART_FRAME_PUSH_BYTE(x)                         \
    do {                                                 \
        uint8_t to_push = x;                             \
        queue_push_retry(queue, &to_push); \
        n_pushed++;                                      \
    } while (0)

static void _usart_encode_push_byte(uint8_t b, struct queue* queue)
{
    if (b == USART_FRAME_FLAG_BYTE || b == USART_FRAME_ESCAPE_BYTE) {
        // Escape special framing bytes.
        USART_FRAME_PUSH_BYTE(USART_FRAME_ESCAPE_BYTE);
        USART_FRAME_PUSH_BYTE(b ^ USART_FRAME_ESCAPE_MASK);
    } else {
        USART_FRAME_PUSH_BYTE(b);
    }
}

void usart_format_frame(
    uint8_t src_endpoint,
    const uint8_t* data,
    uint32_t len,
    uint32_t cid,
    struct queue* queue)
{
    (void)cid;
    USART_FRAME_PUSH_BYTE(USART_FRAME_FLAG_BYTE);
    // Version == 0x01
    _usart_encode_push_byte(0x01, queue);
    _usart_encode_push_byte(src_endpoint, queue);
    for (uint32_t i = 0; i < len; ++i) {
        _usart_encode_push_byte(data[i], queue);
    }
    uint16_t cs = _compute_send_checksum(0x01, src_endpoint, data, len);
    uint8_t* cs_buf = (uint8_t*)&cs;
    _usart_encode_push_byte(cs_buf[0], queue);
    _usart_encode_push_byte(cs_buf[1], queue);
    USART_FRAME_PUSH_BYTE(USART_FRAME_FLAG_BYTE);
}

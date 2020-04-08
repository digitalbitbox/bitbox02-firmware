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

#ifndef _USART_FRAME_H_
#define _USART_FRAME_H_

#include "queue.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// Maximum payload size that can be transmitted in a single UART frame.
#define USART_FRAME_MAX_PAYLOAD_LEN (7609U)
// Maximum total frame size that can be transmitted over UART (includes headers/checksums).
#define USART_FRAME_MAX_DATA_LEN (USART_FRAME_MAX_PAYLOAD_LEN + 4)

/**
 * Processes new raw data read from the USART port.
 * @param[in] buf Data that has been read.
 * @param[in] size Number of bytes queued.
 */
void usart_frame_process_rx(const uint8_t* buf, size_t size);

/**
 * Initializes the parser.
 */
void usart_frame_init(void);

/**
 * Called when a message has been sent to a non-registered endpoint.
 */
void usart_invalid_endpoint(struct queue* queue, uint32_t cid);

/**
 * Creates a data frame for sending over USART.
 */
void usart_format_frame(
    uint8_t src_endpoint,
    const uint8_t* data,
    uint32_t len,
    uint32_t cid,
    struct queue* queue);

#endif

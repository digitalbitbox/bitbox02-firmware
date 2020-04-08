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

#ifndef _QUEUE_H
#define _QUEUE_H

#include <stdint.h>
#include <string.h>

typedef enum {
    QUEUE_ERR_NONE = 0,
    QUEUE_ERR_FULL = 1,
} queue_error_t;

struct queue;

/**
 * Append the given data to the queue.
 * Returns QUEUE_ERR_NONE if the data was added and QUEUE_ERR_FULL if the buffer was full.
 * data must be USB_REPORT_SIZE large
 */
queue_error_t queue_push(struct queue* ctx, const uint8_t* data);

/**
 * Append the given data to the queue. If the queue is full, retry until data is available again.
 *
 * Calling this function from interrupt context should never be done: it will block forever
 * as nothing will ever be able to pop data from the queue!
 *
 * @param[in] data Frame to be sent. Must be USB_REPORT_SIZE large.
 */
void queue_push_retry(struct queue* ctx, const uint8_t* data);

/**
 * Return the first data that was added to the queue.
 * Returns NULL if empty
 */
const uint8_t* queue_pull(struct queue* ctx);

/**
 * Initializes this queue object.
 * The queue will handle elements with the given size.
 *
 * @param[size] Size of each element. This will decide how many
 * bytes each push/pull operation will consume. This must be
 * a submultiple of QUEUE_SIZE.
 */
void queue_init(struct queue* ctx, size_t item_size);

/**
 * Clear the queue.
 */
void queue_clear(struct queue* ctx);

/**
 * Peek at the tip of the queue. Returns NULL if queue is empty.
 */
const uint8_t* queue_peek(struct queue* ctx);

/**
 * Get a pointer to the hww queue
 */
struct queue* queue_hww_queue(void);

/**
 * Get a pointer ot the u2f queue
 */
struct queue* queue_u2f_queue(void);

#endif

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

#include "usart_hww.h"

#include "hardfault.h"
#include "usart_frame.h"
#include "usb/usb_processing.h"

#include <hal_usart_async.h>
#include <peripheral_clk_config.h>
#include <queue.h>

#define HID_HWW_VERSION 0x00000001u

#define USART_TX_BUFFER_SIZE 16

/**
 * Static buffer containing data to be sent.
 * This will be consumed by the interrupt handler
 * as needed.
 */
static uint8_t _usart_tx_buf[USART_TX_BUFFER_SIZE];

/** Set when the send channel is busy sending data. */
static bool _send_busy = false;

/** Pointer to our UART descriptor. */
static struct usart_async_descriptor* _usart_descriptor;

/**
 * Sends the next frame, if the USART interface is ready.
 */
static void _send_next(void)
{
    if (_send_busy) {
        /*
         * We can't send yet. Whenever the current sender finished, it will
         * flush anything that's still queued.
         */
        return;
    }
    /*
     * Load our tx buffer with has many bytes as we can.
     * FUTURE: Give queue_pull the possibility of reading N bytes at once
     *         to avoid all this boilerplate.
     */
    size_t n_read;
    for (n_read = 0; n_read < USART_TX_BUFFER_SIZE; ++n_read) {
        const uint8_t* data = queue_pull(queue_hww_queue());
        if (data == NULL) {
            break;
        }
        _usart_tx_buf[n_read] = *data;
    }
    if (n_read == 0) {
        /* Nothing to send. */
        return;
    }
    _send_busy = true;
    struct io_descriptor* io;
    usart_async_get_io_descriptor(_usart_descriptor, &io);
    int32_t res = io_write(io, _usart_tx_buf, n_read);
    /*
     * Assumption: io_write to UART uses a static buffer,
     * so it will always write all that we sent it.
     */
    if (res < 0 || (size_t)res != n_read) {
        Abort("io_write to usart failed.");
    }
}

/**
 * Called when a usb frame has been replied to the host via the HWW interface
 * and the device is ready to send the next frame.
 */
static void _sent_done(const struct usart_async_descriptor* const descr)
{
    (void)descr;
    _send_busy = false;
    /*
     * If there is more data queued, push it immediately to save some time.
     * Otherwise, sending will stop until somebody explicitely queues
     * a frame again.
     */
    _send_next();
}

/**
 * This function polls the USART rx status. If there is
 * data available, it will unframe it and buffer any
 * resulting packet for later processing.
 */
static void _out(const struct usart_async_descriptor* const descr)
{
    (void)descr;
}

/**
 * This callback will be invoked when the USART stack
 * enters an error state.
 *
 * We just ignore errors for now.
 * FUTURE: investigate what kind of errors are reported exactly
 *         and reset the USART state on error.
 */
static void _err(const struct usart_async_descriptor* const descr)
{
    (void)descr;
}

void usart_hww_init(struct usart_async_descriptor* desc)
{
    _usart_descriptor = desc;
    usart_async_register_callback(_usart_descriptor, USART_ASYNC_TXC_CB, _sent_done);
    /*
     * If we don't register a RX callback, the USART stack just
     * disables RX entirely.
     * Register an empty callback instead, so we can poll for
     * received data in the main loop.
     */
    usart_async_register_callback(_usart_descriptor, USART_ASYNC_RXC_CB, _out);
    usart_async_register_callback(_usart_descriptor, USART_ASYNC_ERROR_CB, _err);
    /*
     * Tell the application layer how they can notify us that
     * new data must be sent.
     */
    usb_processing_set_send(usb_processing_hww(), _send_next);
}

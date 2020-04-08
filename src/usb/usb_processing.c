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

#include "usb_processing.h"
#include "platform_config.h"
#include "u2f/u2f_packet.h"
#include "usart/usart_frame.h"
#include "usb_frame.h"
#include "usb_packet.h"

#include <hardfault.h>

#if !defined(BOOTLOADER)
#include <hww.h>
#ifndef TESTING
#include <hal_timer.h>
extern struct timer_descriptor TIMER_0;
#endif

#endif
#include <queue.h>
#include <stdlib.h>
#include <string.h>
#include <u2f.h>
#include <util.h>

/**
 * Amount of time to wait before an outstanding operation times out
 * (if the client is closed).
 */
#define USB_OUTSTANDING_OP_TIMEOUT_MS (500)
#define USB_TIMER_TICK_PERIOD_MS (100)
#define USB_OUTSTANDING_OP_TIMEOUT_TICKS (USB_OUTSTANDING_OP_TIMEOUT_MS / USB_TIMER_TICK_PERIOD_MS)

struct usb_processing {
    CMD_Callback* registered_cmds;
    uint32_t registered_cmds_len;
    /* Whether the content of in_packet is a new, complete incoming packet. */
    bool has_packet;
    struct queue* (*out_queue)(void);
    void (*send)(void);
    usb_frame_formatter_t format_frame;
    /**
     * Function to call when a message has been received,
     * but there is no registered API set to manage it.
     */
    void (*manage_invalid_endpoint)(struct queue* queue, uint32_t cid);
#if !defined(BOOTLOADER)
    /**
     * Function to call when a message has been received,
     * but the stack cannot process it because the device
     * is busy processing another request.
     */
    void (*create_blocked_req_error)(Packet* out_packet, const Packet* in_packet);
    /**
     * Function to call to forcefully abort any operation
     * that is keeping the USB stack busy.
     */
    void (*force_operation_abort)(void);
    /**
     * Function to call in order to know whether the given
     * request can be passed to the stack, while the stack
     * is blocked.
     */
    bool (*can_request_unblock)(const Packet* in_packet);
    /**
     * Callback to forcefully abort any operation processing
     * on this stack.
     */
    void (*abort_outstanding_op)(void);
#endif
};

/**
 * Keeps track of the internal state of the USB processing stack.
 */
typedef struct {
    /**
     * FUTURE: this can be removed and packets can be queued when
     * hww workflows are independent from the USB processing layer.
     *
     * At that point, we can just use the usb_processing.has_packet flags to make
     * sure that we don't drop packets, send FRAME_ERR_CHANNEL_BUSY when layer-1
     * is busy (i.e. we are in the process of buffering a frame) and continuously accept
     * frames from both stacks (so we don't send FRAME_ERR_CHANNEL_BUSY improperly when
     * it's the user interface that is busy, and not the USB port).
     *
     * For now this is impossible as the UI being busy keeps the USB port busy as well...
     */
    volatile bool in_packet_queued;

    /**
     * Contains the USB packet that is currently being processed.
     * This is only valid if in_packet_queued is true.
     * It is shared between all stacks (as we only process one packet at the time,
     * and send out FRAME_ERR_CHANNEL_BUSY if we are still processing the buffered one
     * and a new one arrives).
     */
    Packet in_packet;

#if !defined(BOOTLOADER)
    /**
     * Pointer to the context that has locked the USB stack while
     * handling a blocking request.
     */
    struct usb_processing* blocking_ctx;
    /**
     * Timeout counter. This is increased every 100ms by a timer,
     * and is reset to 0 every time a new packet is send to one of the
     * underlying stacks. When the timeout counter becomes greater then
     * USB_OUTSTANDING_OP_TIMEOUT_TICKS, any outstanding operation is aborted
     * and the USB stack is forcefully unlocked.
     */
    uint16_t timeout_counter;
#endif
} usb_processing_state_t;

static usb_processing_state_t _usb_state = {0};

/**
 * Responds with data of a certain length.
 * @param[in] packet The packet to be sent.
 */
void usb_processing_send_packet(struct usb_processing* ctx, const Packet* out_packet)
{
    ctx->format_frame(
        out_packet->cmd, out_packet->data_addr, out_packet->len, out_packet->cid, ctx->out_queue());
}

/**
 * Builds a packet from the passed state.
 * @param[in] in_state The packet is loaded from the state.
 */
static void _build_packet(const uint8_t* buf, size_t length, uint8_t cmd, uint32_t cid)
{
    memcpy(_usb_state.in_packet.data_addr, buf, MIN(USB_DATA_MAX_LEN, length));
    _usb_state.in_packet.len = length;
    _usb_state.in_packet.cmd = cmd;
    _usb_state.in_packet.cid = cid;
}

/**
 * Prepares an outgoing packet.
 */
void prepare_usb_packet(uint8_t cmd, uint32_t cid, Packet* out_packet)
{
    memset(out_packet->data_addr, 0, sizeof(out_packet->data_addr));
    out_packet->len = 0;
    out_packet->cmd = cmd;
    out_packet->cid = cid;
}

/**
 * Register a command callback that is executed when a USB frame with
 * a specific cmd id is received.
 */
void usb_processing_register_cmds(
    struct usb_processing* ctx,
    const CMD_Callback* cmd_callbacks,
    int num_cmds)
{
    if (ctx->registered_cmds == NULL) {
        ctx->registered_cmds = malloc(num_cmds * sizeof(CMD_Callback));
        if (!ctx->registered_cmds) {
            Abort("Error: malloc usb commands");
        }
        memcpy(ctx->registered_cmds, cmd_callbacks, num_cmds * sizeof(CMD_Callback));
    } else {
        size_t old_size = ctx->registered_cmds_len * sizeof(CMD_Callback);
        size_t added_size = num_cmds * sizeof(CMD_Callback);
        size_t new_size = old_size + added_size;
        CMD_Callback* new_registered_cmds = (CMD_Callback*)realloc(ctx->registered_cmds, new_size);
        if (new_registered_cmds == NULL) {
            free(ctx->registered_cmds);
            Abort("Error: realloc usb commands");
        }
        ctx->registered_cmds = new_registered_cmds;
        memcpy(ctx->registered_cmds + ctx->registered_cmds_len, cmd_callbacks, added_size);
    }
    ctx->registered_cmds_len += num_cmds;
}

/**
 * Request to process a complete incoming USB packet.
 */
bool usb_processing_enqueue(
    struct usb_processing* ctx,
    const uint8_t* buf,
    size_t length,
    uint8_t cmd,
    uint32_t cid)
{
    if (_usb_state.in_packet_queued) {
        /* We already have a buffered packet. */
        return false;
    }
    _build_packet(buf, length, cmd, cid);
    _usb_state.in_packet_queued = true;
    ctx->has_packet = true;
    return true;
}

void usb_processing_set_send(struct usb_processing* ctx, void (*send)(void))
{
    ctx->send = send;
}

/**
 * Marks any buffered RX packet as fully processed.
 * This frees the RX buffer so that it's possible to
 * receive further packets.
 */
static void _usb_processing_drop_received(struct usb_processing* ctx)
{
    // Mark the packet as processed.
    if (ctx->has_packet) {
        ctx->has_packet = false;
        util_zero(&_usb_state.in_packet, sizeof(_usb_state.in_packet));
    }
    _usb_state.in_packet_queued = false;
}

/**
 * Executes a packet, making it go through the registered callbacks
 * for the given context.
 *
 * @param ctx USB stack that should execute the packet.
 * @param in_packet Packet to execute.
 */
static void _usb_execute_packet(struct usb_processing* ctx, const Packet* in_packet)
{
    bool cmd_valid = false;
    for (uint32_t i = 0; i < ctx->registered_cmds_len; i++) {
        if (in_packet->cmd == ctx->registered_cmds[i].cmd) {
            cmd_valid = true;
            // process_cmd calls commander(...) or U2F functions.
            ctx->registered_cmds[i].process_cmd(in_packet);
            break;
        }
    }

    if (!cmd_valid) {
        ctx->manage_invalid_endpoint(ctx->out_queue(), _usb_state.in_packet.cid);
    }
}

#if !defined(BOOTLOADER)
/**
 * Processes an incoming packet. If the packet cannot be processed,
 * send an error response.
 *
 * @param ctx USB stack that received the packet.
 * @param in_packet Packet to process.
 */
static void _usb_arbitrate_packet(struct usb_processing* ctx, const Packet* in_packet)
{
    bool can_go_through = true;

    /*
     * If we're busy on another request, check if this
     * request matches.
     */
    if (_usb_state.blocking_ctx) {
        if (ctx == _usb_state.blocking_ctx) {
            /* Ask the lock owner to check if it will accept this request. */
            can_go_through = ctx->can_request_unblock(in_packet);
        } else {
            can_go_through = false;
        }
    }

    if (!can_go_through) {
        /* The receiving state should send back an error */
        Packet* out_packet = util_malloc(sizeof(*out_packet));
        prepare_usb_packet(in_packet->cmd, in_packet->cid, out_packet);
        ctx->create_blocked_req_error(out_packet, in_packet);
        usb_processing_send_packet(ctx, out_packet);
        free(out_packet);
    } else {
        _usb_execute_packet(ctx, in_packet);
        /* New packet processed: reset the watchdog timeout. */
        _usb_state.timeout_counter = 0;
    }
}
#endif

/**
 * Check if packets are buffered; if yes, process and pop them.
 * @param ctx USB stack to process.
 */
static void _usb_consume_incoming_packets(struct usb_processing* ctx)
{
    if (!ctx->has_packet) {
        return;
    }
/*
 * The bootloader is not allowed to execute any blocking request.
 * Remove all the arbitration logic.
 */
#if !defined(BOOTLOADER)
    _usb_arbitrate_packet(ctx, &_usb_state.in_packet);
#else
    _usb_execute_packet(ctx, &_usb_state.in_packet);
#endif
    _usb_processing_drop_received(ctx);
}

#if !defined(BOOTLOADER)
/**
 * Check if the lock timer has expired for this context.
 * If it has, call the abort_outstanding_op function and unlock
 * the USB stack.
 *
 * @param ctx Context to check.
 */
static void _check_lock_timeout(struct usb_processing* ctx)
{
    if (_usb_state.blocking_ctx != ctx) {
        return;
    }
    if (_usb_state.timeout_counter > USB_OUTSTANDING_OP_TIMEOUT_TICKS) {
        if (!ctx->abort_outstanding_op) {
            Abort("abort_outstanding_op is NULL.");
        }
        ctx->abort_outstanding_op();
        usb_processing_unlock();
    }
}
#endif

void usb_processing_process(struct usb_processing* ctx)
{
#if APP_U2F == 1
    uint32_t timeout_cid;
    // If there are any timeouts, send them first
    while (u2f_packet_timeout_get(&timeout_cid)) {
        u2f_packet_timeout(timeout_cid);
        usb_processing_u2f()->send();
    }

#endif
    _usb_consume_incoming_packets(ctx);
    /*
     * If USB sends are not enabled (yet), send will be NULL.
     * Otherwise, we can call it now to flush outstanding writes.
     */
    if (ctx->send != NULL) {
        ctx->send();
    }
#if !defined(BOOTLOADER)
    /*
     * If we've been locked for too much time, it's time
     * to forcefully close the offending operation.
     */
    _check_lock_timeout(ctx);
#endif
}

#if APP_U2F == 1
struct usb_processing* usb_processing_u2f(void)
{
    static struct usb_processing usb_processing;
    return &usb_processing;
}
#endif

struct usb_processing* usb_processing_hww(void)
{
    static struct usb_processing usb_processing;
    return &usb_processing;
}

#if !defined(BOOTLOADER) && !defined(TESTING)
/**
 * Callback invoked every 100ms from interrupt space.
 *
 * Increments the realtime counter (until it saturates).
 */
static void _timer_cb(const struct timer_task* const timer_task)
{
    (void)timer_task;
    if (_usb_state.timeout_counter != (uint16_t)-1) {
        _usb_state.timeout_counter++;
    }
}

static void _register_timer(void)
{
    static struct timer_task Timer_task;
    Timer_task.interval = USB_TIMER_TICK_PERIOD_MS;
    Timer_task.cb = _timer_cb;
    Timer_task.mode = TIMER_TASK_REPEAT;
    timer_stop(&TIMER_0);
    timer_add_task(&TIMER_0, &Timer_task);
    timer_start(&TIMER_0);
}
#endif

void usb_processing_init(void)
{
#if APP_U2F == 1
    usb_processing_u2f()->out_queue = queue_u2f_queue;
    queue_init(queue_u2f_queue(), USB_REPORT_SIZE);
    usb_processing_u2f()->format_frame = usb_frame_reply;
    usb_processing_u2f()->has_packet = false;
    usb_processing_u2f()->manage_invalid_endpoint = u2f_invalid_endpoint;
    usb_processing_u2f()->can_request_unblock = u2f_blocking_request_can_go_through;
    usb_processing_u2f()->create_blocked_req_error = u2f_blocked_req_error;
    usb_processing_u2f()->abort_outstanding_op = u2f_abort_outstanding_op;
#endif
    usb_processing_hww()->out_queue = queue_hww_queue;
#if !defined(BOOTLOADER)
    usb_processing_hww()->can_request_unblock = hww_blocking_request_can_go_through;
    usb_processing_hww()->create_blocked_req_error = hww_blocked_req_error;
    usb_processing_hww()->abort_outstanding_op = hww_abort_outstanding_op;
#endif
#if PLATFORM_BITBOXBASE == 1
    queue_init(queue_hww_queue(), 1);
    usb_processing_hww()->format_frame = usart_format_frame;
    usb_processing_hww()->manage_invalid_endpoint = usart_invalid_endpoint;
#else
    queue_init(queue_hww_queue(), USB_REPORT_SIZE);
    usb_processing_hww()->format_frame = usb_frame_reply;
    usb_processing_hww()->manage_invalid_endpoint = usb_invalid_endpoint;
#endif
    usb_processing_hww()->has_packet = false;
#if !defined(BOOTLOADER) && !defined(TESTING)
    _register_timer();
#endif
}

#if !defined(BOOTLOADER)
void usb_processing_lock(struct usb_processing* ctx)
{
    if (_usb_state.blocking_ctx) {
        Abort("Tried to lock the USB stack while locked.");
    }
    _usb_state.blocking_ctx = ctx;
}

void usb_processing_timeout_reset(void)
{
    _usb_state.timeout_counter = 0;
}

void usb_processing_unlock(void)
{
    if (!_usb_state.blocking_ctx) {
        Abort("Tried to unlock the USB stack while not locked.");
    }
    _usb_state.blocking_ctx = NULL;
}
#endif

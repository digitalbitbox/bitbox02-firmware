/**
 * \copyright
 * MIT License
 *
 * Copyright (c) 2019 Infineon Technologies AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 *
 * \endcopyright
 *
 * \author Infineon Technologies AG
 *
 * \file pal_os_event.c
 *
 * \brief   This file implements the platform abstraction layer APIs for os event/scheduler.
 *
 * \ingroup  grPAL
 *
 * @{
 */

#include "optiga/pal/pal_os_event.h"
#include "hal_timer.h"
#include "util.h"
extern struct timer_descriptor TIMER_0;

static pal_os_event_t pal_os_event_0 = {0};

void pal_os_event_start(
    pal_os_event_t* p_pal_os_event,
    register_callback callback,
    void* callback_args)
{
    if (0 == p_pal_os_event->is_event_triggered) {
        p_pal_os_event->is_event_triggered = TRUE;
        pal_os_event_register_callback_oneshot(p_pal_os_event, callback, callback_args, 1000);
    }
}

void pal_os_event_stop(pal_os_event_t* p_pal_os_event)
{
    p_pal_os_event->is_event_triggered = 0;
}

pal_os_event_t* pal_os_event_create(register_callback callback, void* callback_args)
{
    if ((NULL != callback) && (NULL != callback_args)) {
        pal_os_event_start(&pal_os_event_0, callback, callback_args);
    }
    return (&pal_os_event_0);
}

static struct timer_task scheduler;

void pal_os_event_trigger_registered_callback(void)
{
    // traceln("%s: called", __func__);
    register_callback callback;

    if (pal_os_event_0.callback_registered) {
        callback = pal_os_event_0.callback_registered;
        callback((void*)pal_os_event_0.callback_ctx);
    }
}

static void _timer_cb(const struct timer_task* const timer_task)
{
    (void)timer_task;
    pal_os_event_trigger_registered_callback();
}

void pal_os_event_register_callback_oneshot(
    pal_os_event_t* p_pal_os_event,
    register_callback callback,
    void* callback_args,
    uint32_t time_us)
{
    p_pal_os_event->callback_registered = callback;
    p_pal_os_event->callback_ctx = callback_args;

    scheduler.interval = (time_us + 99) / 100;
    scheduler.cb = _timer_cb;
    scheduler.mode = TIMER_TASK_ONE_SHOT;
    timer_add_task(&TIMER_0, &scheduler);
}

void pal_os_event_destroy(pal_os_event_t* pal_os_event)
{
    (void)pal_os_event;
}

/**
 * @}
 */

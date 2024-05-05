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
 * \file pal_os_timer.c
 *
 * \brief   This file implements the platform abstraction layer APIs for timer.
 *
 * \ingroup  grPAL
 *
 * @{
 */

#include "optiga/pal/pal_os_timer.h"
#include "hal_delay.h"
#include "hal_timer.h"
#include "hpl_time_measure.h"
#include "util.h"
extern struct timer_descriptor TIMER_0;

static volatile uint32_t g_ms_count = 0;
static struct timer_task scheduler;

uint32_t pal_os_timer_get_time_in_microseconds(void)
{
    static uint32_t count = 0;
    // The implementation must ensure that every invocation of this API returns a unique
    // value.
    return g_ms_count * 1000 + (count++);
}

uint32_t pal_os_timer_get_time_in_milliseconds(void)
{
    return g_ms_count;
}

void pal_os_timer_delay_in_milliseconds(uint16_t milliseconds)
{
    delay_ms(milliseconds);
}

static void _timer_cb(const struct timer_task* const timer_task)
{
    (void)timer_task;
    g_ms_count++;
}

pal_status_t pal_timer_init(void)
{
    scheduler.interval = 1;
    scheduler.cb = _timer_cb;
    scheduler.mode = TIMER_TASK_REPEAT;
    timer_add_task(&TIMER_0, &scheduler);
    return PAL_STATUS_SUCCESS;
}

pal_status_t pal_timer_deinit(void)
{
    timer_remove_task(&TIMER_0, &scheduler);
    return PAL_STATUS_SUCCESS;
}
/**
 * @}
 */

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
 * \file pal_os_lock.c
 *
 * \brief   This file implements the platform abstraction layer APIs for os locks (e.g. semaphore).
 *
 * \ingroup  grPAL
 *
 * @{
 */

#include "optiga/pal/pal_os_lock.h"

void pal_os_lock_create(pal_os_lock_t* p_lock, uint8_t lock_type)
{
    p_lock->type = lock_type;
    p_lock->lock = 0;
}

void pal_os_lock_destroy(pal_os_lock_t* p_lock)
{
    (void)p_lock;
}

pal_status_t pal_os_lock_acquire(pal_os_lock_t* p_lock)
{
    pal_status_t return_status = PAL_STATUS_FAILURE;

    // Below is a sample shared resource acquire mechanism
    // it doesn't provide a guarantee against a deadlock
    if (!(p_lock->lock)) {
        p_lock->lock++;
        if (1 != p_lock->lock) {
            p_lock->lock--;
        }
        return_status = PAL_STATUS_SUCCESS;
    }
    return return_status;
}

void pal_os_lock_release(pal_os_lock_t* p_lock)
{
    // Below is a sample shared resource acquire mechanism
    // it doesn't provide a guarantee against a deadlock
    if (0 != p_lock->lock) {
        p_lock->lock--;
    }
}

void pal_os_lock_enter_critical_section()
{
    // For safety critical systems it is recommended to implement a critical section entry
}

void pal_os_lock_exit_critical_section()
{
    // For safety critical systems it is recommended to implement a critical section exit
}

/**
 * @}
 */

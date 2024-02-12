/**
 * \copyright
 * MIT License
 *
 * Copyright (c) 2020 Infineon Technologies AG
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
 * \file pal_os_datastore.c
 *
 * \brief   This file implements the platform abstraction layer APIs for data store.
 *
 * \ingroup  grPAL
 *
 * @{
 */

#include "optiga/pal/pal_os_datastore.h"
#include "memory/memory.h"
/// @cond hidden

pal_status_t pal_os_datastore_write(uint16_t datastore_id, const uint8_t* p_buffer, uint16_t length)
{
    pal_status_t return_status = PAL_STATUS_FAILURE;
    (void)p_buffer;
    (void)length;

    switch (datastore_id) {
    case OPTIGA_PLATFORM_BINDING_SHARED_SECRET_ID: {
        // Not implemented
        return_status = PAL_STATUS_FAILURE;
        break;
    }
    default: {
        break;
    }
    }
    return return_status;
}

pal_status_t pal_os_datastore_read(
    uint16_t datastore_id,
    uint8_t* p_buffer,
    uint16_t* p_buffer_length)
{
    pal_status_t return_status = PAL_STATUS_FAILURE;

    switch (datastore_id) {
    case OPTIGA_PLATFORM_BINDING_SHARED_SECRET_ID: {
        memory_get_io_protection_key(p_buffer);
        *p_buffer_length = 32;
        return_status = PAL_STATUS_SUCCESS;
        break;
    }
    default: {
        *p_buffer_length = 0;
        break;
    }
    }

    return return_status;
}
/// @endcond
/**
 * @}
 */

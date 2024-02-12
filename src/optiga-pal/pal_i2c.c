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
 * \file pal_i2c.c
 *
 * \brief   This file implements the platform abstraction layer(pal) APIs for I2C.
 *
 * \ingroup  grPAL
 *
 * @{
 */

#include "optiga/pal/pal_i2c.h"
#include "hal_delay.h"
#include "hal_i2c_m_sync.h"
#include "optiga/pal/pal_os_timer.h"
#include "util.h"
extern struct i2c_m_sync_desc I2C_0;

#define PAL_I2C_MASTER_MAX_BITRATE (400U)

static volatile uint32_t g_entry_count = 0;
static const pal_i2c_t* gp_pal_i2c_current_ctx;

static pal_status_t pal_i2c_acquire(const void* p_i2c_context)
{
    // To avoid compiler errors/warnings. This context might be used by a target
    // system to implement a proper mutex handling
    (void)p_i2c_context;

    if (0 == g_entry_count) {
        g_entry_count++;
        if (1 == g_entry_count) {
            return PAL_STATUS_SUCCESS;
        }
    }
    traceln("%s: acquired failed", __func__);
    return PAL_STATUS_FAILURE;
}

static void pal_i2c_release(const void* p_i2c_context)
{
    // To avoid compiler errors/warnings. This context might be used by a target
    // system to implement a proper mutex handling
    (void)p_i2c_context;

    g_entry_count = 0;
}

static void invoke_upper_layer_callback(const pal_i2c_t* p_pal_i2c_ctx, optiga_lib_status_t event)
{
    upper_layer_callback_t upper_layer_handler;

    // Casting a data pointer to a function pointer is not OK according to ISO C. However, everyone
    // does it...
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    upper_layer_handler = (upper_layer_callback_t)p_pal_i2c_ctx->upper_layer_event_handler;
#pragma GCC diagnostic pop

    upper_layer_handler(p_pal_i2c_ctx->p_upper_layer_ctx, event);

    // Release I2C Bus
    pal_i2c_release(p_pal_i2c_ctx->p_upper_layer_ctx);
}

// !!!OPTIGA_LIB_PORTING_REQUIRED
// The next 5 functions are required only in case you have interrupt based i2c implementation
// void i2c_master_end_of_transmit_callback(void)
//{
//    invoke_upper_layer_callback(gp_pal_i2c_current_ctx, PAL_I2C_EVENT_SUCCESS);
//}
//
// void i2c_master_end_of_receive_callback(void)
//{
//    invoke_upper_layer_callback(gp_pal_i2c_current_ctx, PAL_I2C_EVENT_SUCCESS);
//}
//
// void i2c_master_error_detected_callback(void)
//{
//    invoke_upper_layer_callback(gp_pal_i2c_current_ctx, PAL_I2C_EVENT_ERROR);
//}
//
// void i2c_master_nack_received_callback(void)
//{
//    i2c_master_error_detected_callback();
//}
//
// void i2c_master_arbitration_lost_callback(void)
//{
//    i2c_master_error_detected_callback();
//}

pal_status_t pal_i2c_init(const pal_i2c_t* p_i2c_context)
{
    (void)p_i2c_context;
    return PAL_STATUS_SUCCESS;
}

pal_status_t pal_i2c_deinit(const pal_i2c_t* p_i2c_context)
{
    (void)p_i2c_context;
    return PAL_STATUS_SUCCESS;
}

pal_status_t pal_i2c_write(const pal_i2c_t* p_i2c_context, uint8_t* p_data, uint16_t length)
{
    // traceln("%s", __func__);
    pal_status_t status = PAL_STATUS_FAILURE;
    struct _i2c_m_msg packet;
    uint8_t retries = 25U;
    int32_t r;

    packet.addr = p_i2c_context->slave_address;
    packet.len = (int32_t)length;
    packet.buffer = p_data;
    packet.flags = I2C_M_SEVEN | I2C_M_STOP;

    // Acquire the I2C bus before read/write
    if (PAL_STATUS_SUCCESS == pal_i2c_acquire(p_i2c_context)) {
        gp_pal_i2c_current_ctx = p_i2c_context;

        // Invoke the low level i2c master driver API to write to the bus
        //  !!!OPTIGA_LIB_PORTING_REQUIRED
        do {
            r = i2c_m_sync_transfer(p_i2c_context->p_i2c_hw_config, &packet);
            delay_ms(2U);
        } while (retries-- && r != I2C_OK);

        if (r != I2C_OK) {
            // If I2C Master fails to invoke the write operation, invoke upper layer event handler
            // with error.

            // Casting a data pointer to a function pointer is not OK according to ISO C. However,
            // everyone does it...
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
            ((upper_layer_callback_t)(p_i2c_context->upper_layer_event_handler))(
                p_i2c_context->p_upper_layer_ctx, PAL_I2C_EVENT_ERROR);
#pragma GCC diagnostic pop

            // Release I2C Bus
            pal_i2c_release(p_i2c_context);
        } else {
            // !!!OPTIGA_LIB_PORTING_REQUIRED
            /**
             * Infineon I2C Protocol is a polling based protocol, if foo_i2c_write will fail it will
             * be reported to the upper layers by calling
             * (p_i2c_context->upper_layer_event_handler))(p_i2c_context->p_upper_layer_ctx ,
             * PAL_I2C_EVENT_ERROR); If the function foo_i2c_write() will succedd then two options
             * are possible
             * 1. if foo_i2c_write() is interrupt based, then you need to configure interrupts in
             * the function pal_i2c_init() so that on a succesfull transmit interrupt the callback
             * i2c_master_end_of_transmit_callback(), in case of successfull receive
             * i2c_master_end_of_receive_callback() callback in case of not acknowedged, arbitration
             * lost, generic error i2c_master_nack_received_callback() or
             *    i2c_master_arbitration_lost_callback()
             * 2. If foo_i2c_write() is a blocking function which will return either ok or failure
             * after transmitting data you can handle this case directly here and call
             *    invoke_upper_layer_callback(gp_pal_i2c_current_ctx, PAL_I2C_EVENT_SUCCESS);
             *
             */
            invoke_upper_layer_callback(gp_pal_i2c_current_ctx, PAL_I2C_EVENT_SUCCESS);
            status = PAL_STATUS_SUCCESS;
        }
    } else {
        status = PAL_STATUS_I2C_BUSY;
        // Casting a data pointer to a function pointer is not OK according to ISO C. However,
        // everyone does it...
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
        ((upper_layer_callback_t)(p_i2c_context->upper_layer_event_handler))(
            p_i2c_context->p_upper_layer_ctx, PAL_I2C_EVENT_BUSY);
#pragma GCC diagnostic pop
    }
    return status;
}

pal_status_t pal_i2c_read(const pal_i2c_t* p_i2c_context, uint8_t* p_data, uint16_t length)
{
    // traceln("%s", __func__);
    // int32_t start = pal_os_timer_get_time_in_milliseconds();
    pal_status_t status = PAL_STATUS_FAILURE;
    struct _i2c_m_msg packet;
    uint8_t retries = 25U;
    int32_t r;

    packet.addr = p_i2c_context->slave_address;
    packet.len = (int32_t)length;
    packet.buffer = p_data;
    packet.flags = I2C_M_SEVEN | I2C_M_RD | I2C_M_STOP;

    // Acquire the I2C bus before read/write
    if (PAL_STATUS_SUCCESS == pal_i2c_acquire(p_i2c_context)) {
        gp_pal_i2c_current_ctx = p_i2c_context;

        // Invoke the low level i2c master driver API to read from the bus
        do {
            r = i2c_m_sync_transfer(p_i2c_context->p_i2c_hw_config, &packet);
            delay_ms(2U);
        } while (retries-- && r != I2C_OK);

        if (r != I2C_OK) {
            traceln("%s transfer failed", __func__);
            // If I2C Master fails to invoke the read operation, invoke upper layer event handler
            // with error.
            // Casting a data pointer to a function pointer is not OK according to ISO C. However,
            // everyone does it...
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
            ((upper_layer_callback_t)(p_i2c_context->upper_layer_event_handler))(
                p_i2c_context->p_upper_layer_ctx, PAL_I2C_EVENT_ERROR);
#pragma GCC diagnostic pop

            // Release I2C Bus
            pal_i2c_release(p_i2c_context);
        } else {
            // !!!OPTIGA_LIB_PORTING_REQUIRED
            /**
             * Similar to the foo_i2c_write() case you can directly call
             * invoke_upper_layer_callback(gp_pal_i2c_current_ctx, PAL_I2C_EVENT_SUCCESS);
             * if you have blocking (non-interrupt) i2c calls
             */
            invoke_upper_layer_callback(gp_pal_i2c_current_ctx, PAL_I2C_EVENT_SUCCESS);
            status = PAL_STATUS_SUCCESS;
        }
    } else {
        status = PAL_STATUS_I2C_BUSY;
        // Casting a data pointer to a function pointer is not OK according to ISO C. However,
        // everyone does it...
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
        ((upper_layer_callback_t)(p_i2c_context->upper_layer_event_handler))(
            p_i2c_context->p_upper_layer_ctx, PAL_I2C_EVENT_BUSY);
#pragma GCC diagnostic pop
    }
    // uint32_t final_time = pal_os_timer_get_time_in_milliseconds() - start;
    // traceln("took %lu ms", final_time);
    return status;
}

pal_status_t pal_i2c_set_bitrate(const pal_i2c_t* p_i2c_context, uint16_t bitrate)
{
    // traceln("%s %d", __func__, bitrate);
    pal_status_t return_status = PAL_STATUS_FAILURE;
    optiga_lib_status_t event = PAL_I2C_EVENT_ERROR;

    // Acquire the I2C bus before setting the bitrate
    if (PAL_STATUS_SUCCESS == pal_i2c_acquire(p_i2c_context)) {
        // If the user provided bitrate is greater than the I2C master hardware maximum supported
        // value, set the I2C master to its maximum supported value.
        if (bitrate > PAL_I2C_MASTER_MAX_BITRATE) {
            bitrate = PAL_I2C_MASTER_MAX_BITRATE;
        }

        do {
            if (0 != i2c_m_sync_disable(&I2C_0)) {
                traceln("%s: failed to disable i2c", __func__);
                return_status = PAL_STATUS_FAILURE;
                break;
            }

            if (0 != i2c_m_sync_set_baudrate(p_i2c_context->p_i2c_hw_config, 0, bitrate)) {
                traceln("%s: failed to set bitrate", __func__);
                return_status = PAL_STATUS_FAILURE;
                break;
            }

            if (0 != i2c_m_sync_enable(&I2C_0)) {
                traceln("%s: failed to enable i2c", __func__);
                return_status = PAL_STATUS_FAILURE;
                break;
            }
            event = PAL_I2C_EVENT_SUCCESS;
            return_status = PAL_STATUS_SUCCESS;
        } while (0);
    } else {
        return_status = PAL_STATUS_I2C_BUSY;
        event = PAL_I2C_EVENT_BUSY;
    }
    if (0 != p_i2c_context->upper_layer_event_handler) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
        ((upper_layer_callback_t)(p_i2c_context->upper_layer_event_handler))(
            p_i2c_context->p_upper_layer_ctx, event);
#pragma GCC diagnostic pop
    }
    // Release I2C Bus if its acquired
    if (PAL_STATUS_I2C_BUSY != return_status) {
        pal_i2c_release(p_i2c_context);
    }
    return return_status;
}

/**
 * @}
 */

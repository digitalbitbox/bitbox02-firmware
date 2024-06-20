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

#include "usb.h"
#include "hal_delay.h"
#include "util.h"
#ifndef TESTING
#include "hid_hww.h"
#include "iap2/iap2.h"
#include "usb_desc.h"
#include "usbdc.h"
#if APP_U2F == 1
#include "u2f.h"
#include <usb/class/hid/u2f/hid_u2f.h>
#endif
#endif
#include "usb_processing.h"

#ifndef TESTING
#include <hal_timer.h>
#include <u2f/u2f_packet.h>
#include <usb/usb_packet.h>
extern struct timer_descriptor TIMER_0;
#endif

#define TIMEOUT_TICK_PERIOD_MS 100

#ifndef TESTING
static uint8_t _ctrl_endpoint_buffer[USB_REPORT_SIZE];
static uint8_t _descriptor_bytes[] = {
    USB_DESC_FS}; // Device descriptors and Configuration descriptors list.
static struct usbd_descriptors _descriptor[] = {
    {_descriptor_bytes, _descriptor_bytes + sizeof(_descriptor_bytes)}};
static void (*_on_hww_init)(void) = NULL;
static void _hww_endpoint_available(void);
#if APP_U2F == 1
static void _u2f_endpoint_available(void);
#endif

/* ==== HWW ==== */
static void _hww_endpoint_available(void)
{
    if (!hid_hww_is_enabled()) {
        return;
    }
    if (_on_hww_init != NULL) {
        _on_hww_init();
    }
    hid_hww_setup();
}

#if APP_U2F == 1
/* ==== U2F ==== */
static void _u2f_endpoint_available(void)
{
    if (!hid_u2f_is_enabled()) {
        return;
    };
    u2f_device_setup();
    hid_u2f_setup();
}
#endif
#endif

#if !defined(TESTING) && APP_U2F == 1
static void _timeout_cb(const struct timer_task* const timer_task)
{
    (void)timer_task;
    u2f_packet_timeout_tick();
}
#endif

static bool _usb_enabled = false;

static volatile bool _iap2_data_ready = false;

static void iap2_ctrl_rd(uint16_t count)
{
    traceln("%s %u", "ctrl read got data", count);
}
static void iap2_ctrl_wr(uint16_t count)
{
    traceln("%s %u", "ctrl write got data", count);
}
static uint8_t read_buf[64];
static void iap2_bulk_rd(const uint8_t ep, const enum usb_xfer_code rc, const uint32_t count)
{
    (void)ep;
    (void)rc;
    //_iap2_data_ready = true;
    uint32_t len = count > sizeof(read_buf) ? sizeof(read_buf) : count;
    iap2_read(read_buf, len);
    traceln("%s %lu", "read got data", len);
}
static void iap2_bulk_wr(const uint8_t ep, const enum usb_xfer_code rc, const uint32_t count)
{
    (void)ep;
    (void)rc;
    traceln("%s %lu", "write got data", count);
}

int32_t usb_start(void (*on_hww_init)(void))
{
#if !defined(TESTING) && APP_U2F == 1
    static struct timer_task Timer_task;
    Timer_task.interval = TIMEOUT_TICK_PERIOD_MS;
    Timer_task.cb = _timeout_cb;
    Timer_task.mode = TIMER_TASK_REPEAT;
    timer_stop(&TIMER_0);
    timer_add_task(&TIMER_0, &Timer_task);
    timer_start(&TIMER_0);
#endif
#if !defined(TESTING)
    // required before hid init
    int32_t ret = 0;
    ret = usbdc_init(_ctrl_endpoint_buffer);
    if (ret != 0) {
        return ret;
    }
    _on_hww_init = on_hww_init;
    ret = hid_hww_init(_hww_endpoint_available);
    if (ret != 0) {
        return ret;
    }
#if APP_U2F == 1
    ret = hid_u2f_init(_u2f_endpoint_available);
    if (ret != 0) {
        return ret;
    }
#endif
    ret = iap2_register_callback(IAP2_CTRL_READ_CB, (FUNC_PTR)iap2_ctrl_rd);
    ret = iap2_register_callback(IAP2_CTRL_WRITE_CB, (FUNC_PTR)iap2_ctrl_wr);
    ret = iap2_register_callback(IAP2_BULK_READ_CB, (FUNC_PTR)iap2_bulk_rd);
    ret = iap2_register_callback(IAP2_BULK_WRITE_CB, (FUNC_PTR)iap2_bulk_wr);
    traceln("%s", "callbacks registered");
    ret = iap2_init();
    if (ret != 0) {
        return ret;
    }
    ret = usbdc_start(_descriptor);
    if (ret != 0) {
        return ret;
    }
    usbdc_attach();
    while (!iap2_is_enabled()) {
    }
    // uint8_t buf[100] = {0};
    // for(;;) {
    //     //if (_iap2_data_ready) {
    //     //    traceln("0xff5a? %s", util_uint8_to_hex_alloc(buf, sizeof(buf)));
    //     //    memset(buf, 0, sizeof(buf));
    //     //    _iap2_data_ready = false;
    //     //} else {
    //     //    iap2_read(buf, 100);
    //     //}
    //     delay_ms(10);
    // }
#else
    (void)on_hww_init;
#endif
    usb_processing_init();
    _usb_enabled = true;
    return 0;
}

void usb_stop(void)
{
    _usb_enabled = false;
#if !defined(TESTING)
    usbdc_detach();
    usbdc_stop();
    usbdc_deinit();
#endif
}

bool usb_is_enabled(void)
{
    return _usb_enabled;
}

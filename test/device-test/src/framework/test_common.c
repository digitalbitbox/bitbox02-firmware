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

#include <string.h>

#include "test_common.h"

#include "queue.h"
#include <usb/class/hid/hww/hid_hww.h>
#include <usb/class/hid/u2f/hid_u2f.h>
#include <usb/class/usb_desc.h>
#include <usb/device/usbdc.h>
#include <usb/usb.h>
#include <usb/usb_desc_bytes.h>

#include "screen.h"
#include "util.h"

/* endpoint direction */
#define DIR_OUT 1
#define DIR_IN 0

static uint8_t usb_desc_bytes[] = {
    USB_DESC_FS}; // Device descriptors and Configuration descriptors list.
static struct usbd_descriptors usb_desc[] = {
    {usb_desc_bytes, usb_desc_bytes + sizeof(usb_desc_bytes)}};

/**
 * Echo content of the given packet into the frame.
 */
void echo_data(const Packet* packet, USB_FRAME* write_frame)
{
    int ret_write = write_single_frame(packet, write_frame);
    if (ret_write == 0) {
        char msg[100];
        sprintf(msg, "echoing: %s", (const char*)write_frame->init.data);
        screen_print_debug(msg, 1000);
    } else if (ret_write == 1) {
        screen_print_debug("message too long", 1000);
    } else if (ret_write == 2) {
        screen_print_debug("need more frames", 1000);
    } else {
        screen_print_debug("unexpected response", 1000);
    }
}

/**
 * Reads single frame and appends data in given packet
 * The following return values are returned:
 * - 0: frame parsed and packet prepared.
 * - 1: frame message is longer than what the packet can hold.
 * - 2: more than one frame expected.
 */
int read_single_frame(USB_FRAME* frame, Packet* packet)
{
    if ((unsigned)FRAME_MSG_LEN(*frame) > USB_DATA_MAX_LEN) {
        // Message too long
        return 1;
    }

    memset(packet, 0, sizeof(Packet));
    packet->len = FRAME_MSG_LEN(*frame);
    packet->cmd = frame->type;
    packet->cid = frame->cid;
    memcpy(packet->data_addr, frame->init.data, USB_DATA_MAX_LEN);

    return 0;
}

/**
 * Sends single frame and appends data in given packet
 * The following return values are returned:
 * - 0: frame parsed and packet prepared.
 * - 1: frame message is longer than what the packet can hold.
 * - 2: cannot fit data into frame.
 */
int write_single_frame(const Packet* packet, USB_FRAME* frame)
{
    uint32_t l = packet->len;

    memset(frame, 0, sizeof(USB_FRAME));
    frame->cid = packet->cid;
    frame->init.cmd = packet->cmd;
    frame->init.bcnth = packet->len >> 8;
    frame->init.bcntl = packet->len & 0xff;

    if (sizeof(frame->init.data) < l) {
        return 2;
    }
    memcpy(frame->init.data, packet->data_addr, l);
    if ((unsigned)FRAME_MSG_LEN(*frame) > USB_DATA_MAX_LEN) {
        // Message too long
        return 1;
    }
    return 0;
}

/**
 * Returns the packet data as a string.
 * @param[in] packet The packet from where we extract the string.
 * @return string The packet data as string. The returned pointer is to a statically allocated
 * buffer
 */
char* data_to_string(const Packet* packet)
{
    static char buf[2048];
    int wrote = snprintf(buf, sizeof(buf), "%s", packet->data_addr);
    if (wrote >= (int)sizeof(buf)) {
        // TODO convert to traceln
        printf("%s\n", "Internal error: packet to large to print as string");
    }
    return buf;
}

// USB_REPORT_SIZE = 0x40
static uint8_t usb_ctrl_endpoint_buffer[USB_REPORT_SIZE];

static struct test_usb_metadata* hww_metadata = NULL;
static struct test_usb_metadata* u2f_metadata = NULL;

static void test_usb_hww_endpoint(void)
{
    if (!hid_hww_is_enabled()) {
        screen_print_debug("HWW interface disabled", 1000);
        return;
    };

    int32_t ret_ep_out = usb_d_ep_register_callback(
        hid_hww_get_ep(DIR_OUT), USB_D_EP_CB_XFER, (const FUNC_PTR)hww_metadata->usb_cb_out);
    int32_t ret_ep_in = ERR_NONE;
    if (hww_metadata->usb_cb_in != NULL) {
        ret_ep_in = usb_d_ep_register_callback(
            hid_hww_get_ep(DIR_IN), USB_D_EP_CB_XFER, (const FUNC_PTR)hww_metadata->usb_cb_in);
    }

    if (ret_ep_out != ERR_NONE) {
        screen_print_debug("failed to register hww ep OUT callback", 1000);
    }
    if (ret_ep_in != ERR_NONE) {
        screen_print_debug("failed to register hww ep IN callback", 1000);
    }

    struct usb_d_ep_status hww_out_status;
    usb_d_ep_get_status(hid_hww_get_ep(DIR_OUT), &hww_out_status);
    switch (hww_out_status.state) {
    case USB_EP_S_IDLE:
        screen_print_debug("hww ep OUT idle", 1000);
        break;
    case USB_EP_S_HALTED:
        screen_print_debug("hww ep OUT halted", 1000);
        break;
    case USB_EP_S_ERROR:
        screen_print_debug("hww ep OUT error", 1000);
        break;
    case USB_EP_S_DISABLED:
        screen_print_debug("hww ep OUT disabled", 1000);
        break;
    default:
        screen_print_debug("hww ep OUT busy", 1000);
    }

    if (hww_metadata->usb_cb_in != NULL) {
        struct usb_d_ep_status hww_in_status;
        usb_d_ep_get_status(hid_hww_get_ep(DIR_IN), &hww_in_status);
        switch (hww_in_status.state) {
        case USB_EP_S_IDLE:
            screen_print_debug("hww ep IN idle", 1000);
            break;
        case USB_EP_S_HALTED:
            screen_print_debug("hww ep IN halted", 1000);
            break;
        case USB_EP_S_ERROR:
            screen_print_debug("hww ep IN error", 1000);
            break;
        case USB_EP_S_DISABLED:
            screen_print_debug("hww ep IN disabled", 1000);
            break;
        default:
            screen_print_debug("hww ep IN busy", 1000);
        }
    }

    // TODO: marko refactored the USB stuff, needs to be fixed
    // Wait for data
    // hid_hww_read(hww_metadata->usb_hid_out_report, USB_HID_REPORT_OUT_SIZE);
}

static void test_usb_u2f_endpoint(void)
{
    if (!hid_u2f_is_enabled()) {
        screen_print_debug("U2F interface disabled", 1000);
        return;
    };

    int32_t ret_ep_out = usb_d_ep_register_callback(
        hid_u2f_get_ep(DIR_OUT), USB_D_EP_CB_XFER, (const FUNC_PTR)u2f_metadata->usb_cb_out);
    int32_t ret_ep_in = ERR_NONE;
    if (u2f_metadata->usb_cb_in != NULL) {
        ret_ep_in = usb_d_ep_register_callback(
            hid_u2f_get_ep(DIR_IN), USB_D_EP_CB_XFER, (const FUNC_PTR)u2f_metadata->usb_cb_in);
    }

    if (ret_ep_out != ERR_NONE) {
        screen_print_debug("failed to register u2f ep OUT callback", 1000);
    }
    if (ret_ep_in != ERR_NONE) {
        screen_print_debug("failed to register u2f ep IN callback", 1000);
    }

    struct usb_d_ep_status u2f_out_status;
    usb_d_ep_get_status(hid_u2f_get_ep(DIR_OUT), &u2f_out_status);
    switch (u2f_out_status.state) {
    case USB_EP_S_IDLE:
        screen_print_debug("u2f ep OUT idle", 1000);
        break;
    case USB_EP_S_HALTED:
        screen_print_debug("u2f ep OUT halted", 1000);
        break;
    case USB_EP_S_ERROR:
        screen_print_debug("u2f ep OUT error", 1000);
        break;
    case USB_EP_S_DISABLED:
        screen_print_debug("u2f ep OUT disabled", 1000);
        break;
    default:
        screen_print_debug("u2f ep OUT busy", 1000);
    }

    struct usb_d_ep_status u2f_in_status;
    usb_d_ep_get_status(hid_u2f_get_ep(DIR_IN), &u2f_in_status);
    switch (u2f_in_status.state) {
    case USB_EP_S_IDLE:
        screen_print_debug("u2f ep IN idle", 1000);
        break;
    case USB_EP_S_HALTED:
        screen_print_debug("u2f ep IN halted", 1000);
        break;
    case USB_EP_S_ERROR:
        screen_print_debug("u2f ep IN error", 1000);
        break;
    case USB_EP_S_DISABLED:
        screen_print_debug("u2f ep IN disabled", 1000);
        break;
    default:
        screen_print_debug("u2f ep IN busy", 1000);
    }

    // TODO: marko refactored the USB stuff, needs to be fixed
    // Wait for data
    // hid_u2f_read(u2f_metadata->usb_hid_out_report, USB_HID_REPORT_OUT_SIZE);
}

uint8_t test_usb_init(
    struct test_usb_metadata* _hww_metadata,
    struct test_usb_metadata* _u2f_metadata)
{
    hww_metadata = _hww_metadata;
    u2f_metadata = _u2f_metadata;

    int32_t ret_usbdc = usbdc_init(usb_ctrl_endpoint_buffer);

    if (ret_usbdc != 0) {
        return ERR_USBDC_FAILED;
    }

    int32_t ret_hww_init = ERR_NONE;
    int32_t ret_u2f_init = ERR_NONE;
    if (hww_metadata != NULL) {
        if (hww_metadata->endpoint_available_cb != NULL) {
            ret_hww_init = hid_hww_init(hww_metadata->endpoint_available_cb);
        } else {
            ret_hww_init = hid_hww_init(test_usb_hww_endpoint);
        }
    }
    if (u2f_metadata != NULL) {
        if (u2f_metadata->endpoint_available_cb != NULL) {
            ret_u2f_init = hid_u2f_init(u2f_metadata->endpoint_available_cb);
        } else {
            ret_u2f_init = hid_u2f_init(test_usb_u2f_endpoint);
        }
    }
    if (ret_u2f_init != ERR_NONE || ret_hww_init != ERR_NONE) {
        return ERR_HID_FAILED;
    }
    usbdc_start(usb_desc);
    usbdc_attach();

    return ERR_NONE;
}

/**
 * Reads a frame from the queue and passes it to the HID interface.
 */
void test_hid_send(enum interface_type interface)
{
    const uint8_t* data = queue_pull(queue_hww_queue());
    if (data != NULL) {
        (void)interface;
        // TODO: marko refactored the USB stuff, needs to be fixed
        /*if (interface == HWW) {
            hid_hww_write(data);
        } else {
            hid_u2f_write(data);
        }*/
    }
}

static void read_and_print2screen(struct test_usb_metadata* metadata)
{
    char buf[100];
    sprintf(buf, "Received USB data: %d", metadata->cnt);
    screen_print_debug(buf, 1000);
    metadata->cnt++;

    int ret = read_single_frame((USB_FRAME*)metadata->usb_hid_out_report, &metadata->packet);
    if (ret == 0) {
        screen_print_debug(data_to_string(&metadata->packet), 1000);
    } else if (ret == 1) {
        screen_print_debug("message too long", 1000);
    } else if (ret == 2) {
        screen_print_debug("need more data", 1000);
    }
}

void test_hww_out_echo(const uint8_t ep, const enum usb_xfer_code rc, const uint32_t count)
{
    (void)(ep);
    (void)(rc);
    (void)(count);

    read_and_print2screen(hww_metadata);

    echo_data(&hww_metadata->packet, &hww_metadata->write_frame);
    // hid_hww_write((uint8_t*)&hww_metadata->write_frame);

    // Wait for data
    // TODO: marko refactored the USB stuff, needs to be fixed
    // hid_hww_read(hww_metadata->usb_hid_out_report, USB_HID_REPORT_OUT_SIZE);
}

void test_hww_out_print2screen(const uint8_t ep, const enum usb_xfer_code rc, const uint32_t count)
{
    (void)(ep);
    (void)(rc);
    (void)(count);

    read_and_print2screen(hww_metadata);

    // TODO: marko refactored the USB stuff, needs to be fixed
    // Wait for data
    // hid_hww_read(hww_metadata->usb_hid_out_report, USB_HID_REPORT_OUT_SIZE);
}

void test_u2f_out_echo(const uint8_t ep, const enum usb_xfer_code rc, const uint32_t count)
{
    (void)(ep);
    (void)(rc);
    (void)(count);

    read_and_print2screen(u2f_metadata);

    echo_data(&u2f_metadata->packet, &u2f_metadata->write_frame);
    // TODO: marko refactored the USB stuff, needs to be fixed
    // hid_u2f_write((uint8_t*) &u2f_metadata->write_frame);

    // TODO: marko refactored the USB stuff, needs to be fixed
    // Wait for data
    // hid_u2f_read(u2f_metadata->usb_hid_out_report, USB_HID_REPORT_OUT_SIZE);
}

void test_u2f_out_print2screen(const uint8_t ep, const enum usb_xfer_code rc, const uint32_t count)
{
    (void)(ep);
    (void)(rc);
    (void)(count);

    read_and_print2screen(u2f_metadata);

    // TODO: marko refactored the USB stuff, needs to be fixed
    // Wait for data
    // hid_u2f_read(u2f_metadata->usb_hid_out_report, USB_HID_REPORT_OUT_SIZE);
}

void test_in(void)
{
    screen_print_debug("USB data send", 1000);
}

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

#ifndef _TEST_COMMON_H_
#define _TEST_COMMON_H_

#include <usb/class/hid/hid.h>
#include <usb/class/usb_desc.h>
#include <usb/usb_frame.h>
#include <usb/usb_packet.h>

#define ERR_NONE 0
#define ERR_USBDC_FAILED 1
#define ERR_HID_FAILED 2

enum interface_type { HWW, U2F };

void echo_data(const Packet* packet, USB_FRAME* write_frame);

int read_single_frame(USB_FRAME* frame, Packet* packet);

int write_single_frame(const Packet* packet, USB_FRAME* frame);

/**
 * Returns the packet data as a string.
 * @param[in] packet The packet from where we extract the string.
 * @return string The packet data as string. The caller must free the returned value.
 */
char* data_to_string(const Packet* packet);

struct test_usb_metadata {
    uint8_t usb_hid_out_report[USB_HID_REPORT_OUT_SIZE];
    int cnt;
    Packet packet;
    USB_FRAME write_frame;
    void (*usb_cb_out)(uint8_t ep, enum usb_xfer_code rc, uint32_t count);
    void (*usb_cb_in)(void);
    void (*endpoint_available_cb)(void);
};

uint8_t test_usb_init(
    struct test_usb_metadata* hww_metadata,
    struct test_usb_metadata* u2f_metadata);

void test_hid_send(enum interface_type interface);

void test_hww_out_print2screen(uint8_t ep, enum usb_xfer_code rc, uint32_t count);

void test_hww_out_echo(uint8_t ep, enum usb_xfer_code rc, uint32_t count);

void test_u2f_out_print2screen(uint8_t ep, enum usb_xfer_code rc, uint32_t count);

void test_u2f_out_echo(uint8_t ep, enum usb_xfer_code rc, uint32_t count);

void test_in(void);

#endif

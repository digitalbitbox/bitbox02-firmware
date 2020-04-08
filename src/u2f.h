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

#ifndef _U2F_DEVICE_H_
#define _U2F_DEVICE_H_

#include <usb/usb_packet.h>

void u2f_device_setup(void);

/**
 * When the U2F stack is blocking the device, checks if
 * a U2F request is allowed to be processed.
 * U2F requests are allowed if they match the request type that
 * caused the U2F stack to block.
 */
bool u2f_blocking_request_can_go_through(const Packet* in_packet);

/**
 * Create an output packet used to signal to the client
 * that a valid U2F request has been received, but it can't be processed
 * because the device is busy doing something else.
 *
 * We respond to any U2F request that can't be processed by the device
 * with U2F_SW_CONDITIONS_NOT_SATISFIED, since we're not technically able
 * to verify user presence at the moment.
 */
void u2f_blocked_req_error(Packet* out_packet, const Packet* in_packet);

/**
 * Called at every event loop to manage the U2F stack.
 */
void u2f_process(void);
void u2f_timer(void);

/**
 * Called to abort any operation that blocked the U2F stack.
 */
void u2f_abort_outstanding_op(void);

#endif

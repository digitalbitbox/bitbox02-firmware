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

#include "reset.h"

#include "hardfault.h"
#include "keystore.h"
#include "memory/memory.h"
#include "memory/smarteeprom.h"

#ifndef TESTING
#include "atecc/atecc.h"
#include <driver_init.h>
#include <hal_delay.h>
#include <ui/components/status.h>
#include <ui/ugui/ugui.h>
#endif

#if !defined(TESTING)
/*
 * Shows a centered "Device reset" label.
 * Waits for 3000ms, then exit.
 */
static void _show_reset_label(bool status)
{
    const char* msg = "Device reset";
    component_t* comp = status_create(msg, status, NULL, NULL);
    UG_ClearBuffer();
    comp->f->render(comp);
    UG_SendBuffer();
    comp->f->cleanup(comp);
    delay_ms(3000);
}
#endif

void reset_reset(bool status)
{
    keystore_lock();
#if !defined(TESTING)
    if (!securechip_update_keys()) {
        Abort("Could not reset secure chip.");
    }
#if APP_U2F == 1
    if (!securechip_u2f_counter_set(0)) {
        Abort("Could not initialize U2F counter.");
    }
#endif
#endif
    if (!memory_reset_hww()) {
        Abort("Could not reset memory.");
    }
#if !defined(TESTING)
    /* Disable SmartEEPROM, so it will be erased on next reboot. */
    smarteeprom_disable();
    _show_reset_label(status);
    _reset_mcu();
#else
    (void)status;
#endif
}

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

#include "reboot.h"
#include "confirm.h"
#include <memory/memory.h>
#include <platform/platform_config.h>
#include <screen.h>
#ifndef TESTING
#include <driver_init.h>
#endif

static void _reboot(void)
{
    auto_enter_t auto_enter = {
        .value = sectrue_u8,
    };
    upside_down_t upside_down = {
#if PLATFORM_BITBOX02 == 1 || defined(TESTING)
        .value = screen_is_upside_down(),
#elif PLATFORM_BITBOXBASE == 1
        .value = false,
#else
#error "No platform"
#endif
    };
    if (!memory_bootloader_set_flags(auto_enter, upside_down)) {
        // If this failed, we might not be able to reboot into the bootloader.
        // We will try anyway, no point in aborting here.
    }
#ifndef TESTING
    _reset_mcu();
#endif
}

bool workflow_reboot(void)
{
#if PLATFORM_BITBOX02 == 1
    // Only ask on the bitbox02 platform, bitboxbase will always reboot
    const confirm_params_t params = {
        .title = "",
        .body = "Proceed to upgrade?",
    };
    if (!workflow_confirm(&params)) {
        return false;
    }
#endif
    _reboot();
    return true;
}

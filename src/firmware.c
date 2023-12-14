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

#include "common_main.h"
#include "driver_init.h"
#include "firmware_main_loop.h"
#include "hardfault.h"
#include "memory/bitbox02_smarteeprom.h"
#include "platform/platform_config.h"
#include "platform_init.h"
#include "qtouch.h"
#include "screen.h"
#include "ui/screen_stack.h"
#include "util.h"
#include "workflow/idle_workflow.h"
#include "workflow/orientation_screen.h"

#include "keyrotation.h"

uint32_t __stack_chk_guard = 0;

int main(void)
{
    init_mcu();
    system_init();
    platform_init();
    __stack_chk_guard = common_stack_chk_guard();
    screen_init();
    screen_splash();
    qtouch_init();
    common_main();
    bitbox02_smarteeprom_init();
    traceln("%s", "Device initialized");

    keyrotation();

    orientation_screen_blocking();
    idle_workflow_blocking();
    firmware_main_loop();
    return 0;
}

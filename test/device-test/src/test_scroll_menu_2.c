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

#include <common_main.h>
#include <driver_init.h>
#include <firmware_main_loop.h>
#include <platform_init.h>
#include <screen.h>
#include <string.h>
#include <ui/components/scroll_through_all_variants.h>
#include <ui/screen_stack.h>
#include <usb/usb.h>

#include "qtouch.h"
#include "random.h"
#include "util.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

uint32_t __stack_chk_guard = 0;

int main(void)
{
    init_mcu();
    system_init();
    platform_init();
    //__stack_chk_guard = common_stack_chk_guard();
    screen_init();
    qtouch_init();

    const char* words[] = {"first", "second", "third", "forth"};
    component_t* test_scroll_through_2 =
        scroll_through_all_variants_create(words, NULL, NULL, 4, NULL, NULL, NULL, NULL, NULL);

    ui_screen_stack_push(test_scroll_through_2);
    firmware_main_loop();
}

#pragma GCC diagnostic pop

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

#include "confirm_mnemonic.h"
#include "label.h"
#include "scroll_through_all_variants.h"

#include <hardfault.h>
#include <screen.h>
#include <ui/ui_util.h>

#include <stdio.h>
#include <string.h>

/**
 * Collects all component functions.
 */
static const component_functions_t _component_functions = {
    .cleanup = ui_util_component_cleanup,
    .render = ui_util_component_render_subcomponents,
    .on_event = ui_util_on_event_noop,
};

/**
 * Creates a screen that allows to confirm the mnemonic words.
 */
component_t* confirm_mnemonic_create(
    const char** wordlist,
    uint8_t length,
    uint8_t index,
    void (*check_word_cb)(uint8_t, void*),
    void* check_word_cb_param,
    void (*cancel_cb)(void*),
    void* cancel_cb_param)
{
    component_t* confirm_mnemonic = malloc(sizeof(component_t));
    if (!confirm_mnemonic) {
        Abort("Error: malloc confirm_mnemonic");
    }
    memset(confirm_mnemonic, 0, sizeof(component_t));
    confirm_mnemonic->f = &_component_functions;

    confirm_mnemonic->dimension.width = SCREEN_WIDTH;
    confirm_mnemonic->dimension.height = SCREEN_HEIGHT;

    char title[100];
    snprintf(title, sizeof(title), "%02d", index + 1);
    ui_util_add_sub_component(
        confirm_mnemonic, label_create(title, NULL, CENTER_TOP, confirm_mnemonic));

    ui_util_add_sub_component(
        confirm_mnemonic,
        scroll_through_all_variants_create(
            wordlist,
            check_word_cb,
            check_word_cb_param,
            length,
            "",
            NULL,
            cancel_cb,
            cancel_cb_param,
            confirm_mnemonic));

    return confirm_mnemonic;
}

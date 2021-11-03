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

#include "info_centered.h"
#include "../ui_util.h"
#include "button.h"
#include "label.h"

#include <hardfault.h>
#include <screen.h>

#include <string.h>

/********************************** Component Functions **********************************/

/**
 * Collects all component functions.
 */
static const component_functions_t _component_functions = {
    .cleanup = ui_util_component_cleanup,
    .render = ui_util_component_render_subcomponents,
    .on_event = ui_util_on_event_noop,
};

/********************************** Create Instance **********************************/

/**
 * Creates a info screen that renders the given text in the center. If a skip callback
 * is defined, a skip button is rendered, which calls the callback if pushed.
 * @param[in] text The info text.
 * @param[in] skip_callback The optional skip callback.
 */
component_t* info_centered_create(const char* text, void (*skip_callback)(component_t*))
{
    component_t* info_centered = malloc(sizeof(component_t));
    if (!info_centered) {
        Abort("Error: malloc info_centered");
    }
    memset(info_centered, 0, sizeof(component_t));

    info_centered->f = &_component_functions;

    info_centered->dimension.width = SCREEN_WIDTH;
    info_centered->dimension.height = SCREEN_HEIGHT;

    ui_util_add_sub_component(info_centered, label_create(text, NULL, CENTER, info_centered));
    if (skip_callback != NULL) {
        component_t* skip_button =
            button_create("Skip", bottom_slider, SCREEN_WIDTH / 2, skip_callback, info_centered);
        ui_util_add_sub_component(info_centered, skip_button);
    }

    return info_centered;
}

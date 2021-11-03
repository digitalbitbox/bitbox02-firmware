// Copyright 2021 Shift Crypto AG
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

#include "lockscreen.h"
#include "../ui_util.h"
#include "label.h"

#include <hardfault.h>
#include <memory/memory.h>
#include <screen.h>
#include <string.h>
#include <touch/gestures.h>
#include <ui/fonts/arial_fonts.h>

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

// Outputs `in` as is if it can be rendered to fit in `max_width`.
// If it can't, it is truncated (with appended "...") to a size where it fits.
static void _truncate_to_fit(
    const char* in,
    char* out,
    size_t out_len,
    const UG_FONT* font,
    UG_S16 max_width)
{
    if (out == NULL || out_len == 0) {
        return;
    }
    if (in[0] == 0) {
        out[0] = 0;
        return;
    }
    UG_S16 width = 0;
    UG_S16 height = 0;
    UG_FontSelect(font);
    UG_MeasureStringCentered(&width, &height, in);

    // Name fits without truncation.
    if (width <= max_width) {
        snprintf(out, MEMORY_DEVICE_NAME_MAX_LEN, "%s", in);
        return;
    }

    // Truncate if too long to a size where "<name>..." fits.
    size_t truncate_len = strlen(in) - 1;
    do {
        // truncate at `truncate_len`.
        snprintf(out, out_len, "%.*s...", (int)truncate_len, in);
        truncate_len--;
        UG_MeasureStringCentered(&width, &height, out);
    } while (truncate_len > 0 && width >= max_width);
}

component_t* lockscreen_create(void)
{
    component_t* component = malloc(sizeof(component_t));
    if (!component) {
        Abort("Error: malloc lockscreen component");
    }
    memset(component, 0, sizeof(component_t));
    component->f = &_component_functions;

    component->dimension.width = SCREEN_WIDTH;
    component->dimension.height = SCREEN_HEIGHT;

    const UG_FONT* device_name_font = &font_font_a_9X9;

    char device_name[MEMORY_DEVICE_NAME_MAX_LEN] = {0};
    memory_get_device_name(device_name);
    // Show nothing if the name is the default name.
    if (STREQ(device_name, MEMORY_DEFAULT_DEVICE_NAME)) {
        device_name[0] = 0;
    }

    char display_name[MEMORY_DEVICE_NAME_MAX_LEN + 3] = {0};
    _truncate_to_fit(
        device_name,
        display_name,
        sizeof(display_name),
        device_name_font,
        component->dimension.width);
    ui_util_add_sub_component(
        component, label_create("See the BitBoxApp", NULL, CENTER, component));
    ui_util_add_sub_component(
        component, label_create(display_name, device_name_font, CENTER_BOTTOM, component));

    return component;
}

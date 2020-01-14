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

#include "show_logo.h"
#include "image.h"
#include "ui_images.h"
#include "ui_logos.h"

#include <hardfault.h>
#include <screen.h>
#include <ui/ui_util.h>
#include <util.h>

/**
 * The component data.
 */
typedef struct {
    uint16_t screen_count;
    uint16_t timeout;
    void (*done_callback)(void);
} orientation_data_t;

static void _render(component_t* component)
{
    orientation_data_t* data = (orientation_data_t*)component->data;
    data->screen_count++;
    if (data->screen_count > data->timeout && data->done_callback != NULL) {
        data->done_callback();
        data->done_callback = NULL;
    }
    ui_util_component_render_subcomponents(component);
}

/********************************** Component Functions **********************************/

/**
 * Collects all component functions.
 */
static component_functions_t _component_functions = {
    .cleanup = ui_util_component_cleanup,
    .render = _render,
    .on_event = ui_util_on_event_noop,
};

/********************************** Create Instance **********************************/

component_t* show_logo_create(void (*done_callback)(void), uint16_t timeout)
{
    component_t* show_logo = malloc(sizeof(component_t));
    if (!show_logo) {
        Abort("Error: malloc show_logo");
    }
    orientation_data_t* data = malloc(sizeof(orientation_data_t));
    if (!data) {
        Abort("Error: malloc show_logo data");
    }
    memset(data, 0, sizeof(orientation_data_t));
    memset(show_logo, 0, sizeof(component_t));

    data->done_callback = done_callback;
    data->screen_count = 0;
    data->timeout = timeout;

    show_logo->data = data;
    show_logo->f = &_component_functions;
    show_logo->dimension.width = SCREEN_WIDTH;
    show_logo->dimension.height = SCREEN_HEIGHT;
    show_logo->position.top = 0;
    show_logo->position.left = 0;

    component_t* bb2_logo = image_create(
        IMAGE_BB2_LOGO,
        sizeof(IMAGE_BB2_LOGO),
        IMAGE_BB2_LOGO_W,
        IMAGE_BB2_LOGO_H,
        CENTER,
        show_logo);

    ui_util_add_sub_component(show_logo, bb2_logo);

    return show_logo;
}

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

#include "waiting.h"

#include "image.h"
#include "ui_images.h"
#include "ui_logos.h"

#include <hardfault.h>
#include <random.h>
#include <screen.h>
#include <ui/ui_util.h>
#include <util.h>

static void _render(component_t* component)
{
    // TODO - add an interesting animation?
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

/**
 * Creates a waiting screen.
 */
component_t* waiting_create(void)
{
    component_t* waiting = malloc(sizeof(component_t));
    if (!waiting) {
        Abort("Error: malloc waiting");
    }
    memset(waiting, 0, sizeof(component_t));
    waiting->f = &_component_functions;
    waiting->dimension.width = SCREEN_WIDTH;
    waiting->dimension.height = SCREEN_HEIGHT;
    waiting->position.top = 0;
    waiting->position.left = 0;
    component_t* bb2_logo = image_create(
        IMAGE_BB2_LOGO,
        sizeof(IMAGE_BB2_LOGO),
        IMAGE_BB2_LOGO_W,
        IMAGE_BB2_LOGO_H,
        CENTER,
        waiting);
    ui_util_add_sub_component(waiting, bb2_logo);
    return waiting;
}

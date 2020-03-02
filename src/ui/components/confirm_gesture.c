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

#include "confirm_gesture.h"
#include "../event.h"
#include "../event_handler.h"
#include "ui_images.h"

#include <hardfault.h>
#include <screen.h>
#include <touch/gestures.h>
#include <ui/ui_util.h>
#include <util.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define SCALE 6 // Divide active_count by scale to slow down motion

typedef struct {
    bool active_top; // Marker is 'active', i.e., touched
    bool active_bottom; // Marker is 'active', i.e., touched
    bool confirmed; // Confirm event occurred
    uint16_t active_count; // Start at an offset to allow movement on first touch
    uint16_t bottom_arrow_slidein; // from zero to arrow height * SCALE
} confirm_data_t;

bool confirm_gesture_is_active(component_t* component)
{
    confirm_data_t* data = (confirm_data_t*)component->data;
    return data->active_top;
}

/**
 * Renders a confirm marker.
 * @param[IN] component The confirm component.
 */
static void _render(component_t* component)
{
    uint8_t arrow_height = 5;
    int16_t x, y0, y1;
    confirm_data_t* data = (confirm_data_t*)component->data;

    // Update active_count
    if (data->active_top && data->active_bottom) {
        data->active_count++;
    } else {
        data->active_count = MAX(SCALE - 1, data->active_count - SCALE);
    }

    // Update bottom arrow slidein
    if (data->active_top) {
        if (data->bottom_arrow_slidein < arrow_height * SCALE) {
            data->bottom_arrow_slidein++;
        }
    } else if (data->bottom_arrow_slidein > 0) {
        data->bottom_arrow_slidein--;
    }

    // Draw the top arrow
    x = SCREEN_WIDTH / 9 * 8;
    y0 = data->active_count / SCALE;
    UG_FillFrame(x - arrow_height, 0, x + arrow_height, y0, screen_back_color);
    image_arrow(x, y0, arrow_height, ARROW_DOWN);

    // Draw the bottom arrow
    y1 = SCREEN_HEIGHT - data->bottom_arrow_slidein / SCALE - data->active_count / SCALE;
    if (data->bottom_arrow_slidein) {
        image_arrow(x, y1, arrow_height, ARROW_UP);
    }

    // The user confirms when the top and bottom arrows touch
    if (y0 + arrow_height > y1 && !data->confirmed) {
        event_t event;
        event.id = EVENT_CONFIRM;
        emit_event(&event);
        data->confirmed = true;
    }
}

/**
 * Event handler.
 * @param[IN] event The event to be handled.
 * @param[IN] component The confirm component.
 */
static void _on_event(const event_t* event, component_t* component)
{
    // Avoid type casting to unknown events
    if (event->id != EVENT_TOP_SLIDE_RELEASED && event->id != EVENT_BOTTOM_SLIDE_RELEASED &&
        event->id != EVENT_TOP_CONTINUOUS_TAP && event->id != EVENT_BOTTOM_CONTINUOUS_TAP &&
        event->id != EVENT_TOP_SHORT_TAP && event->id != EVENT_BOTTOM_SHORT_TAP &&
        event->id != EVENT_TOP_LONG_TAP && event->id != EVENT_BOTTOM_LONG_TAP &&
        event->id != EVENT_TOP_SLIDE && event->id != EVENT_BOTTOM_SLIDE) {
        return;
    }
    confirm_data_t* data = (confirm_data_t*)component->data;
    gestures_slider_data_t* slider_data = (gestures_slider_data_t*)event->data;

    switch (event->id) {
    case EVENT_TOP_SLIDE_RELEASED:
        data->active_top = false;
        break;
    case EVENT_TOP_CONTINUOUS_TAP:
        if (slider_data->position > SLIDER_POSITION_TWO_THIRD &&
            slider_data->position <= MAX_SLIDER_POS) {
            data->active_top = true;
        }
        break;
    case EVENT_TOP_SHORT_TAP:
        data->active_top = false;
        break;
    case EVENT_BOTTOM_SLIDE_RELEASED:
        data->active_bottom = false;
        break;
    case EVENT_BOTTOM_CONTINUOUS_TAP:
        if (slider_data->position > SLIDER_POSITION_TWO_THIRD &&
            slider_data->position <= MAX_SLIDER_POS) {
            data->active_bottom = true;
        }
        break;
    case EVENT_BOTTOM_SHORT_TAP:
        data->active_bottom = false;
        break;
    default:
        break;
    }
}

/********************************** Component Functions **********************************/

/**
 * Collects all component functions.
 */
static component_functions_t _component_functions = {
    .cleanup = ui_util_component_cleanup,
    .render = _render,
    .on_event = _on_event,
};

/********************************** Create Instance **********************************/

/**
 * Creates a confirm_gesture component on the top slider.
 * @param[in] parent The parent component.
 */
component_t* confirm_gesture_create(component_t* parent)
{
    confirm_data_t* data = malloc(sizeof(confirm_data_t));
    if (!data) {
        Abort("Error: malloc confirm_gesture data");
    }
    memset(data, 0, sizeof(confirm_data_t));
    data->active_top = false;
    data->active_bottom = false;
    data->confirmed = false;
    data->active_count = SCALE - 1;
    data->bottom_arrow_slidein = 0;

    component_t* confirm_gesture = malloc(sizeof(component_t));
    if (!confirm_gesture) {
        Abort("Error: malloc confirm_gesture");
    }
    memset(confirm_gesture, 0, sizeof(component_t));
    confirm_gesture->data = data;
    confirm_gesture->f = &_component_functions;
    confirm_gesture->parent = parent;

    ui_util_position_right_top(parent, confirm_gesture);

    return confirm_gesture;
}

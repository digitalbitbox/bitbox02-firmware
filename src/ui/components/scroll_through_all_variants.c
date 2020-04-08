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

#include "scroll_through_all_variants.h"
#include "../event.h"
#include "button.h"
#include "icon_button.h"
#include "label.h"
#include "left_arrow.h"
#include "right_arrow.h"

#include <hardfault.h>
#include <screen.h>
#include <touch/gestures.h>

#include <string.h>

/**
 * Scroll-through data.
 */
typedef struct {
    const char* const* words;
    component_t** labels;
    uint8_t length;
    uint8_t index;
    component_t* index_label;
    component_t* back_arrow;
    component_t* forward_arrow;
    bool show_index;
    int32_t diff_to_middle;
    void (*select_word_cb)(uint8_t, void*);
    void* select_word_cb_param;
    component_t* continue_on_last_button;
    void (*continue_on_last_cb)(void);
    void (*cancel_cb)(void*);
    void* cancel_cb_param;
} scroll_through_all_variants_data_t;

static const uint8_t part_width = 15;

static void _continue(component_t* component)
{
    scroll_through_all_variants_data_t* data =
        (scroll_through_all_variants_data_t*)component->parent->data;
    data->continue_on_last_cb();
}

static void _select(component_t* button)
{
    scroll_through_all_variants_data_t* data =
        (scroll_through_all_variants_data_t*)button->parent->data;
    data->select_word_cb(data->index, data->select_word_cb_param);
}

static void _cancel(component_t* component)
{
    scroll_through_all_variants_data_t* data =
        (scroll_through_all_variants_data_t*)component->parent->data;
    data->cancel_cb(data->cancel_cb_param);
}

static void _display_index(component_t* scroll_through_all_variants)
{
    scroll_through_all_variants_data_t* data =
        (scroll_through_all_variants_data_t*)scroll_through_all_variants->data;
    char index_str[4];
    snprintf(index_str, sizeof(index_str), "%02u", (data->index + 1U));
    label_update(data->index_label, index_str);
}

static void _update_positions(component_t* scroll_through_all_variants, int32_t velocity)
{
    scroll_through_all_variants_data_t* data =
        (scroll_through_all_variants_data_t*)scroll_through_all_variants->data;
    // init to very high number (2^31 - 1).
    int32_t min_diff_to_middle = 2147483647;
    for (int i = 0; i < data->length; i++) {
        ui_util_position_left_center_offset(
            scroll_through_all_variants,
            data->labels[i],
            data->labels[i]->position.left + velocity);

        int32_t diff_to_middle = data->labels[i]->position.left +
                                 data->labels[i]->dimension.width / 2 - SCREEN_WIDTH / 2;
        if (abs(diff_to_middle) < min_diff_to_middle) {
            min_diff_to_middle = abs(diff_to_middle);
            data->index = i;
            data->diff_to_middle = diff_to_middle;
        }
    }

    /* When no title is provided, show the index instead. */
    if (data->show_index) {
        _display_index(scroll_through_all_variants);
    }

    if (data->index == data->length - 1 && data->continue_on_last_cb != NULL &&
        data->continue_on_last_button == NULL) {
        data->continue_on_last_button = button_create(
            "Continue", top_slider, SCREEN_WIDTH - 23, _continue, scroll_through_all_variants);
        ui_util_add_sub_component(scroll_through_all_variants, data->continue_on_last_button);
    }
}

static void _init_positions(component_t* scroll_through_all_variants)
{
    scroll_through_all_variants_data_t* data =
        (scroll_through_all_variants_data_t*)scroll_through_all_variants->data;
    int32_t middle_pos = SCREEN_WIDTH / 2;
    for (int i = 0; i < data->length; i++) {
        int32_t current_pos = middle_pos - data->labels[i]->dimension.width / 2;
        ui_util_position_left_center_offset(
            scroll_through_all_variants, data->labels[i], current_pos);
        if (i + 1 < data->length) {
            middle_pos = middle_pos + SCREEN_WIDTH / 2 - part_width +
                         data->labels[i + 1]->dimension.width / 2;
        }
    }
}

static void _update_arrow_visibility(scroll_through_all_variants_data_t* data, uint8_t new_index)
{
    if (new_index == 0) {
        data->back_arrow->disabled = true;
    } else {
        data->back_arrow->disabled = false;
    }

    if (new_index == data->length - 1) {
        data->forward_arrow->disabled = true;
    } else {
        data->forward_arrow->disabled = false;
    }
}

static void _back(component_t* component)
{
    scroll_through_all_variants_data_t* data = (scroll_through_all_variants_data_t*)component->data;
    uint8_t new_index = data->index > 0 ? data->index - 1 : data->index;
    int32_t diff_to_middle = (data->labels[new_index]->position.left +
                              data->labels[new_index]->dimension.width / 2 - SCREEN_WIDTH / 2) *
                             -1;
    _update_arrow_visibility(data, new_index);
    _update_positions(component, diff_to_middle);
}

static void _forward(component_t* component)
{
    scroll_through_all_variants_data_t* data = (scroll_through_all_variants_data_t*)component->data;
    uint8_t new_index = data->index < (data->length - 1) ? data->index + 1 : data->index;
    int32_t diff_to_middle = (data->labels[new_index]->position.left +
                              data->labels[new_index]->dimension.width / 2 - SCREEN_WIDTH / 2) *
                             -1;
    _update_arrow_visibility(data, new_index);
    _update_positions(component, diff_to_middle);
}

/**
 * Render the UI component.
 */
static void _render(component_t* component)
{
    scroll_through_all_variants_data_t* data = (scroll_through_all_variants_data_t*)component->data;

    UG_S16 x1 = data->labels[data->index]->position.left - 1;
    UG_S16 x2 = x1 + data->labels[data->index]->dimension.width - 1;
    UG_S16 y =
        data->labels[data->index]->position.top + data->labels[data->index]->dimension.height + 2;
    UG_DrawLine(x1, y, x2, y, screen_front_color);

    ui_util_component_render_subcomponents(component);
}

static void _on_event(const event_t* event, component_t* component)
{
    // gestures_slider_data_t* slider_data = (gestures_slider_data_t*)event->data;
    switch (event->id) {
    case EVENT_BACKWARD:
        _back(component);
        break;
    case EVENT_FORWARD:
        _forward(component);
        break;
    default:
        break;
    }
}

/**
 * Clean-up the component.
 */
static void _cleanup(component_t* component)
{
    scroll_through_all_variants_data_t* data = (scroll_through_all_variants_data_t*)component->data;
    free(data->labels);
    // component and component data are cleaned up in ui_util_component_cleanup.
    ui_util_component_cleanup(component);
}

/********************************** Component Functions **********************************/

/**
 * Collects all component functions.
 */
static const component_functions_t _component_functions = {
    .cleanup = _cleanup,
    .render = _render,
    .on_event = _on_event,
};

/********************************** Create Instance **********************************/

/**
 * Creates a scroll through list that renders the current word in the center and parts of the words
 * before and after on the left and right.
 * @param[in] words The words that are displayed on the screen, and through which you can slide
 * through.
 * @param[in] callback If specified, the callback will be called if the user selects a word. The
 * parameter is the index of the selected word.
 * @param[in] length The word list length.
 * @param[in] show_index If true, displays the index of the current word (starting at 1).
 * @param[in] parent The parent component.
 */
component_t* scroll_through_all_variants_create(
    const char* const* words,
    void (*select_word_cb)(uint8_t, void*),
    void* select_word_cb_param,
    const uint8_t length,
    const char* title,
    void (*continue_on_last_cb)(void),
    void (*cancel_cb)(void*),
    void* cancel_cb_param,
    component_t* parent)
{
    component_t** labels = malloc(sizeof(component_t*) * length);
    if (!labels) {
        Abort("Error: malloc scroll through labels");
    }
    scroll_through_all_variants_data_t* data = malloc(sizeof(scroll_through_all_variants_data_t));
    if (!data) {
        Abort("Error: malloc scroll through data");
    }
    memset(data, 0, sizeof(scroll_through_all_variants_data_t));

    component_t* scroll_through_all_variants = malloc(sizeof(component_t));
    if (!scroll_through_all_variants) {
        Abort("Error: malloc scroll through");
    }
    memset(scroll_through_all_variants, 0, sizeof(component_t));

    scroll_through_all_variants->parent = parent;
    scroll_through_all_variants->f = &_component_functions;

    scroll_through_all_variants->dimension.width = SCREEN_WIDTH;
    scroll_through_all_variants->dimension.height = SCREEN_HEIGHT;

    data->labels = labels;
    data->words = words;
    data->select_word_cb = select_word_cb;
    data->select_word_cb_param = select_word_cb_param;
    data->length = length;
    data->index = 0;
    data->show_index = !title;
    data->continue_on_last_cb = continue_on_last_cb;
    data->continue_on_last_button = NULL;
    data->cancel_cb = cancel_cb;
    data->cancel_cb_param = cancel_cb_param;
    scroll_through_all_variants->data = data;

    for (int i = 0; i < length; i++) {
        component_t* label = label_create(words[i], NULL, CENTER, scroll_through_all_variants);
        ui_util_add_sub_component(scroll_through_all_variants, label);
        labels[i] = label;
    }
    data->index_label = label_create("", NULL, CENTER_TOP, scroll_through_all_variants);
    ui_util_add_sub_component(scroll_through_all_variants, data->index_label);
    if (data->show_index) {
        _display_index(scroll_through_all_variants);
    } else {
        label_update(data->index_label, title);
    }

    if (select_word_cb != NULL) {
        ui_util_add_sub_component(
            scroll_through_all_variants,
            button_create(
                "Select", bottom_slider, SCREEN_WIDTH / 2, _select, scroll_through_all_variants));
    }

    if (cancel_cb != NULL) {
        ui_util_add_sub_component(
            scroll_through_all_variants,
            icon_button_create(top_slider, ICON_BUTTON_CROSS, _cancel));
    }

    data->back_arrow = left_arrow_create(bottom_slider, scroll_through_all_variants);
    ui_util_add_sub_component(scroll_through_all_variants, data->back_arrow);

    data->forward_arrow = right_arrow_create(bottom_slider, scroll_through_all_variants);
    ui_util_add_sub_component(scroll_through_all_variants, data->forward_arrow);

    _update_arrow_visibility(data, 0);
    _init_positions(scroll_through_all_variants);
    return scroll_through_all_variants;
}

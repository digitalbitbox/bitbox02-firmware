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

#include <stdlib.h>
#include <string.h>

#include "bitboxbase_pins.h"
#include "common_main.h"
#include "driver_init.h"
#include "firmware_main_loop.h"
#include "hardfault.h"
#include "leds.h"
#include "platform_init.h"
#include "qtouch.h"
#include "screen.h"
#include "touch/gestures.h"
#include "touch/gestures_bitboxbase.h"
#include "ui/component.h"
#include "ui/components/label.h"
#include "ui/oled/oled.h"
#include "ui/screen_process.h"
#include "ui/screen_stack.h"
#include "ui/ui_util.h"
#include "util.h"
#include "workflow/workflow.h"

static void _on_event(const event_t* event, component_t* component);
static void _render(component_t* component);

struct bar_data_t {
    uint32_t progress_left;
    uint32_t progress_right;
    uint32_t timeout;
    uint8_t color_left;
    uint8_t color_right;
};

static component_functions_t _component_functions = {
    .cleanup = ui_util_component_cleanup,
    .render = _render,
    .on_event = _on_event,
};

void _on_event(const event_t* event, component_t* component)
{
    struct bar_data_t* data = component->data;
    if (event->id == EVENT_BUTTON_SHORT_TAP || event->id == EVENT_BUTTON_LONG_TAP ||
        event->id == EVENT_BUTTON_CONTINUOUS_TAP) {
        uint32_t* progress = NULL;
        uint8_t* led_color = NULL;
        component_t* label = NULL;
        switch (gestures_button_which(event)) {
        case BITBOXBASE_BUTTON_LEFT:
            progress = &data->progress_left;
            led_color = &data->color_left;
            label = component->sub_components.sub_components[0];
            if (event->id == EVENT_BUTTON_SHORT_TAP) {
                leds_turn_big_led(0, *led_color + 2);
            }
            break;
        case BITBOXBASE_BUTTON_RIGHT:
            progress = &data->progress_right;
            led_color = &data->color_right;
            label = component->sub_components.sub_components[1];
            if (event->id == EVENT_BUTTON_SHORT_TAP) {
                leds_turn_big_led(1, *led_color + 2);
            }
            break;
        default:; // nothing
        }
        char buf[10] = {0};
        switch (event->id) {
        case EVENT_BUTTON_SHORT_TAP:
            *progress = 0;
            snprintf(buf, sizeof(buf), "short tap");
            *led_color += 1;
            *led_color = *led_color % 2;
            break;
        case EVENT_BUTTON_LONG_TAP:
            *progress = 0;
            snprintf(buf, sizeof(buf), "long tap");
            break;
        case EVENT_BUTTON_CONTINUOUS_TAP:
            *progress = *progress < 100000 ? *progress + 1 : 100000;
            snprintf(buf, sizeof(buf), "%lu", *progress);
            break;
        default:;
        }
        label_update(label, buf);
        data->timeout = 0;
        return;
    }
}

void _render(component_t* component)
{
    struct bar_data_t* data = component->data;
    ui_util_component_render_subcomponents(component);
    if (data->timeout > 100) {
        label_update(component->sub_components.sub_components[0], "");
        label_update(component->sub_components.sub_components[1], "");
        leds_turn_big_led(0, LED_COLOR_RED);
        leds_turn_big_led(1, LED_COLOR_RED);
    }
    data->timeout++;
}

static component_t* _demo_create(void)
{
    component_t* bar = malloc(sizeof(component_t) + sizeof(struct bar_data_t));
    memset(bar, 0, sizeof(component_t) + sizeof(struct bar_data_t));
    if (!bar) {
        Abort("Error: Failed to allocate");
    }
    bar->data = bar + sizeof(component_t);
    bar->f = &_component_functions;
    bar->dimension.width = SCREEN_WIDTH;
    bar->dimension.height = SCREEN_HEIGHT;
    ui_util_add_sub_component(bar, label_create("0", NULL, LEFT_TOP, bar));
    ui_util_add_sub_component(bar, label_create("0           ", NULL, RIGHT_TOP, bar));
    ui_util_add_sub_component(
        bar, label_create_scrollable("abcabcabcabcabcabcabca", NULL, CENTER, bar));
    for (int i = 0; i < 5; ++i) {
        leds_turn_small_led(i, true);
    }
    return bar;
}

static component_t* demo;

static void bitboxbase_touch_demo(void)
{
    demo = _demo_create();
    ui_screen_stack_push(demo);
}

uint32_t __stack_chk_guard = 0;

/* This is the main function to the BitBox Base HSM */
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
    traceln("%s", "Device initialized");
    bitboxbase_touch_demo();
    for (;;) {
        screen_process();
    }
    return 0;
}

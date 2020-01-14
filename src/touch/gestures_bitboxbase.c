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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef TESTING
#include "qtouch.h"
#include <driver_init.h>
#else
#include "mock_qtouch.h"
#endif

#include "gestures.h"
#if PLATFORM_BITBOXBASE == 1
#include "gestures_bitboxbase.h"
#endif

#include "ui/event.h"
#include "ui/event_handler.h"
#include "util.h"
#include <platform_config.h>
#include <ui/component.h>

#define MAX_REGISTRATIONS 7
#define MAX_HISTORY 30

/** The minimum amount of sliding difference required, so that the gesture is detected as slide. */
static const uint8_t SLIDE_DETECTION_DIFF = MAX_SLIDER_POS * 0.04; // Percent of slider range
/**
 * The maximum amount of sliding that the user's finger is allowed to move
 * for its gesture to be still considered a tap.
 */
static const uint8_t TAP_SLIDE_TOLERANCE = MAX_SLIDER_POS * 0.1; // Percent of slider range

extern volatile uint8_t measurement_done_touch;

/********************************** STATE **********************************/

#if PLATFORM_BITBOX02 == 1
static const uint16_t LONG_TOUCH = 500;
#elif PLATFORM_BITBOXBASE == 1
static const uint16_t LONG_TOUCH = 1000;
#endif

enum slider_status_t { INACTIVE, ACTIVE, RELEASED };

enum gesture_type_t { NONE, SLIDE, TAP };

// Stores whether or not sliders were released since a new screen reset the state.
bool _released_since_new_screen = false;

/**
 * The state of the gesture detection while the slider is not released.
 */
typedef struct {
    // Incremented by 1 for every update.
    uint32_t duration;
    // The start of the position.
    uint16_t position_start;
    // The last measured position.
    uint16_t position_current;
    /*
     * The maximum distance the finger has travelled
     * since starting the gesture.
     */
    uint16_t max_slide_travel;
    int32_t velocity_sum;
    uint16_t velocity_index;
    // Stores the velocities.
    int16_t velocity_values[MAX_HISTORY];
    // The gesture type (tap, slide). FUTURE: remove this?
    enum gesture_type_t gesture_type;
    // The status of the slider.
    enum slider_status_t slider_status;
} gestures_detection_state_t;

/**
 * The current state. A gesture is detected over multiple function calls to
 * gestures_measure_and_emit(). Thus, we need to store the information continuously in a file-local
 * state.
 */
static gestures_detection_state_t _state[TOUCH_NUM_SLIDERS] = {0};

#if PLATFORM_BITBOXBASE == 1
struct button_detection_state_t {
    enum bitboxbase_button_id_t button_id;
    uint32_t duration;
    enum slider_status_t button_status;
};

struct button_detection_state_t _bitboxbase_button_state[] = {
    {BITBOXBASE_BUTTON_LEFT, 0, INACTIVE},
    {BITBOXBASE_BUTTON_RIGHT, 0, INACTIVE},
};

enum bitboxbase_button_id_t gestures_button_which(const event_t* event)
{
    return ((const struct button_detection_state_t*)event->data)->button_id;
}
#endif

/********************************** STATE UPDATE **********************************/

/**
 * Updates the state of a slider.
 */
static void _slider_state_update(gestures_detection_state_t* state, uint16_t position)
{
    if (state->duration == 0) {
        state->position_start = position;
        state->position_current = position;
        state->max_slide_travel = 0;
        state->gesture_type = TAP;
    }
    int16_t velocity_current = position - state->position_current;
    state->position_current = position;
    int16_t velocity_removed = state->velocity_values[state->velocity_index];
    state->velocity_sum = state->velocity_sum - velocity_removed + velocity_current;
    state->velocity_values[state->velocity_index] = velocity_current;
    state->velocity_index = (state->velocity_index + 1) % MAX_HISTORY;
    uint16_t distance_from_start = abs((int)position - (int)state->position_start);
    state->max_slide_travel = MAX(distance_from_start, state->max_slide_travel);

    state->slider_status = ACTIVE;
    if (abs(state->position_current - state->position_start) > SLIDE_DETECTION_DIFF) {
        state->gesture_type = SLIDE;
    }
    state->duration++;
}

/**
 * Reads the status of the touch sliders and updates the state.
 */
static void _slider_state_read_and_update(const uint8_t location)
{
    if (qtouch_is_scroller_active(location)) {
        uint16_t current_pos = qtouch_get_scroller_position(location);
        if (location == bottom_slider) {
            current_pos = MAX_SLIDER_POS - current_pos;
        }
        _slider_state_update(&_state[location], current_pos);
    } else if (_state[location].duration > 0 && _state[location].slider_status != RELEASED) {
        _state[location].slider_status = RELEASED;
    } else {
        _state[location].slider_status = INACTIVE;
        _state[location].duration = 0;
    }
}

/**
 * Resets the state.
 */
static void _reset_state(void)
{
    memset(_state, 0, sizeof(_state));
}

/**
 * Prepares the gestures data to be sent with an emitted event
 */
static void _collect_gestures_data(
    gestures_detection_state_t* state,
    gestures_slider_data_t* slider_data)
{
    slider_data->position = state->position_current;
    slider_data->diff = state->position_current - state->position_start;
    slider_data->velocity = state->velocity_sum;
}

/********************************** GESTURE DETECTION **********************************/

static bool _is_continuous_tap(uint8_t location)
{
    return _state[location].max_slide_travel < TAP_SLIDE_TOLERANCE &&
           _state[location].slider_status == ACTIVE;
}

static bool _is_tap_release(uint8_t location)
{
    return _state[location].max_slide_travel < TAP_SLIDE_TOLERANCE &&
           _state[location].slider_status == RELEASED;
}

static bool _is_long_tap_release(uint8_t location)
{
    return _is_tap_release(location) && _state[location].duration > LONG_TOUCH;
}

static bool _is_continuous_slide(uint8_t location)
{
    return _state[location].gesture_type == SLIDE && _state[location].slider_status == ACTIVE;
}

static bool _is_slide_released(uint8_t location)
{
    return _state[location].gesture_type == SLIDE && _state[location].slider_status == RELEASED;
}

/********************************** EVENT HANDLER **********************************/

static void _gesture_emit_event(uint8_t id, slider_location_t location)
{
    // If a slider is being touched on a new screen,
    // wait until released before emitting events.
    if (!_released_since_new_screen) {
        return;
    }
    gestures_slider_data_t slider_data;
    _collect_gestures_data(&_state[location], &slider_data);
    event_t event = {.data = &slider_data, .id = id};
    emit_event(&event);
}

static void _emit_continuous_slide_event(void)
{
    if (_is_continuous_slide(top_slider)) {
        _gesture_emit_event(EVENT_TOP_SLIDE, top_slider);
    }
    if (_is_continuous_slide(bottom_slider)) {
        _gesture_emit_event(EVENT_BOTTOM_SLIDE, bottom_slider);
    }
}

static void _emit_slide_release_event(void)
{
    if (_is_slide_released(top_slider)) {
        _gesture_emit_event(EVENT_TOP_SLIDE_RELEASED, top_slider);
    }
    if (_is_slide_released(bottom_slider)) {
        _gesture_emit_event(EVENT_BOTTOM_SLIDE_RELEASED, bottom_slider);
    }
}

static void _emit_long_tap_event(void)
{
    if (_is_long_tap_release(top_slider)) {
        _gesture_emit_event(EVENT_TOP_LONG_TAP, top_slider);
    }
    if (_is_long_tap_release(bottom_slider)) {
        _gesture_emit_event(EVENT_BOTTOM_LONG_TAP, bottom_slider);
    }
}

static void _emit_short_tap_event(void)
{
    if (_is_tap_release(top_slider)) {
        _gesture_emit_event(EVENT_TOP_SHORT_TAP, top_slider);
    }
    if (_is_tap_release(bottom_slider)) {
        _gesture_emit_event(EVENT_BOTTOM_SHORT_TAP, bottom_slider);
    }
}

static void _emit_continuous_tap_event(void)
{
    if (_is_continuous_tap(top_slider)) {
        _gesture_emit_event(EVENT_TOP_CONTINUOUS_TAP, top_slider);
    }
    if (_is_continuous_tap(bottom_slider)) {
        _gesture_emit_event(EVENT_BOTTOM_CONTINUOUS_TAP, bottom_slider);
    }
}

#if PLATFORM_BITBOXBASE == 1
static void _emit_button_short_tap(size_t idx)
{
    event_t event = {.data = &_bitboxbase_button_state[idx], .id = EVENT_BUTTON_SHORT_TAP};
    emit_event(&event);
}

static void _emit_button_long_tap(size_t idx)
{
    event_t event = {.data = &_bitboxbase_button_state[idx], .id = EVENT_BUTTON_LONG_TAP};
    emit_event(&event);
}

static void _emit_button_continouos_tap(size_t idx)
{
    event_t event = {.data = &_bitboxbase_button_state[idx], .id = EVENT_BUTTON_CONTINUOUS_TAP};
    emit_event(&event);
}

static void _button_state_update_and_emit(size_t idx)
{
    bool active = qtouch_get_button_state(idx);
    struct button_detection_state_t* current = &_bitboxbase_button_state[idx];
    switch (current->button_status) {
    case INACTIVE:
        if (active) {
            current->button_status = ACTIVE;
        }
        break;
    case ACTIVE:
        current->duration++;
        if (current->duration > LONG_TOUCH) {
            _emit_button_continouos_tap(idx);
        }
        if (!active) {
            current->button_status = RELEASED;
        }
        break;
    case RELEASED:
        if (current->duration > LONG_TOUCH) {
            _emit_button_long_tap(idx);
        } else {
            _emit_button_short_tap(idx);
        }
        current->button_status = INACTIVE;
        current->duration = 0;
        break;
    default:;
        // Do nothing
    }
}
#endif

/********************************** MEASURE, DETECT and CALLBACK **********************************/

/**
 * Measures the slider usage and calls registered callbacks to inform a client
 * about a detected gesture.
 */
static void _measure_and_emit(void)
{
    qtouch_process(); // Non blocking
    if (measurement_done_touch != 1) {
        return;
    }

    bool gesture_detected = false;

    for (int location = 0; location < TOUCH_NUM_SLIDERS; location++) {
        _slider_state_read_and_update(location);
        gesture_detected = gesture_detected || _state[location].gesture_type != NONE;
    }

#if PLATFORM_BITBOXBASE == 1
    for (size_t button = 0; button < DEF_NUM_BUTTONS; button++) {
        _button_state_update_and_emit(button);
    }
#endif

    if (gesture_detected) {
        _emit_continuous_slide_event();
        _emit_slide_release_event();
        _emit_long_tap_event();
        _emit_short_tap_event();
        _emit_continuous_tap_event();
    }

    bool both_sliders_released_or_inactive = true;
    for (int location = 0; location < TOUCH_NUM_SLIDERS; location++) {
        if (_state[location].slider_status != RELEASED &&
            _state[location].slider_status != INACTIVE) {
            both_sliders_released_or_inactive = false;
        }
    }
    if (both_sliders_released_or_inactive) {
        _reset_state();
        _released_since_new_screen = true;
    }
}

void gestures_detect(bool reset, bool emit_without_release)
{
    if (reset) {
        _reset_state();
        _released_since_new_screen = emit_without_release;
    }
    _measure_and_emit();
}

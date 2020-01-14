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

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <cmocka.h>

#include "mock_gestures.h"
#include "mock_qtouch.h"

#include <touch/gestures_impl.h>
#include <util.h>

#define MEASUREMENT_PERIOD 125

static bool gestures_history_reset = false;

/********************************** POSITIONING **********************************/

/**
 * Converts the screen position into the slider position.
 */
// TODO: clean up eventually. This is copied form gestures.c
static uint16_t _screen_to_slider_position(uint8_t screen_position)
{
    uint16_t slider_position = ((float)screen_position / (float)SCREEN_WIDTH) * MAX_SLIDER_POS;
    return slider_position;
}

/**
 * Mocks the sensors for sliding and tap or hold detection.
 * The flag 'expect_slide_detection' indicates whether the caller expects that the mocked gesture
 * detection returns after detecting a slide gesture. This flag needs to be set to false if the
 * caller requires mocking of the sensor node signal and sensor node reference driver functions.
 * @param[in] pos The position at which the touch slider was touched (between 0 and 255).
 */
void mock_gestures_touch(slider_location_t location, uint8_t screen_position)
{
    for (int j = 0; j < MEASUREMENT_PERIOD; j++) {
        for (int i = 0; i < TOUCH_NUM_SLIDERS; i++) {
            if (i == location) {
                will_return(qtouch_is_scroller_active, 129);
                uint8_t measured_position = _screen_to_slider_position(screen_position);
                if (location == bottom_slider) {
                    measured_position = MAX_SLIDER_POS - measured_position;
                }
                will_return(qtouch_get_scroller_position, measured_position);
            } else {
                will_return(qtouch_is_scroller_active, 0);
            }
        }
        gestures_detect(gestures_history_reset, true);
        gestures_history_reset = false;
    }
}

/**
 * Mocks the sensors for slider release detection.
 */
void mock_gestures_touch_release(void)
{
    for (int i = 0; i < TOUCH_NUM_SLIDERS; i++) {
        will_return(qtouch_is_scroller_active, 0);
    }
    gestures_detect(gestures_history_reset, true);
    gestures_history_reset = false;
}

/**
 * Initializes the touch detection by resetting the detection history.
 */
void mock_gestures_touch_init(void)
{
    gestures_history_reset = true;
}

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

#ifndef _MOTION_H_
#define _MOTION_H_

#include <stdbool.h>

#include <screen.h>
#include <ui/component.h>

#ifndef TESTING
#include <qtouch.h>
#define MAX_SLIDER_POS (DEF_SCROLLER_RESOLUTION - 1)
#else
#define MAX_SLIDER_POS (255)
#endif

#define SLIDER_POSITION_ONE_THIRD (MAX_SLIDER_POS / 3)
#define SLIDER_POSITION_TWO_THIRD (MAX_SLIDER_POS / 3 * 2)

typedef struct {
    int16_t diff;
    uint16_t position;
    int32_t velocity;
} gestures_slider_data_t;

/**
 * Detects a gestures and calls the respective callback.
 * @param[in] reset The flag indicates whether the gesture history should be
 * reset. This is the case, for example, if the screen component changes.
 * @param[in] emit_without_release The flag indicates if touch sensors must be
 * released before touch events can be emitted. This parameter is only used
 * when `reset` is `true`.
 */
void gestures_detect(bool reset, bool emit_without_release);

#endif

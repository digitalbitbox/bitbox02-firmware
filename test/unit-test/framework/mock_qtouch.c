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
#include <stddef.h>
#include <cmocka.h>

#include "mock_qtouch.h"

volatile bool measurement_done_touch = true;

uint8_t qtouch_is_scroller_active(uint16_t sensor_node)
{
    return (uint8_t)mock();
}

uint16_t qtouch_get_scroller_position(uint16_t sensor_node)
{
    return (uint16_t)mock();
}

void qtouch_process(void) {}

void qtouch_force_calibrate(void) {}

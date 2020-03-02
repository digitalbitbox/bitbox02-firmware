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

#ifndef _SCREEN_H_
#define _SCREEN_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <ui/ugui/ugui.h>

// TODO: allow updating
extern UG_COLOR screen_front_color;
extern UG_COLOR screen_back_color;

typedef uint8_t slider_location_t;

extern slider_location_t top_slider;
extern slider_location_t bottom_slider;

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

void screen_init(void);
void screen_print_debug(const char* message, int duration);
void screen_sprintf_debug(int duration, const char* fmt, ...) __attribute__((format(printf, 2, 0)));
void screen_print_debug_hex(const uint8_t* bytes, size_t len, int duration);

void screen_splash(void);

void screen_rotate(void);

bool screen_is_upside_down(void);

#endif

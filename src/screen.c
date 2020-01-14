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

#include "screen.h"

#include <hal_delay.h>
#include <platform/platform_config.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ui/components/ui_images.h>
#include <ui/fonts/arial_fonts.h>
#include <ui/oled/oled.h>
#include <ui/ugui/ugui.h>
#include <util.h>

static UG_GUI guioled; // Global GUI structure for OLED screen
#if PLATFORM_BITBOX02 == 1 || defined(TESTING)
static bool screen_upside_down = false;
#endif

UG_COLOR screen_front_color = C_WHITE;
UG_COLOR screen_back_color = C_BLACK;

slider_location_t top_slider = 1;
slider_location_t bottom_slider = 0;

// message truncated to 99 chars. somewhere between 99 and 120 we start to get hardfaults...
void screen_print_debug(const char* message, int duration)
{
    char print[100];
    snprintf(print, sizeof(print), "%s", message);
    UG_ClearBuffer();
    UG_FontSelect(&font_font_a_9X9);
    UG_PutString(0, 0, print, false);
    UG_SendBuffer();
    delay_ms(duration);
}

void screen_sprintf_debug(int duration, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    char print[100];
    // There is a bug in clang-tidy
    // See https://bugs.llvm.org/show_bug.cgi?id=41311
    vsnprintf(print, sizeof(print), fmt, args); // NOLINT
    va_end(args);
    screen_print_debug(print, duration);
}

void screen_print_debug_hex(const uint8_t* bytes, size_t len, int duration)
{
    if (len > 50) {
        len = 50;
    }
    char hex[2 * 50 + 1] = {0};
    util_uint8_to_hex(bytes, len, hex);
    screen_print_debug(hex, duration);
}

// Careful, this function is used in both the bootloader and the firmware.
void screen_splash(void)
{
    UG_ClearBuffer();

    int height = IMAGE_DEFAULT_ARROW_HEIGHT;
    int x = 0;
    int y = SCREEN_HEIGHT / 2 - height;
    image_arrow(x - height + 2, y, height, ARROW_RIGHT);
    image_arrow(SCREEN_WIDTH - x - 2, y, height, ARROW_LEFT);

    UG_SendBuffer();
    UG_ClearBuffer();
}

// TODO(nc): Remove these 2 functions from bitboxbase
void screen_rotate(void)
{
#if PLATFORM_BITBOX02 == 1 || defined(TESTING)
    screen_upside_down = !screen_upside_down;
    top_slider = 1 - top_slider;
    bottom_slider = 1 - bottom_slider;
    oled_mirror(screen_upside_down);
#endif
}

bool screen_is_upside_down(void)
{
#if PLATFORM_BITBOX02 == 1 || defined(TESTING)
    return screen_upside_down;
#else
    return false;
#endif
}

void screen_init(void)
{
    UG_Init(
        &guioled,
        (void (*)(UG_S16, UG_S16, UG_COLOR))oled_set_pixel,
        &font_font_a_9X9,
        SCREEN_WIDTH,
        SCREEN_HEIGHT);
}

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

#include "trinary_input_string.h"
#include "confirm_button.h"
#include "confirm_gesture.h"
#include "keyboard_switch.h"
#include "label.h"
#include "left_arrow.h"
#include "trinary_input_char.h"

#include <hardfault.h>
#include <screen.h>
#include <touch/gestures.h>
#include <ui/event.h>
#include <ui/event_handler.h>
#include <ui/fonts/password_11X12.h>
#include <ui/ugui/ugui.h>
#include <ui/ui_util.h>
#include <util.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define EMPTY_CHAR '_'
#define MASK_CHAR_WIDTH 6
#define BLINK_RATE 200

#define STRING_POS_X_START 5
#define STRING_POS_Y 29

// After entering too many chars and exceeding the screen width, the right end of the last char will
// end up be at this position.
#define SCROLL_LEFT_PAD 35
// Slide to left after exceeding this position
#define SCROLL_RIGHT_LIMIT (SCREEN_WIDTH - 10)

static char _alphabet_uppercase[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static char _alphabet_lowercase[] = "abcdefghijklmnopqrstuvwxyz";
static char _digits[] = "0123456789";
// ` and ~ are missing here as they don't legible on the device with arial 9x9. Can add them back
// after tuning the font.
static char _special_chars[] = " !\"#$%&'()*+,-./:;<=>?^[\\]@_{|}";

static const UG_FONT* _font = &font_password_11X12;

typedef struct {
    // Can be NULL.
    const char* const* wordlist;
    size_t wordlist_size;
    // Only applies if wordlist != NULL: determines if a word from the wordlist was entered.
    bool can_confirm;
    // Mask user input with '*'?
    bool hide;
    // use hold gesture vs. simple tap to confirm.
    bool longtouch;
    void (*confirm_cb)(const char* string);
    void (*cancel_cb)(void);

    // Internals follow.

    // Start rendering string here
    UG_S16 start_x;
    // Slide to target.
    UG_S16 target_x;

    // Current state of input.
    size_t string_index;
    char string[INPUT_STRING_MAX_SIZE];

    // Show last character instead of asterisk. Applies only if `hide` is true.
    bool show_last_character;

    component_t* title_component;
    component_t* trinary_char_component;
    component_t* confirm_component;
    component_t* left_arrow_component;
    component_t* keyboard_switch_component;
} data_t;

static void _cleanup(component_t* component)
{
    data_t* data = (data_t*)component->data;
    util_zero(data, sizeof(data_t));
    ui_util_component_cleanup(component);
}

/**
 * Computes width of inputted string, including trailing underscore.  If hidden, the last letter is
 * treated as masked as well, so that different widths of letters do not change the total width for
 * the purpose of scrolling (since going backwards would be a different width than going forward,
 * with the last letter never being shown when going backwards).
 *
 */
static UG_S16 _constant_string_width(const component_t* component)
{
    data_t* data = (data_t*)component->data;
    UG_S16 width = 0;
    for (size_t i = 0; i <= data->string_index; i++) {
        if (i == data->string_index) {
            char chr = EMPTY_CHAR;
            width += _font->widths[chr - _font->start_char];
        } else if (!data->hide) {
            char chr = data->string[i];
            width += _font->widths[chr - _font->start_char];
        } else {
            width += MASK_CHAR_WIDTH;
        }

        width += 1;
        if (data->hide) {
            width += 1;
        }
    }
    return width;
}

static void _render(component_t* component)
{
    static int frame_counter = 0;
    frame_counter++;
    bool blink = (frame_counter % BLINK_RATE) < (BLINK_RATE / 2);

    data_t* data = (data_t*)component->data;
    bool confirm_gesture_active =
        data->can_confirm && data->longtouch && confirm_gesture_is_active(data->confirm_component);
    bool show_title =
        data->string_index == 0 && !trinary_input_char_in_progress(data->trinary_char_component);

    UG_S16 string_x = data->start_x;

    if (frame_counter % 3 == 0 && data->target_x != data->start_x) {
        int fx = data->target_x > data->start_x ? 1 : -1;
        int offset = (data->target_x - data->start_x) / 5;
        if (offset == 0) offset = fx;
        data->start_x += offset;
    }

    UG_FontSelect(_font);
    for (size_t i = 0; i <= data->string_index; i++) {
        uint8_t string_y = STRING_POS_Y;

        if (i == data->string_index &&
            (confirm_gesture_active || show_title || blink ||
             trinary_input_char_alphabet_is_empty(data->trinary_char_component))) {
            // Don't show trailing char during confirm, to make it clear
            // that it is not part of the pw.
            // Also do not show it if there are not more chars to choose from.
            continue;
        }

        char chr;
        uint8_t width;
        if (i == data->string_index) {
            chr = EMPTY_CHAR;
            width = _font->widths[chr - _font->start_char];
        } else if ((data->show_last_character && i == data->string_index - 1) || !data->hide) {
            // Show character (or only last entered character in if input is hidden).
            chr = data->string[i];
            width = _font->widths[chr - _font->start_char];
        } else {
            // ad-hoc encoding of the masked char, which will be drawn as a filled circle below.
            chr = '\0';
            width = MASK_CHAR_WIDTH;
        }
        if (string_x >= 0) {
            if (chr == '\0') {
                UG_FillCircle(string_x + 3, string_y + 4, 2, screen_front_color);
            } else {
                UG_PutChar(chr, string_x, string_y, screen_front_color, screen_back_color, false);
            }
        }
        string_x += width + 1;
        if (data->hide) {
            // A bit more horizontal spacing if the input is masked.
            string_x += 1;
        }
    }

    // Draw '...' when the left part scrolled out of view.
    if (data->target_x < STRING_POS_X_START) {
        // HACK: blank out the chars rendered at this position first.
        UG_FillFrame(0, STRING_POS_Y, 11, STRING_POS_Y + _font->char_height, screen_back_color);
        UG_PutString(0, STRING_POS_Y, "...", false);
    }

    // Render sub-components
    if (data->can_confirm) {
        data->confirm_component->f->render(data->confirm_component);
    }
    if (!confirm_gesture_active) {
        data->left_arrow_component->f->render(data->left_arrow_component);
        if (data->keyboard_switch_component != NULL) {
            data->keyboard_switch_component->f->render(data->keyboard_switch_component);
        }
        data->trinary_char_component->f->render(data->trinary_char_component);
    }
    if (show_title) {
        data->title_component->f->render(data->title_component);
    }
}

static void _set_alphabet(component_t* trinary_input_string)
{
    data_t* data = (data_t*)trinary_input_string->data;
    component_t* trinary_char = data->trinary_char_component;
    if (data->wordlist != NULL) {
        // Restrict input charset based on the available words with.
        // E.g. if the user entered "act", and the wordlist contains "actor", "actress", "action",
        // the charset to select the next letter wil be "eio".
        // The wordlist is assumed to be sorted and only have 'a-z' characters.
        char charset[27] = {0};
        for (size_t word_idx = 0; word_idx < data->wordlist_size; word_idx++) {
            const char* word = data->wordlist[word_idx];
            bool is_prefix = strncmp(data->string, word, data->string_index) == 0;
            if (is_prefix) {
                if (strlen(word) > data->string_index) {
                    const char include = word[data->string_index];
                    if (strchr(charset, include) == NULL) {
                        charset[strlen(charset)] = include;
                    }
                }
            }
        }
        // Since wordlist is sorted, charset is sorted automatically.
        trinary_input_char_set_alphabet(trinary_char, charset, 1);
    } else {
        // Otherwise set the input charset based on the user selected keyboard mode.
        keyboard_mode_t keyboard_mode = keyboard_current_mode(data->keyboard_switch_component);
        switch (keyboard_mode) {
        case LOWER_CASE:
            trinary_input_char_set_alphabet(trinary_char, _alphabet_lowercase, 1);
            break;
        case UPPER_CASE:
            trinary_input_char_set_alphabet(trinary_char, _alphabet_uppercase, 1);
            break;
        case DIGITS:
            trinary_input_char_set_alphabet(trinary_char, _digits, 1);
            break;
        case SPECIAL_CHARS:
            trinary_input_char_set_alphabet(trinary_char, _special_chars, 2);
            break;
        default:
            break;
        }
    }
}

static void _set_can_confirm(component_t* trinary_input_string)
{
    data_t* data = (data_t*)trinary_input_string->data;
    if (data->wordlist == NULL) {
        data->can_confirm = true;
        return;
    }
    data->can_confirm = false;
    // Can only confirm if the entered word matches a word in the wordlist.
    for (size_t i = 0; i < data->wordlist_size; i++) {
        if (STREQ(data->wordlist[i], data->string)) {
            data->can_confirm = true;
            return;
        }
    }
}

static void _on_event(const event_t* event, component_t* component)
{
    data_t* data = (data_t*)component->data;

    if (event->id == EVENT_CONFIRM && data->can_confirm) {
        data->confirm_cb(data->string);
        return;
    }

    // Other gestures deactivated during confirming.
    if (data->longtouch && confirm_gesture_is_active(data->confirm_component)) {
        return;
    }

    switch (event->id) {
    case EVENT_TOGGLE_ALPHANUMERIC:
        _set_alphabet(component);
        break;
    case EVENT_BACKWARD:
        if (trinary_input_char_in_progress(data->trinary_char_component)) {
            _set_alphabet(component);
            break;
        }
        // Move cursor backward and display preceeding character
        if (data->string_index > 0) {
            data->string_index--;
            data->string[data->string_index] = '\0';
            data->show_last_character = false;
            UG_S16 string_width = _constant_string_width(component);
            if (data->target_x < STRING_POS_X_START &&
                data->target_x + string_width < SCROLL_LEFT_PAD) {
                data->target_x = SCROLL_RIGHT_LIMIT - string_width;
                // data->target_x += MIN(SCREEN_WIDTH - SCROLL_RIGHT_LIMIT, string_width);
            }
        } else if (data->cancel_cb != NULL) {
            data->cancel_cb();
        }
        _set_alphabet(component);
        _set_can_confirm(component);
        break;
    default:
        break;
    }
}

static void _letter_chosen(component_t* trinary_char, char chosen)
{
    component_t* trinary_input_string = trinary_char->parent;
    data_t* data = (data_t*)trinary_input_string->data;
    bool confirm_gesture_active =
        data->longtouch && confirm_gesture_is_active(data->confirm_component);
    if (confirm_gesture_active) {
        _set_alphabet(trinary_input_string);
        return;
    }
    data->string[data->string_index] = chosen;
    data->string_index++;
    data->string[data->string_index] = '\0';
    data->show_last_character = true;
    _set_alphabet(trinary_input_string);
    _set_can_confirm(trinary_input_string);
    UG_S16 string_width = _constant_string_width(trinary_input_string);
    if (data->target_x + string_width > SCROLL_RIGHT_LIMIT) {
        data->target_x = -string_width + SCROLL_LEFT_PAD;
    }

    if (data->string_index + 1 >= INPUT_STRING_MAX_SIZE) {
        event_t e;
        e.id = EVENT_CONFIRM;
        emit_event(&e);
    }
}

static const component_functions_t component_functions = {
    .cleanup = _cleanup,
    .render = _render,
    .on_event = _on_event,
};

/********************************** Create Instance **********************************/

static component_t* _create(
    const char* title,
    const char* const* wordlist,
    size_t wordlist_size,
    bool hide,
    bool special_chars,
    bool longtouch,
    void (*confirm_cb)(const char* input),
    void (*cancel_cb)(void))
{
    component_t* component = malloc(sizeof(component_t));
    if (!component) {
        Abort("Error: malloc trinary_input_string");
    }
    data_t* data = malloc(sizeof(data_t));
    if (!data) {
        Abort("Error: malloc trinary_input_string data");
    }
    memset(component, 0, sizeof(component_t));
    memset(data, 0, sizeof(data_t));

    data->confirm_cb = confirm_cb;
    data->cancel_cb = cancel_cb;
    data->wordlist = wordlist;
    data->wordlist_size = wordlist_size;
    data->hide = hide;
    data->longtouch = longtouch;

    data->target_x = STRING_POS_X_START;
    data->start_x = data->target_x;

    component->data = data;
    component->parent = NULL;
    component->f = &component_functions;
    component->dimension.width = SCREEN_WIDTH;
    component->dimension.height = SCREEN_HEIGHT;
    component->position.top = 0;
    component->position.left = 0;

    data->left_arrow_component = left_arrow_create(top_slider, component);
    ui_util_add_sub_component(component, data->left_arrow_component);

    data->confirm_component = confirm_button_create(longtouch, ICON_BUTTON_CHECK);
    ui_util_add_sub_component(component, data->confirm_component);

    if (wordlist == NULL) {
        data->keyboard_switch_component =
            keyboard_switch_create(top_slider, special_chars, component);
        ui_util_add_sub_component(component, data->keyboard_switch_component);
    }

    data->title_component = label_create(title, NULL, CENTER, component);
    ui_util_add_sub_component(component, data->title_component);

    data->trinary_char_component = trinary_input_char_create(_letter_chosen, component);
    ui_util_add_sub_component(component, data->trinary_char_component);
    _set_alphabet(component);
    _set_can_confirm(component);

    return component;
}

component_t* trinary_input_string_create_wordlist(
    const char* title,
    const char* const* wordlist,
    size_t wordlist_size,
    void (*confirm_cb)(const char* input),
    void (*cancel_cb)(void))
{
    if (wordlist == NULL) {
        Abort("trinary_input_string_\ncreate_wordlist");
    }
    return _create(title, wordlist, wordlist_size, false, false, false, confirm_cb, cancel_cb);
}

component_t* trinary_input_string_create_password(
    const char* title,
    bool special_chars,
    void (*confirm_cb)(const char* input),
    void (*cancel_cb)(void))
{
    return _create(title, NULL, 0, true, special_chars, true, confirm_cb, cancel_cb);
}

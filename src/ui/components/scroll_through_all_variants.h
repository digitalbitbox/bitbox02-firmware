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

#ifndef _SCROLL_THROUGH_ALL_VARIANTS_H_
#define _SCROLL_THROUGH_ALL_VARIANTS_H_

#include <ui/component.h>

/**
 * Creates a scroll through list that renders the current word in the center and parts of the words
 * before and after on the left and right.
 * @param[in] words The words that are displayed on the screen, and through which you can slide
 * through.
 * @param[in] select_word_cb If specified, the callback will be called if the user selects a word.
 * The parameter is the index of the selected word. Should not be used with show_index.
 * @param[in] length The word list length.
 * @param[in] title Title for the window.
 *                  If NULL, displays the index of the current word instead (starting at 1).
 *                  For no title, set this to "".
 * @param[in] continue_on_last_cb If set, a checkmark appears when reaching the last word, calling
 * this callback.
 * @param[in] cancel_cb Called when the cancel button is pressed.
 * @param[in] parent The parent component.
 */
component_t* scroll_through_all_variants_create(
    const char* const* words,
    void (*select_word_cb)(uint8_t, void*),
    void* select_word_cb_param,
    uint8_t length,
    const char* title,
    void (*continue_on_last_cb)(void),
    void (*cancel_cb)(void*),
    void* cancel_cb_param,
    component_t* parent);

#endif

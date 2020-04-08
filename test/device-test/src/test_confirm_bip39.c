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

#include <string.h>
#ifndef TESTING
#include "driver_init.h"
#include "qtouch.h"
#endif
#include <ui/screen_stack.h>
#include <wally_bip39.h>

#include <firmware_main_loop.h>
#include <ui/components/confirm_mnemonic.h>

#include "hardfault.h"
#include "keystore.h"
#include "random.h"
#include "screen.h"
#include "sd.h"
#include "util.h"

#include "securechip/securechip.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

#define LEN_WORDLIST_EN 2048

uint32_t __stack_chk_guard = 0;

static bool _mock_get_bip_39_mnemonic(char** mnemonic)
{
    const char* wordlist = "flight donkey evolve skirt";
    // const char* wordlist = "flight donkey evolve skirt inspire balcony accident aisle walk vivid
    // weasel region sadness immense index champion almost avocado castle chaos defense crystal
    // device emotion";
    *mnemonic = strdup(wordlist);
    return true;
}

static uint8_t _current_correct_idx;

static void _confirm_mnemonic(uint8_t index, void* param)
{
    (void)param;
    if (index == 5) {
        screen_print_debug("back to seed phrase", 1000);
    } else if (index == _current_correct_idx) {
        screen_print_debug("correct", 1000);
    } else {
        screen_print_debug("incorrect", 1000);
    }
}

static bool _is_in_list(uint8_t number, const uint8_t list[], uint8_t length)
{
    for (int i = 0; i < length; i++) {
        if (number == list[i]) {
            return true;
        }
    }
    return false;
}

static uint8_t _create_random_unique_words(const char** wordlist, uint8_t length, const char* word)
{
    uint8_t random_numbers[length - 1];
    uint8_t current_length = 0;
    uint8_t i = 0;
    uint8_t index_word = random_byte_mcu() % length;
    while (i < length) {
        if (i == index_word) {
            // add correct word at random location
            wordlist[i] = word;
            i++;
            continue;
        }
        uint8_t random_num_b1 = random_byte_mcu();
        uint8_t random_num_b2 = random_byte_mcu();
        uint16_t random_num = (random_num_b1 << 8 | random_num_b2) % LEN_WORDLIST_EN;
        if (_is_in_list(random_num, random_numbers, current_length)) {
            // already chose that word, so select a different word
            continue;
        }
        char* picked_word;
        bip39_get_word(NULL, random_num, &picked_word);
        wordlist[i] = picked_word;
        if (strcmp(wordlist[i], word) == 0) {
            // if it's the same as the correct word, select a different word
            continue;
        }
        random_numbers[current_length] = random_num;
        current_length++;
        i++;
    }
    return index_word;
}

static void _cancel(void* param)
{
    (void)param;
}

#define NUM_RANDOM_WORDS 5
#define NUM_CONFIRM_WORDS (NUM_RANDOM_WORDS + 1)

int main(void)
{
    system_init();
    screen_init();
    qtouch_init();

    const char* wordlist[NUM_CONFIRM_WORDS];
    // const char* wordlist[] = {"flight", "donkey", "evolve", "skirt", "inspire", "back to seed
    // phrase"};
    _current_correct_idx = _create_random_unique_words(wordlist, NUM_RANDOM_WORDS, "skirt");
    wordlist[NUM_CONFIRM_WORDS - 1] = "Back to seed phrase";

    component_t* confirm_mnemonic = confirm_mnemonic_create(
        wordlist, NUM_CONFIRM_WORDS, 0, _confirm_mnemonic, NULL, _cancel, NULL);
    ui_screen_stack_switch(confirm_mnemonic);

    firmware_main_loop();
}

#pragma GCC diagnostic pop

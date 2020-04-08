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

#include "show_mnemonic.h"

#include "blocking.h"
#include "cancel.h"
#include "password.h"
#include "status.h"
#include "workflow.h"

#include <hardfault.h>
#include <keystore.h>
#include <random.h>
#include <ui/components/confirm_mnemonic.h>
#include <ui/components/scroll_through_all_variants.h>
#include <util.h>

#define BIP39_NUM_WORDS 24
#define MAX_WORDLENGTH 20

#define NUM_RANDOM_WORDS 5

static const char* _back_label = "Back to seed phrase";
static const char* _cancel_confirm_title = "Mnemonic";

static void _split_and_save_wordlist(
    char* mnemonic,
    const char** wordlist_out,
    uint8_t* words_count_out)
{
    char* next_word = strtok(mnemonic, " ");

    int i = 0;
    while (next_word != NULL) {
        wordlist_out[i] = next_word;
        next_word = strtok(NULL, " ");
        i++;
    }
    *words_count_out = i;
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

/**
 * Creates a list of unique, random words from the BIP39 wordlist and places the passed
 * word at a random position. The generated list of words is used to show it to the user
 * who must identify the word that was pased to the function. This functionality is used
 * to confirm that the user correctly copied his/her BIP39 seed phrase.
 *
 * @param[out] wordlist A list of randomly selected, unique words and the passed word.
 * @param[in] length The length of the wordlist that is generated.
 * @param[in] word The word that is put into the wordlist at a random position.
 */
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
        uint16_t random_num = (random_num_b1 << 8 | random_num_b2) % BIP39_WORDLIST_LEN;
        if (_is_in_list(random_num, random_numbers, current_length)) {
            // already chose that word, so select a different word
            continue;
        }
        char* picked_word;
        if (!keystore_get_bip39_word(random_num, &picked_word)) {
            Abort("keystore_get_bip39_word: alloc");
        }
        wordlist[i] = picked_word;
        if (STREQ(wordlist[i], word)) {
            // if it's the same as the correct word, select a different word
            continue;
        }
        random_numbers[current_length] = random_num;
        current_length++;
        i++;
    }
    return index_word;
}

static uint8_t _selection_idx;
static void _select_word(uint8_t selection_idx, void* param)
{
    (void)param;
    _selection_idx = selection_idx;
    workflow_blocking_unblock();
}

static void _workflow_cancel_cb(void* param)
{
    (void)param;
    workflow_cancel();
}

static bool _show_words(const char** words, uint8_t words_count)
{
    return workflow_cancel_run(
        _cancel_confirm_title,
        scroll_through_all_variants_create(
            words,
            NULL,
            NULL,
            words_count,
            NULL,
            workflow_blocking_unblock,
            _workflow_cancel_cb,
            NULL,
            NULL));
}

typedef struct {
    char* mnemonic;
    // Keep len as mnemonic is tokenized using strtok, so util_cleanup_str() does not work anymore
    // to clean the string.
    size_t len;
} mnemonic_t;

static void _cleanup_mnemonic(mnemonic_t* mnemonic)
{
    util_zero(mnemonic->mnemonic, mnemonic->len);
    free(mnemonic->mnemonic);
}

bool workflow_show_mnemonic_create(void)
{
    if (!password_check()) {
        return false;
    }

    mnemonic_t __attribute__((__cleanup__(_cleanup_mnemonic))) mnemonic;
    if (!keystore_get_bip39_mnemonic(&mnemonic.mnemonic)) {
        Abort("mnemonic create not possible");
    }
    // This field must be set before we tokenize the mnemonic, because we use the length when we
    // zero the memory after confirmation.
    mnemonic.len = strlens(mnemonic.mnemonic);

    // No malloc elements point into parts of the tokenized `mnemonic`.
    const char* words[BIP39_NUM_WORDS];
    uint8_t words_count;
    _split_and_save_wordlist(mnemonic.mnemonic, words, &words_count);

    // Part 1) Scroll through words
    if (!_show_words(words, words_count)) {
        return false;
    }

    // Part 2) Confirm words
    for (size_t word_idx = 0; word_idx < words_count; word_idx++) {
        const char* confirm_wordlist[NUM_RANDOM_WORDS + 1];
        const int back_idx = NUM_RANDOM_WORDS;
        size_t correct_idx =
            _create_random_unique_words(confirm_wordlist, NUM_RANDOM_WORDS, words[word_idx]);
        confirm_wordlist[back_idx] = _back_label;

        while (true) {
            if (!workflow_cancel_run(
                    _cancel_confirm_title,
                    confirm_mnemonic_create(
                        confirm_wordlist,
                        NUM_RANDOM_WORDS + 1,
                        word_idx,
                        _select_word,
                        NULL,
                        _workflow_cancel_cb,
                        NULL))) {
                return false;
            }
            if (_selection_idx == correct_idx) {
                break;
            }
            if (_selection_idx == back_idx) {
                if (!_show_words(words, words_count)) {
                    return false;
                }
                continue;
            }
            workflow_status_blocking("Incorrect word\nTry again", false);
        }
    }

    workflow_status_blocking("Success", true);
    return true;
}

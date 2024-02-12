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

#include <apps/eth/eth_params.h>
#include <atecc/atecc.h>
#include <bip32.h>
#include <keystore.h>
#include <memory/bitbox02_smarteeprom.h>
#include <memory/memory.h>
#include <memory/smarteeprom.h>
#include <random.h>
#include <reset.h>
#include <screen.h>
#include <sd.h>
#include <secp256k1_ecdsa_s2c.h>
#include <system.h>
#include <time.h>
#include <ui/components/confirm.h>
#include <ui/components/confirm_transaction.h>
#include <ui/components/empty.h>
#include <ui/components/label.h>
#include <ui/components/menu.h>
#include <ui/components/progress.h>
#include <ui/components/sdcard.h>
#include <ui/components/status.h>
#include <ui/components/trinary_choice.h>
#include <ui/components/trinary_input_string.h>
#include <ui/fonts/font_a_11X10.h>
#include <ui/fonts/font_a_9X9.h>
#include <ui/fonts/monogram_5X9.h>
#include <ui/fonts/password_11X12.h>
#include <ui/graphics/lock_animation.h>
#include <ui/oled/oled.h>
#include <ui/screen_process.h>
#include <ui/screen_saver.h>
#include <ui/screen_stack.h>
#include <ui/ugui/ugui.h>
#include <util.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_crypto.h>

#if defined(TESTING)
#include <mock_memory.h>
#endif

#if !defined(TESTING)
#include <hal_delay.h>
#else
void delay_us(const uint16_t us);
void delay_ms(const uint16_t ms);
#endif

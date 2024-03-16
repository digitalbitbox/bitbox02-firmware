// Copyright 2022 Shift Crypto AG
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

#ifndef _MEMORY_SHARED_H_
#define _MEMORY_SHARED_H_

#include <stdint.h>

#include <compiler_util.h>
#include <flags.h>

#if (FLASH_SHARED_DATA_LEN != CHUNK_SIZE)
#error "Shared data chunk not correct length"
#endif

// CHUNK_SHARED: Shared data between the bootloader and firmware.
//    auto_enter: if sectrue_u8, bootloader mode is entered on reboot
//    upside_down: passes screen orientation to the bootloader
//
// ** DO NOT CHANGE MEMBER ORDER OR MEMORY LOCATION **
//
// Because the bootloader is fixed, changes may break the bootloader!
//
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpacked"
#pragma GCC diagnostic ignored "-Wattributes"
typedef union {
    struct __attribute__((__packed__)) {
        // Shared flags - do not change order!
        uint8_t auto_enter;
        uint8_t upside_down;
        uint8_t screen_type;
        uint8_t securechip_type;
        // Following are used by firmware only
        uint8_t io_protection_key_split[32];
        uint8_t authorization_key_split[32];
        uint8_t encryption_key_split[32];
    } fields;
    uint8_t bytes[FLASH_SHARED_DATA_LEN];
} chunk_shared_t;
#pragma GCC diagnostic pop

void memory_read_shared_bootdata(chunk_shared_t* chunk_out);

// 0xFF is the default memory value if not set otherwise. We use this value for the original screen
// for backwards compatibility.
#define MEMORY_SCREEN_TYPE_SH1107 0xFF
#define MEMORY_SCREEN_TYPE_SSD1312 0x01

/**
 * Which screen is mounted? Currently there are two possible screens. The original screen uses the
 * SH1107 driver, and the newer display uses the SSD1312 driver.  See the `SCREEN_TYPE_` consts.
 * Any undefined value (none of the predefined `SCREEN_TYPE_`) defaults to the original SH1107 for
 * backwards compatibility.
 *
 * Can be called before `memory_setup()`.
 */
USE_RESULT uint8_t memory_get_screen_type(void);

#define MEMORY_SECURECHIP_TYPE_ATECC 0xFF
#define MEMORY_SECURECHIP_TYPE_OPTIGA 0x01
USE_RESULT uint8_t memory_get_securechip_type(void);

#endif

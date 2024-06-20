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

#include "bootloader.h"
#include "bootloader_version.h"
#include "mpu_regions.h"

#include <driver_init.h>
#include <stdint.h>
#include <string.h>
#ifdef BOOTLOADER_DEVDEVICE
#include <qtouch/qtouch.h>
#endif
#include <flags.h>
#include <memory/memory_shared.h>
#include <memory/nvmctrl.h>
#include <pukcc/curve_p256.h>
#include <screen.h>
#include <ui/components/ui_images.h>
#include <ui/fonts/arial_fonts.h>
#include <ui/oled/oled.h>
#include <ui/ugui/ugui.h>
#include <usb/usb.h>
#include <usb/usb_packet.h>
#include <usb/usb_processing.h>
#include <util.h>

#include <assert.h>

#define BOOT_OP_LEN 2u // 1 byte op code and 1 byte parameter
#define BOOTLOADER_CMD (HID_VENDOR_FIRST + 0x03) // Hardware wallet command

// Bootloader API command op codes
//
// OP_ERASE - Receives the total number of firmware chunks to write,
// then pads any left over FLASH that would be empty by 0xFFs;
// FLASH areas that will contain firmware are erased when writing the
// firmware chunk to FLASH.
#define OP_ERASE ((uint8_t)'e') /* 0x65 */
// OP_REBOOT - Reboot the MCU and clear the auto_enter flag.
#define OP_REBOOT ((uint8_t)'r') /* 0x72 */
// OP_WRITE - Write a firmware chunk; the binary must be streamed in chunks.
// The command must include the chunk number in order to be written to the
// correct FLASH location.
#define OP_WRITE_FIRMWARE_CHUNK ((uint8_t)'w') /* 0x77 */
// OP_WRITE_SIG_DATA - Write the firmware's signature data, which is used
// for firmware verification.
#define OP_WRITE_SIG_DATA ((uint8_t)'s') /* 0x73 */
// OP_VERSIONS - Return firmware and signature data version numbers to the
// computer. Note: The bootloader version is specified in the USB descriptor.
#define OP_VERSIONS ((uint8_t)'v') /* 0x76 */
// OP_HASHES - Display firmware and signature data hashes on the screen
// and return the values to the computer.
#define OP_HASHES ((uint8_t)'h') /* 0x68 */
// OP_SCREEN_ROTATE flips the screen orientation.
#define OP_SCREEN_ROTATE ((uint8_t)'f') /* 0x66 */
// OP_SET_SHOW_FIRMWARE_HASH - Enable or disable the flag to automatically show the firmware hash.
#define OP_SET_SHOW_FIRMWARE_HASH ((uint8_t)'H') /* 0x4A */

// API return codes
#define OP_STATUS_OK ((uint8_t)0)
#define OP_STATUS_ERR ((uint8_t)'Z')
#define OP_STATUS_ERR_VERSION ((uint8_t)'V')
#define OP_STATUS_ERR_LEN ((uint8_t)'N')
#define OP_STATUS_ERR_MACRO ((uint8_t)'M')
#define OP_STATUS_ERR_WRITE ((uint8_t)'W')
#define OP_STATUS_ERR_CHECK ((uint8_t)'C')
#define OP_STATUS_ERR_ABORT ((uint8_t)'A')
#define OP_STATUS_ERR_ERASE ((uint8_t)'E')
#define OP_STATUS_ERR_LOAD_FLAG ((uint8_t)'L')
#define OP_STATUS_ERR_INVALID_CMD ((uint8_t)'I')
#define OP_STATUS_ERR_UNLOCK ((uint8_t)'U')
#define OP_STATUS_ERR_LOCK ((uint8_t)'K')

extern volatile bool measurement_done_touch;

COMPILER_ALIGNED(128)
static struct sha_context _pukcc_sha256_context;
COMPILER_PACK_RESET()

#define FIRMWARE_CHUNK_LEN (8U * FLASH_PAGE_SIZE) // 4kB
#define FIRMWARE_MAX_NUM_CHUNKS \
    (FLASH_APP_LEN / FIRMWARE_CHUNK_LEN) // app len must be a multiple of chunk len
#if (FIRMWARE_MAX_NUM_CHUNKS > UINT8_MAX)
#error "incompatible variable type"
#endif

// Be sure to not overflow boot data area
static_assert(sizeof(((boot_data_t*)0)->fields) <= FLASH_BOOTDATA_LEN, "boot_data_t too large");
// Be sure signing pubkey data fits within a single chunk
#if (                                                                               \
    1 + 4 + /* op code + signing_pubkeys_version */                                 \
        BOOT_PUBKEY_LEN * BOOT_NUM_FIRMWARE_SIGNING_KEYS +                          \
        BOOT_SIG_LEN * BOOT_NUM_ROOT_SIGNING_KEYS + 4 /* firmware data version */ + \
        BOOT_SIG_LEN * BOOT_NUM_FIRMWARE_SIGNING_KEYS >                             \
    FIRMWARE_CHUNK_LEN)
#error "incompatible bootloader data macro"
#endif

static bool _loading_ready = false;
static uint8_t _firmware_num_chunks = 0;
// Indicates whether the whole app flash contains only 0xFF.
// This controls bootloader text messages on the screen.
// The value is computed at bootloader enter.
static bool _is_app_flash_empty = false;

// A "bare" firmware hash where all app flash sections are empty.
// Bare meaning the hash is computed in the same way as _firmware_hash except
// the firmware version is omitted.
// If FLASH_APP_LEN is changed, recompute with either a shell command:
//     printf '%884736s' | tr ' ' '\377' | openssl sha256 -binary | openssl sha256 -hex
// or python:
//     hashlib.sha256(hashlib.sha256(b'\xff' * 884736).digest()).hexdigest()
static const uint8_t _empty_bare_flash_hash[SHA256_DIGEST_LENGTH] = {
    0xbf, 0x71, 0x80, 0xc1, 0x23, 0xdf, 0xb5, 0x96, 0x1d, 0x93, 0xcd, 0x5f, 0xd9, 0x8a, 0xa4, 0x35,
    0x00, 0xb8, 0xaf, 0x3a, 0x79, 0xf8, 0xc6, 0x56, 0x4a, 0x9b, 0x02, 0xe1, 0x8a, 0xb8, 0x21, 0xae,
};
#if FLASH_APP_LEN != 884736
#error "FLASH_APP_LEN changed; recompute _empty_bare_flash_hash"
#endif

// clang-format off
#if PRODUCT_BITBOX_BTCONLY == 1
static const uint8_t _root_pubkeys[BOOT_NUM_ROOT_SIGNING_KEYS][BOOT_PUBKEY_LEN] = { // order is important
    {
        0x56, 0x82, 0xcc, 0xed, 0x54, 0x4e, 0xa6, 0xa1, 0x8f, 0x9e, 0x7c, 0x48, 0x40, 0xb8, 0x6d, 0x3d,
        0x51, 0x4e, 0x49, 0x4a, 0x9f, 0x20, 0xde, 0xe7, 0x6b, 0x5a, 0x99, 0x2c, 0xe1, 0x3e, 0x77, 0xa9,
        0x8a, 0x61, 0xe2, 0x34, 0x3e, 0x1f, 0x9e, 0xc7, 0x27, 0x7f, 0xf7, 0x50, 0xf2, 0x07, 0x09, 0x3a,
        0xa0, 0xba, 0x36, 0x31, 0xa4, 0x0f, 0xcd, 0x5a, 0xd6, 0xd0, 0xaf, 0x38, 0x44, 0x19, 0xc8, 0x86,
    },
    {
        0x3b, 0x13, 0x86, 0x55, 0x8f, 0xc8, 0x31, 0xd6, 0x3a, 0x30, 0x2b, 0x30, 0x84, 0xbf, 0x0a, 0xde,
        0x07, 0x8b, 0xf6, 0x08, 0xec, 0x15, 0x20, 0x8c, 0x0f, 0xb9, 0x51, 0x7d, 0xbc, 0xb4, 0x48, 0xe6,
        0x33, 0xb6, 0x40, 0xf3, 0xb6, 0x19, 0xbe, 0x9b, 0x94, 0x94, 0x4b, 0x80, 0x4f, 0xf6, 0x12, 0x1a,
        0xcd, 0x0a, 0x4d, 0xe7, 0x6b, 0x60, 0x12, 0x64, 0x2f, 0x7a, 0x62, 0x65, 0x2e, 0xc0, 0x44, 0x65,
    },
    {
        0x93, 0x13, 0x34, 0xe4, 0x43, 0x6e, 0x4d, 0x41, 0xfe, 0x2a, 0xee, 0xbd, 0xf1, 0x25, 0x1f, 0x08,
        0x35, 0xb2, 0xca, 0x5a, 0x9b, 0xc5, 0xca, 0x5b, 0x12, 0xcb, 0x72, 0xf9, 0xf7, 0xbf, 0xb4, 0x6f,
        0x73, 0xf5, 0xe2, 0x3e, 0x93, 0x45, 0x50, 0x2c, 0xe0, 0xaf, 0xce, 0x7b, 0xd4, 0x12, 0x56, 0xa2,
        0xde, 0x34, 0x43, 0x8e, 0x71, 0xdf, 0x99, 0xeb, 0x59, 0xb4, 0x1e, 0xb1, 0x32, 0x17, 0xda, 0x8a,
    },
};
#elif PRODUCT_BITBOX_MULTI == 1
static const uint8_t _root_pubkeys[BOOT_NUM_ROOT_SIGNING_KEYS][BOOT_PUBKEY_LEN] = { // order is important
    {
        0x08, 0xa6, 0xdc, 0x5f, 0x9b, 0x9e, 0x0c, 0x74, 0x25, 0x06, 0x3d, 0x00, 0x77, 0x66, 0xe1, 0x69,
        0x0a, 0x57, 0xe7, 0x2d, 0xdb, 0xab, 0xa6, 0x4e, 0x3d, 0x88, 0x75, 0x41, 0x6d, 0xd1, 0x86, 0x37,
        0x9e, 0x01, 0x8c, 0x2a, 0xd1, 0xcf, 0x01, 0xf7, 0x0f, 0x92, 0x5c, 0x18, 0x4f, 0x64, 0x36, 0xa9,
        0xc3, 0xf8, 0x9a, 0x9c, 0x75, 0x9c, 0x92, 0xdb, 0x6a, 0x1a, 0x75, 0xcb, 0x00, 0xb0, 0x26, 0x88,
    },
    {
        0xf5, 0xb9, 0xd3, 0xa8, 0x43, 0x99, 0x2c, 0xb2, 0x5a, 0xcc, 0xd4, 0x20, 0xb8, 0x24, 0x65, 0x46,
        0x77, 0xa2, 0x03, 0xb0, 0x11, 0x68, 0xdb, 0x97, 0x26, 0x8d, 0xe4, 0xd5, 0xd1, 0x94, 0x28, 0x95,
        0x09, 0x3d, 0x22, 0x7e, 0x57, 0x8f, 0x19, 0x4f, 0x2c, 0xd8, 0x45, 0x05, 0x83, 0xdf, 0xe8, 0xfe,
        0xfd, 0x41, 0xdd, 0xb6, 0x7b, 0x05, 0xfe, 0xc1, 0x32, 0xfa, 0xc1, 0x51, 0xe1, 0xbb, 0x44, 0xc7,
    },
    {
        0xa9, 0x1a, 0x8e, 0xc6, 0x46, 0xfc, 0x37, 0x41, 0x64, 0xb5, 0xdc, 0xbf, 0x29, 0x80, 0xfd, 0xbf,
        0xbc, 0xd1, 0x2b, 0x57, 0xaf, 0xa0, 0x29, 0xa4, 0x05, 0x5d, 0x7f, 0x9a, 0x81, 0x75, 0x0f, 0x18,
        0xfc, 0x13, 0x48, 0xdc, 0xda, 0xbd, 0x6e, 0x33, 0x25, 0x5b, 0x29, 0xa5, 0xb7, 0x51, 0x16, 0xbf,
        0xf0, 0xca, 0xde, 0x45, 0xd6, 0x1c, 0x51, 0x4d, 0x86, 0x09, 0xfc, 0xa7, 0x64, 0x1c, 0x9e, 0xe2,
    }
};
#else
#error "unknown product"
#endif
// clang-format on

const uint8_t _empty_sig[BOOT_SIG_LEN] = {0};

static void _render_bootloader_finished_marker(void)
{
    // We render the same as the firmware renders as a splash screen so it is not visually
    // distracting.
    screen_splash();
    // There will be a visible delay anyway before the firmware gets a chance to clear this, but
    // add a small delay anyway just in case.
    delay_ms(30);
}

void _binExec(const uint32_t* l_code_addr) __attribute__((noreturn));
void _binExec(const uint32_t* l_code_addr)
{
    __asm__ volatile("bx   %0" : : "r"(l_code_addr[1]));
    __builtin_unreachable();
}

static void _binary_exec(void)
{
    _render_bootloader_finished_marker();

    int i;

#if (FLASH_APP_START & 0x007F)
#error "app start address not aligned"
#else
    void* app_start_addr = (void*)FLASH_APP_START;
#endif

    rand_sync_disable(&RAND_0);

    // Update MPU settings for firmware mode
    mpu_regions_firmware_init();

    __disable_irq();
    for (i = 0; i < 8; i++) {
        NVIC->ICER[i] = 0xFFFFFFFF;
    }
    for (i = 0; i < 8; i++) {
        NVIC->ICPR[i] = 0xFFFFFFFF;
    }
    __DSB();
    __ISB();
    SCB->VTOR = ((uint32_t)app_start_addr & SCB_VTOR_TBLOFF_Msk);
    __DSB();
    __ISB();
    __enable_irq();
    _binExec(app_start_addr);
}

static void _load_logo(void)
{
    uint16_t x = 0;
    uint16_t y = 0;
    for (size_t i = 0; i < sizeof(IMAGE_BB2_LOGO); i++) {
        uint8_t b = IMAGE_BB2_LOGO[i];
        for (uint8_t j = 0; j < 8; j++) {
            if (b & 0x80) {
                UG_DrawPixel(x, y, C_WHITE);
            }
            b <<= 1;
            x++;
            if ((x % IMAGE_BB2_LOGO_W) == 0) {
                x = 0;
                y++;
            }
        }
    }
}

static void _load_arrow(int x, int y, int height)
{
    int width = height * 2 - 1;
    for (int h = 0; h < height; h++) {
        for (int w = (width + 1) / 2 - h; w < (width + 1) / 2 + h + 1; w++) {
            UG_DrawPixel(x + w, y + h, C_WHITE);
        }
    }
}

static void _load_progress_bar(float progress)
{
    const uint16_t bar_height = 5;
    UG_FillFrame(0, SCREEN_HEIGHT - bar_height, SCREEN_WIDTH * progress, SCREEN_HEIGHT, C_WHITE);
}

static void _render_message(const char* message, int duration)
{
    char print[100];
    snprintf(print, sizeof(print), "%s", message);
    UG_ClearBuffer();
    UG_PutString(0, 0, print, false);
    UG_SendBuffer();
    delay_ms(duration);
}

static void _render_default_screen(void)
{
    UG_ClearBuffer();
    _load_logo();
    if (_is_app_flash_empty) {
        UG_PutString(0, SCREEN_HEIGHT - 9 * 2, "Let's get started!", false);
    }
    UG_PutString(0, SCREEN_HEIGHT - 9, "See the BitBoxApp", false);
    UG_SendBuffer();
}

static void _render_progress(float progress)
{
    UG_ClearBuffer();
    _load_logo();
    if (progress > 0) {
        char label[5] = {0};
        snprintf(label, sizeof(label), "%2d%%", (int)(100 * progress));
        UG_PutString(0, SCREEN_HEIGHT - 9 * 2, label, false);
        _load_progress_bar(progress);
    } else {
        _load_arrow(0, SCREEN_HEIGHT - 16, 10);
    }
    const char* msg = "UPGRADING";
    if (_is_app_flash_empty) {
        msg = "INSTALLING";
    }
    UG_PutString(SCREEN_WIDTH / 2 - 3, SCREEN_HEIGHT - 9 * 2, msg, false);
    UG_SendBuffer();
}

static void _render_hash(const char* title, const uint8_t* hash)
{
    // If you change this, check the timer_buf size below.
    const uint8_t seconds = 10; // how many seconds to show screen
    const UG_S16 title_margin = 7; // Margin between title and hash
    const UG_FONT* f_mono = &font_monogram_5X9; // monospaced font
    const UG_FONT* f_regular = &font_font_a_9X9; // regular font

    // Convert hash to ascii hex
    char hash_hex[2 * SHA256_DIGEST_LENGTH + 1];
    util_uint8_to_hex(hash, SHA256_DIGEST_LENGTH, hash_hex);

    // Buffer for timer. 3 bytes would be enough to hold the string up to "9s", but we do a bit more
    // just in case the number of seconds changes.
    char timer_buf[4];
    // Store the width of the timer string in pixels.
    UG_S16 timer_str_width = 0;
    // 4 lines à 16 chars, 3 newline chars, one null terminator.
    char hash_multiline[4 * 16 + 3 + 1] = {0};
    snprintf(
        hash_multiline,
        sizeof(hash_multiline),
        "%.16s\n%.16s\n%.16s\n%.16s",
        &hash_hex[0],
        &hash_hex[16],
        &hash_hex[32],
        &hash_hex[48]);

    for (uint8_t i = 1; i <= seconds; i++) {
        UG_ClearBuffer();
        UG_PutString(0, 0, title, false);

        snprintf(timer_buf, sizeof(timer_buf), "%ds", seconds - i);
        UG_MeasureString(&timer_str_width, NULL, timer_buf);
        UG_PutString(
            SCREEN_WIDTH - timer_str_width,
            SCREEN_HEIGHT - f_regular->char_height,
            timer_buf,
            false);

        UG_FontSelect(f_mono);
        UG_PutString(0, title_margin + f_regular->char_height, hash_multiline, false);

        UG_FontSelect(f_regular);

        UG_SendBuffer();
        delay_ms(1000);
    }
    _render_default_screen();
}

// Sets _is_app_flash_empty by computing a "bare" hash, identical to _firmware_hash
// except omitting the firmware version.
static void _compute_is_app_flash_empty(void)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha_sync_sha256_start(&HASH_ALGORITHM_0, &_pukcc_sha256_context, false);
    sha_sync_sha256_update(&HASH_ALGORITHM_0, (const uint8_t*)FLASH_APP_START, FLASH_APP_LEN);
    sha_sync_sha256_finish(&HASH_ALGORITHM_0, hash);
    pukcc_sha256_compute(hash, SHA256_DIGEST_LENGTH, hash);
    _is_app_flash_empty = MEMEQ(hash, _empty_bare_flash_hash, sizeof(_empty_bare_flash_hash));
}

static size_t _report_status(uint8_t status, uint8_t* output)
{
    output[1] = status;
    return BOOT_OP_LEN;
}

static size_t _api_write_chunk(const uint8_t* buf, uint8_t chunknum, uint8_t* output)
{
    if (!_loading_ready) {
        return _report_status(OP_STATUS_ERR_LOAD_FLAG, output);
    }
    _loading_ready = false;

    if (BOOT_OP_LEN + FIRMWARE_CHUNK_LEN > USB_DATA_MAX_LEN) {
        return _report_status(OP_STATUS_ERR_MACRO, output);
    }

    // The second is redundant, as _firmware_num_chunks <=
    // FIRMWARE_MAX_NUM_CHUNKS.
    if (chunknum > _firmware_num_chunks - 1 || chunknum > FIRMWARE_MAX_NUM_CHUNKS - 1) {
        return _report_status(OP_STATUS_ERR_LEN, output);
    }

    if (MEMEQ(
            (const void*)(FLASH_APP_START + (chunknum * FIRMWARE_CHUNK_LEN)),
            buf,
            FIRMWARE_CHUNK_LEN)) {
        _loading_ready = true;
        return _report_status(OP_STATUS_OK, output);
    }

    // Erase is handled inside of flash_write
    if (flash_write(
            &FLASH_0,
            FLASH_APP_START + (chunknum * FIRMWARE_CHUNK_LEN),
            (const uint8_t*)buf,
            FIRMWARE_CHUNK_LEN) != ERR_NONE) {
        return _report_status(OP_STATUS_ERR_WRITE, output);
    }

    if (!MEMEQ(
            (const void*)(FLASH_APP_START + (chunknum * FIRMWARE_CHUNK_LEN)),
            buf,
            FIRMWARE_CHUNK_LEN)) {
        return _report_status(OP_STATUS_ERR_CHECK, output);
    }

    size_t len = _report_status(OP_STATUS_OK, output);
    _loading_ready = true;
    return len;
}

/**
 * This function erases only the padding bytes, if not already erased. Other
 * bytes get erased and written when writing the firmware chunks.
 *
 * The number of chunks is put into RAM in order to show the correct
 * progress in the next step flashing the firmware.
 */
static size_t _api_firmware_erase(uint8_t firmware_num_chunks, uint8_t* output)
{
    if (firmware_num_chunks > FIRMWARE_MAX_NUM_CHUNKS - 1) {
        return _report_status(OP_STATUS_ERR_LEN, output);
    }
    if (firmware_num_chunks > 0) {
        _render_progress(0);
    }
    _loading_ready = false;
    for (uint32_t i = 0; i < (uint32_t)FLASH_APP_PAGE_NUM; i += FLASH_REGION_PAGE_NUM) {
        if (flash_unlock(&FLASH_0, FLASH_APP_START + i * FLASH_PAGE_SIZE, FLASH_REGION_PAGE_NUM) !=
            FLASH_REGION_PAGE_NUM) {
            return _report_status(OP_STATUS_ERR_UNLOCK, output);
        }
    }
    uint8_t empty_page[FLASH_PAGE_SIZE];
    memset(empty_page, 0xff, sizeof(empty_page));
    uint16_t firmware_num_pages = firmware_num_chunks * FIRMWARE_CHUNK_LEN / FLASH_PAGE_SIZE;
    for (uint32_t i = firmware_num_pages; i < (uint32_t)FLASH_APP_PAGE_NUM;
         i += FLASH_ERASE_PAGE_NUM) {
        const uint32_t addr = FLASH_APP_START + i * FLASH_PAGE_SIZE;
        if (MEMEQ((const void*)addr, empty_page, sizeof(empty_page))) {
            continue;
        }
        if (flash_erase(&FLASH_0, addr, FLASH_ERASE_PAGE_NUM) != ERR_NONE) {
            return _report_status(OP_STATUS_ERR_ERASE, output);
        }
        if (!MEMEQ((const void*)addr, empty_page, sizeof(empty_page))) {
            return _report_status(OP_STATUS_ERR_CHECK, output);
        }
    }
    if (firmware_num_chunks > 0) {
        _firmware_num_chunks = firmware_num_chunks;
        _loading_ready = true;
    }
    return _report_status(OP_STATUS_OK, output);
}

static inline version_t _parse_version(const uint8_t* start)
{
    // 4 byte little endian
    return *(const version_t*)start;
}

static void _double_hash(const uint8_t* data, uint32_t len, uint8_t* hash)
{
    pukcc_sha256_compute(data, len, hash);
    pukcc_sha256_compute(hash, SHA256_DIGEST_LENGTH, hash);
}

static void _hash_signing_keys(const boot_data_t* data, uint8_t* hash_out)
{
    _double_hash(
        (const uint8_t*)(&data->fields.signing_pubkeys_version),
        sizeof(data->fields.signing_pubkeys_version) + sizeof(data->fields.signing_pubkeys),
        hash_out);
}

static secbool_u32 _pubkeys_verified(const boot_data_t* data)
{
    // Verify the signing keys' version and pubkeys, signed by the root keys
    volatile uint8_t valid = 0;

    uint8_t hash[SHA256_DIGEST_LENGTH];
    _hash_signing_keys(data, hash);
    for (uint8_t i = 0; i < BOOT_NUM_ROOT_SIGNING_KEYS; i++) {
        const uint8_t* sig =
            (const uint8_t*)&data->fields.root_signatures_of_signing_pubkeys + i * BOOT_SIG_LEN;
        uint8_t random[SHA256_DIGEST_LENGTH];
        if (MEMEQ(sig, _empty_sig, sizeof(_empty_sig))) {
            continue;
        }
        rand_sync_read_buf8(&RAND_0, random, sizeof(random));
        // First is sanity check
        if (pukcc_ecdsa_verify(_root_pubkeys[i], sig, random, sizeof(random), curve_p256) != 0) {
            if (pukcc_ecdsa_verify(_root_pubkeys[i], sig, hash, sizeof(hash), curve_p256) == 0) {
                valid++;
                continue;
            }
        }
        return secfalse_u32;
    }
    if (valid >= BOOT_ROOT_SIG_M) {
        return sectrue_u32;
    }
    return secfalse_u32;
}

// double hashes firmware version | firmware
static void _firmware_hash(const boot_data_t* data, uint8_t* hash_out)
{
    sha_sync_sha256_start(&HASH_ALGORITHM_0, &_pukcc_sha256_context, false);
    sha_sync_sha256_update(
        &HASH_ALGORITHM_0,
        (const uint8_t*)&data->fields.firmware_version,
        sizeof(data->fields.firmware_version));
    sha_sync_sha256_update(&HASH_ALGORITHM_0, (const uint8_t*)FLASH_APP_START, FLASH_APP_LEN);
    sha_sync_sha256_finish(&HASH_ALGORITHM_0, hash_out);
    pukcc_sha256_compute(hash_out, SHA256_DIGEST_LENGTH, hash_out);
}

static void _maybe_show_hash(void)
{
    const boot_data_t* data = (const boot_data_t*)FLASH_BOOTDATA_START;
    if (!data->fields.show_firmware_hash) {
        return;
    }
    uint8_t hash[SHA256_DIGEST_LENGTH];
    _firmware_hash(data, hash);
    _render_hash("Firmware hash", hash);
}

/*
 * Check the if the signatures of the firmware hash are valid.
 * If jump = true and M signatures are valid, jump to the firmware app.
 */
static secbool_u32 _firmware_verified_jump(const boot_data_t* data, secbool_u32 jump)
{
    if (jump) {
        _maybe_show_hash();
    }

    for (uint32_t i = 0; i < (uint32_t)FLASH_APP_PAGE_NUM; i += FLASH_REGION_PAGE_NUM) {
        flash_lock(&FLASH_0, FLASH_APP_START + i * FLASH_PAGE_SIZE, FLASH_REGION_PAGE_NUM);
    }

    // Verify the firmware, signed by the signing keys
    if (_pubkeys_verified(data) != sectrue_u32) {
        return secfalse_u32;
    }

    volatile uint8_t valid = 0;

    uint8_t hash[SHA256_DIGEST_LENGTH];
    _firmware_hash(data, hash);
    for (uint8_t i = 0; i < BOOT_NUM_FIRMWARE_SIGNING_KEYS; i++) {
        const uint8_t* pubkey = (const uint8_t*)&data->fields.signing_pubkeys + i * BOOT_PUBKEY_LEN;
        const uint8_t* sig = (const uint8_t*)&data->fields.firmware_signatures + i * BOOT_SIG_LEN;
        uint8_t random[SHA256_DIGEST_LENGTH];
        if (MEMEQ(sig, _empty_sig, sizeof(_empty_sig))) {
            continue;
        }
        rand_sync_read_buf8(&RAND_0, random, sizeof(random));
        // First is sanity check
        if (pukcc_ecdsa_verify(pubkey, sig, random, sizeof(random), curve_p256) != 0) {
            if (pukcc_ecdsa_verify(pubkey, sig, hash, sizeof(hash), curve_p256) == 0) {
                valid++;
                continue;
            }
        }
        return secfalse_u32;
    }

    if (valid >= BOOT_FIRMWARE_SIG_M) {
        if (jump == sectrue_u32) {
            _binary_exec(); /* no return */
        }
        return sectrue_u32;
    }
    return secfalse_u32;
}

static uint8_t _write_chunk(uint32_t address, const uint8_t* data)
{
    const uint32_t lock_size = FLASH_ERASE_PAGE_NUM * FLASH_PAGE_SIZE;
    if (flash_unlock(&FLASH_0, address & ~(lock_size - 1), FLASH_REGION_PAGE_NUM) !=
        FLASH_REGION_PAGE_NUM) {
        return OP_STATUS_ERR_UNLOCK;
    }
    // Erase is handled inside of flash_write
    if (flash_write(&FLASH_0, address, data, FLASH_BOOTDATA_LEN) != ERR_NONE) {
        return OP_STATUS_ERR_WRITE;
    }
    if (flash_lock(&FLASH_0, address & ~(lock_size - 1), FLASH_REGION_PAGE_NUM) !=
        FLASH_REGION_PAGE_NUM) {
        return OP_STATUS_ERR_LOCK;
    }
    return OP_STATUS_OK;
}

/*
 * input: firmware version | i signatures of the double hash of the [version | firmware app]
 */
static uint8_t _set_firmware_data(boot_data_t* data, const uint8_t* input)
{
    version_t version_new = _parse_version(input);
    // Downgrade prevention
    if (version_new < data->fields.firmware_version) {
        return OP_STATUS_ERR_VERSION;
    }

    data->fields.firmware_version = version_new;

    memcpy(
        &data->fields.firmware_signatures,
        input + sizeof(version_t),
        BOOT_SIG_LEN * BOOT_NUM_FIRMWARE_SIGNING_KEYS);

    if (_firmware_verified_jump(data, secfalse_u32) != sectrue_u32) {
        return OP_STATUS_ERR;
    }
    return OP_STATUS_OK;
}

/*
 * input:  signing pubkeys version | i signing pubkeys | j signatures of the double hash of [version
 * | signing pubkeys]
 */
static uint8_t _set_signing_pubkey_data(boot_data_t* data, const uint8_t* input)
{
    version_t version_new = _parse_version(input);
    // Downgrade prevention
    if (version_new < data->fields.signing_pubkeys_version) {
        return OP_STATUS_ERR_VERSION;
    }

    data->fields.signing_pubkeys_version = version_new;

    const uint8_t* signing_pubkeys_addr = input + sizeof(version_t);
    memcpy(
        (uint8_t*)&data->fields.signing_pubkeys,
        signing_pubkeys_addr,
        sizeof(data->fields.signing_pubkeys));

    memcpy(
        &data->fields.root_signatures_of_signing_pubkeys,
        signing_pubkeys_addr + BOOT_NUM_FIRMWARE_SIGNING_KEYS * BOOT_PUBKEY_LEN,
        sizeof(data->fields.root_signatures_of_signing_pubkeys));

    if (_pubkeys_verified(data) != sectrue_u32) {
        return OP_STATUS_ERR;
    }
    return OP_STATUS_OK;
}

static size_t _api_write_sig_data(const uint8_t* input, uint8_t* output)
{
    boot_data_t data;
    memcpy(data.bytes, (uint8_t*)(FLASH_BOOTDATA_START), FLASH_BOOTDATA_LEN);
    uint8_t status = _set_signing_pubkey_data(&data, input);
    if (status != OP_STATUS_OK) {
        return _report_status(status, output);
    }
    status = _set_firmware_data(
        &data,
        input + sizeof(version_t) + BOOT_PUBKEY_LEN * BOOT_NUM_FIRMWARE_SIGNING_KEYS +
            BOOT_SIG_LEN * BOOT_NUM_ROOT_SIGNING_KEYS);
    if (status != OP_STATUS_OK) {
        return _report_status(status, output);
    }
    return _report_status(_write_chunk(FLASH_BOOTDATA_START, data.bytes), output);
}

/*
 * output filled with double hash of firmware app | double hash of signing key data
 */
static size_t _api_get_hashes(const uint8_t* input, uint8_t* output)
{
    const boot_data_t* data = (const boot_data_t*)FLASH_BOOTDATA_START;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    _firmware_hash(data, hash);
    memcpy(output + BOOT_OP_LEN, hash, SHA256_DIGEST_LENGTH);

    if (input[0]) {
        _render_hash("Firmware hash", hash);
    }

    _hash_signing_keys(data, hash);
    memcpy(output + BOOT_OP_LEN + SHA256_DIGEST_LENGTH, hash, SHA256_DIGEST_LENGTH);

    if (input[1]) {
        _render_hash("Sigkeys hash", hash);
    }

    size_t len = _report_status(OP_STATUS_OK, output);
    return len + SHA256_DIGEST_LENGTH * 2;
}

/*
 * input: one byte: 0 - disable, 1 - enable, >1: no effect.
 * output: one byte: 0 - disabled, 1: enabled.
 */
static size_t _api_set_show_firmware_hash(const uint8_t* input, uint8_t* output)
{
    boot_data_t data;
    memcpy(data.bytes, (uint8_t*)(FLASH_BOOTDATA_START), FLASH_BOOTDATA_LEN);
    uint8_t result = OP_STATUS_OK;
    uint8_t value = input[0];
    if (value == 0 || value == 1) {
        if (data.fields.show_firmware_hash != value) {
            data.fields.show_firmware_hash = value;
            result = _write_chunk(FLASH_BOOTDATA_START, data.bytes);
        }
    }
    output[BOOT_OP_LEN] = data.fields.show_firmware_hash;
    return _report_status(result, output) + 1;
}

/*
 * output filled with bootloader version | firmware version | signing pubkeys version
 */
static size_t _api_versions(uint8_t* output)
{
    const boot_data_t* data = (const boot_data_t*)FLASH_BOOTDATA_START;
    memcpy(output + BOOT_OP_LEN, (const uint8_t*)&data->fields.firmware_version, sizeof(version_t));
    memcpy(
        output + BOOT_OP_LEN + sizeof(version_t),
        (const uint8_t*)&data->fields.signing_pubkeys_version,
        sizeof(version_t));
    _report_status(OP_STATUS_OK, output);
    return BOOT_OP_LEN + sizeof(version_t) * 3;
}

static void _api_reboot(void)
{
    chunk_shared_t shared_data;
    memory_read_shared_bootdata(&shared_data);
    if (shared_data.fields.auto_enter == sectrue_u8) {
        shared_data.fields.auto_enter = secfalse_u8;
        _write_chunk(FLASH_SHARED_DATA_START, shared_data.bytes);
    }
    _reset_mcu();
}

static size_t _api_screen_rotate(uint8_t* output)
{
    if (_loading_ready) {
        return _report_status(OP_STATUS_ERR_LOAD_FLAG, output);
    }
    screen_rotate();
    _render_default_screen();
    return _report_status(OP_STATUS_OK, output);
}

static size_t _api_command(const uint8_t* input, uint8_t* output, const size_t max_out_len)
{
    memset(output, 0, max_out_len);
    output[0] = input[0]; // OP_CODE
    size_t len = 1;

    switch (output[0]) {
    case OP_VERSIONS:
        len = _api_versions(output);
        break;

    case OP_HASHES:
        len = _api_get_hashes(input + 1, output);
        break;

    case OP_SET_SHOW_FIRMWARE_HASH:
        len = _api_set_show_firmware_hash(input + 1, output);
        break;

    case OP_ERASE:
        len = _api_firmware_erase(input[1], output);
        break;

    case OP_REBOOT:
        _api_reboot();
        break;

    case OP_WRITE_FIRMWARE_CHUNK: {
        uint8_t chunk_num = input[1];
        len = _api_write_chunk(input + 2, chunk_num, output);
        if (output[1] != OP_STATUS_OK) {
            _render_default_screen();
        } else {
            _render_progress((float)chunk_num / (float)(_firmware_num_chunks - 1));
        }
        break;
    }
    case OP_WRITE_SIG_DATA:
        len = _api_write_sig_data(input + 1, output);
        break;
    case OP_SCREEN_ROTATE:
        len = _api_screen_rotate(output);
        break;
    default:
        len = _report_status(OP_STATUS_ERR_INVALID_CMD, output);
        _loading_ready = false;
        char msg[100];
        snprintf(msg, 100, "Command: %u unknown", input[0]);
        _render_message(msg, 1000);
        break;
    }

    return len;
}

static void _api_msg(const Packet* in_packet, Packet* out_packet, const size_t max_out_len)
{
    size_t len = _api_command(in_packet->data_addr, out_packet->data_addr, max_out_len);
    out_packet->len = len;
}

static void _api_setup(void)
{
    const CMD_Callback cmd_callbacks[] = {{BOOTLOADER_CMD, _api_msg}};

    usb_processing_register_cmds(usb_processing_hww(), cmd_callbacks, 1);
}

static void _check_init(boot_data_t* data)
{
#ifdef BOOTLOADER_PRODUCTION
    // Enable boot protection if not already enabled. The
    // BOOTPROT fuse is persistent and not erased on chip erase.
    while (NVMCTRL->STATUS.bit.READY == 0) {
    }
    if (NVMCTRL->STATUS.bit.BOOTPROT != FLASH_BOOTPROTECTION) {
        // Update BOOTPROT fuse
        uint32_t fuses[2];
        fuses[0] = *((uint32_t*)NVMCTRL_FUSES_BOOTPROT_ADDR);
        fuses[1] = *(((uint32_t*)NVMCTRL_FUSES_BOOTPROT_ADDR) + 1);
        fuses[0] = (fuses[0] & ~NVMCTRL_FUSES_BOOTPROT_Msk) |
                   (FLASH_BOOTPROTECTION << NVMCTRL_FUSES_BOOTPROT_Pos);
        // Write fuses
        NVMCTRL->CTRLA.bit.WMODE = NVMCTRL_CTRLA_WMODE_MAN; // Manual write
        nvmctrl_exec_cmd(NVMCTRL_CTRLB_CMD_EP); // Erase page
        nvmctrl_exec_cmd(NVMCTRL_CTRLB_CMD_PBC); // Clear page buffer
        *((uint32_t*)NVMCTRL_FUSES_BOOTPROT_ADDR) = fuses[0];
        *(((uint32_t*)NVMCTRL_FUSES_BOOTPROT_ADDR) + 1) = fuses[1];
        nvmctrl_exec_cmd(NVMCTRL_CTRLB_CMD_WQW); // Write a 128-bit word
        // Reboot for changes to take effect
        _reset_mcu();
    }

    // Hard lock the Device Service Unit, i.e., set the PAC write-protection bit,
    // which can only be cleared by a hardware reset. Because the DSU is soft
    // locked by default on reset, an unlock is required before a hard lock.
    periph_unlock(DSU);
    periph_lock_hard(DSU);

    // Set the security bit to disable hardware debug access if not already set.
    // The security bit is persistent and erased on chip erase. A chip erase is
    // disabled by hard locking the DSU.
    if (!DSU->STATUSB.bit.PROT) {
        while (NVMCTRL->STATUS.bit.READY == 0) {
        }
        do {
            NVMCTRL->CTRLB.reg = NVMCTRL_CTRLB_CMD_SSB | NVMCTRL_CTRLB_CMDEX_KEY;
            while (NVMCTRL->INTFLAG.bit.DONE == 0 || NVMCTRL->STATUS.bit.READY == 0) {
            }
        } while (NVMCTRL->INTFLAG.bit.PROGE); // Program Error flag
        // Software reset the NVMCTRL peripheral to have correct NVM state output
        NVMCTRL->CTRLB.reg = NVMCTRL_CTRLB_CMD_SWRST | NVMCTRL_CTRLB_CMDEX_KEY;
        while (NVMCTRL->STATUS.bit.READY == 0) {
        }
    }
#endif

    // Check bootdata initialized
    const uint8_t expected_initialized[2] = {sectrue_u8, sectrue_u8};
    if (!MEMEQ(data->fields.is_initialized, expected_initialized, 2)) {
        memset(data->bytes, 0, sizeof(data->bytes));
        memcpy(data->fields.is_initialized, expected_initialized, 2);
        _write_chunk(FLASH_BOOTDATA_START, data->bytes);
    }
}

#ifdef BOOTLOADER_DEVDEVICE
#if PLATFORM_BITBOX02 == 1
static bool _devdevice_enter(secbool_u32 firmware_verified)
{
    UG_ClearBuffer();
    UG_PutString(0, 0, "    <Enter bootloader>", false);
    UG_PutString(0, SCREEN_HEIGHT / 2 - 11, "DEV DEVICE", false);
    UG_PutString(0, SCREEN_HEIGHT / 2 + 2, "NOT FOR VALUE", false);
    UG_PutString(0, SCREEN_HEIGHT - 9, "        <Continue>", false);
    uint16_t ypos = SCREEN_HEIGHT / 2 - 4;
    uint16_t xpos = SCREEN_WIDTH - 10;
    if (firmware_verified != sectrue_u32) {
        // Draw cross
        UG_DrawLine(xpos, ypos, xpos + 5, ypos + 5, C_WHITE);
        UG_DrawLine(xpos + 5, ypos, xpos, ypos + 5, C_WHITE);
    } else {
        // Draw checkmark
        UG_DrawLine(xpos + 5, ypos, xpos, ypos + 5, C_WHITE);
        UG_DrawLine(xpos - 2, ypos + 3, xpos, ypos + 5, C_WHITE);
    }
    UG_SendBuffer();
    while (true) {
        do {
            qtouch_process();
        } while (!measurement_done_touch);

        if (qtouch_is_scroller_active(top_slider)) {
            return true;
        }
        if (qtouch_is_scroller_active(bottom_slider)) {
            return false;
        }
    }
}
#endif
#endif

void bootloader_jump(void)
{
    boot_data_t bootdata;
    chunk_shared_t shared_data;

    memcpy(bootdata.bytes, (uint8_t*)(FLASH_BOOTDATA_START), FLASH_BOOTDATA_LEN);
    memory_read_shared_bootdata(&shared_data);

    _check_init(&bootdata);

#if PLATFORM_BITBOX02 == 1
    if (shared_data.fields.upside_down) {
        screen_rotate();
    }
#endif

    UG_FontSelect(&font_font_a_9X9);

    if (shared_data.fields.auto_enter != sectrue_u8) {
#ifdef BOOTLOADER_DEVDEVICE
        if (!_devdevice_enter(_firmware_verified_jump(&bootdata, secfalse_u32))) {
            _binary_exec();
            /* no return */
        }
#else
        _firmware_verified_jump(&bootdata, sectrue_u32); // no return if firmware is valid
        _render_message("Firmware\ninvalid\n \nEntering bootloader", 3000);
#endif
    }

    // App not entered. Start USB API to receive boot commands
    _compute_is_app_flash_empty();
    _render_default_screen();
    if (usb_start(_api_setup) != ERR_NONE) {
        _render_message("Failed to initialize USB", 0);
    }
}

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
#include "leds.h"
#include "mpu_regions.h"

#include <driver_init.h>
#include <stdint.h>
#include <string.h>
#ifdef BOOTLOADER_DEVDEVICE
#include <qtouch/qtouch.h>
#endif
#include <flags.h>
#include <memory/nvmctrl.h>
#include <pukcc/curve_p256.h>
#include <screen.h>
#include <ui/components/ui_images.h>
#include <ui/components/ui_logos.h>
#include <ui/oled/oled.h>
#include <ui/ugui/ugui.h>
#if PLATFORM_BITBOXBASE == 1
#include <usart/usart.h>
#include <usart/usart_frame.h>
#elif PLATFORM_BITBOX02 == 1
#include <usb/usb.h>
#include <usb/usb_packet.h>
#endif
#include <usb/usb_processing.h>
#include <util.h>

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

extern volatile uint8_t measurement_done_touch;

COMPILER_ALIGNED(128)
static struct sha_context _pukcc_sha256_context;
COMPILER_PACK_RESET()

#define FIRMWARE_CHUNK_LEN (8U * FLASH_PAGE_SIZE) // 4kB
#define FIRMWARE_MAX_NUM_CHUNKS \
    (FLASH_APP_LEN / FIRMWARE_CHUNK_LEN) // app len must be a multiple of chunk len
#if (FIRMWARE_MAX_NUM_CHUNKS > UINT8_MAX)
#error "incompatible variable type"
#endif

#define BOOT_NUM_FIRMWARE_SIGNING_KEYS 3u
#define BOOT_NUM_ROOT_SIGNING_KEYS 3u
#define BOOT_FIRMWARE_SIG_M 2u
#define BOOT_ROOT_SIG_M 2u
#define BOOT_PUBKEY_LEN 64u
#define BOOT_SIG_LEN 64u

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpacked"
#pragma GCC diagnostic ignored "-Wattributes"
// Packed to make the layout more explicit.
// Total size equals min erase granularity
typedef uint32_t version_t;
typedef union {
    struct __attribute__((__packed__)) {
        uint16_t hardware_version;
        uint8_t is_initialized[2];
        version_t signing_pubkeys_version;
        uint8_t signing_pubkeys
            [BOOT_PUBKEY_LEN *
             BOOT_NUM_FIRMWARE_SIGNING_KEYS]; // Keep after signing_pubkeys_version
        uint8_t root_signatures_of_signing_pubkeys[BOOT_SIG_LEN * BOOT_NUM_ROOT_SIGNING_KEYS];
        version_t firmware_version;
        uint8_t
            firmware_signatures[BOOT_SIG_LEN * BOOT_NUM_FIRMWARE_SIGNING_KEYS]; // Keep after
                                                                                // firmware_version
        uint8_t show_firmware_hash;
    } fields;
    uint8_t bytes[FLASH_BOOTDATA_LEN];
} boot_data_t;

typedef union {
    // If changed, also need to change memory.c
    struct __attribute__((__packed__)) {
        uint8_t auto_enter;
        uint8_t upside_down;
    } fields;
    uint8_t bytes[FLASH_SHARED_DATA_LEN];
} shared_data_t;
#pragma GCC diagnostic pop
// Be sure to not overflow boot data area
#if (                                                                            \
    10 + /* hardawre_version + is_initialized + pad + signing_pubkeys_version */ \
        BOOT_PUBKEY_LEN * BOOT_NUM_FIRMWARE_SIGNING_KEYS +                       \
        BOOT_SIG_LEN * BOOT_NUM_ROOT_SIGNING_KEYS +                              \
        BOOT_SIG_LEN * BOOT_NUM_FIRMWARE_SIGNING_KEYS + 4 /* firware_version */  \
    > FLASH_BOOTDATA_LEN)
#error "incompatible bootloader data macro"
#endif
// Be sure signing pubkey data fits within a single chunk
#if (                                                                               \
    1 + 4 + /* op code + signing_pubkeys_version */                                 \
        BOOT_PUBKEY_LEN * BOOT_NUM_FIRMWARE_SIGNING_KEYS +                          \
        BOOT_SIG_LEN * BOOT_NUM_ROOT_SIGNING_KEYS + 4 /* firmware data version */ + \
        BOOT_SIG_LEN * BOOT_NUM_FIRMWARE_SIGNING_KEYS >                             \
    FIRMWARE_CHUNK_LEN)
#error "incompatible bootloader data macro"
#endif

static uint8_t _loading_ready = 0;
static uint8_t _firmware_num_chunks = 0;
// clang-format off
#if PRODUCT_BITBOX_BTCONLY == 1
static const uint8_t _root_pubkeys[BOOT_NUM_ROOT_SIGNING_KEYS][BOOT_PUBKEY_LEN] = { // order is important
    {
        0xe7, 0x30, 0x92, 0x3f, 0x19, 0x04, 0xd3, 0xe8, 0x3e, 0x0a, 0xb0, 0x7f, 0x05, 0x0d, 0x8e, 0x4e,
        0x60, 0x4c, 0x46, 0xba, 0x36, 0xae, 0xbb, 0xdb, 0x9a, 0x4d, 0x3c, 0x96, 0x60, 0x5b, 0x9e, 0xc3,
        0x94, 0x71, 0x03, 0x5c, 0x0f, 0x87, 0x34, 0xbd, 0xcb, 0xe1, 0x8f, 0x0c, 0xaa, 0x6f, 0x6e, 0x3d,
        0x8b, 0x7f, 0xa0, 0x5e, 0x42, 0x5a, 0xc2, 0x21, 0x5e, 0x6e, 0x97, 0x97, 0x5f, 0x48, 0x03, 0x8b,
    },
    {
        0xfd, 0x11, 0xed, 0xc3, 0xb6, 0xd8, 0xe5, 0x0b, 0xe8, 0x6b, 0x2e, 0x33, 0xee, 0xb0, 0x3b, 0x32,
        0x23, 0x91, 0x4c, 0x12, 0xe4, 0x9d, 0x0e, 0x64, 0xd9, 0x74, 0x03, 0xa7, 0x31, 0xc4, 0x30, 0x6a,
        0x44, 0xab, 0x6a, 0x99, 0x3e, 0x9d, 0xaa, 0x44, 0xda, 0x0e, 0x5a, 0x0a, 0x8b, 0x3e, 0x02, 0xe9,
        0xa4, 0x6e, 0x2c, 0xb6, 0x14, 0x57, 0xce, 0x78, 0x81, 0xa8, 0x71, 0x55, 0xee, 0x23, 0x67, 0x44,
    },
    {
        0x75, 0x98, 0x7e, 0x69, 0xa5, 0xed, 0xa5, 0x3f, 0x79, 0x63, 0x16, 0xfa, 0x47, 0x00, 0xf9, 0x9a,
        0x86, 0x36, 0xb0, 0xa5, 0x6c, 0x57, 0x28, 0xee, 0x8a, 0xd3, 0xb3, 0xcc, 0x8f, 0x37, 0xe6, 0xac,
        0xfc, 0xa6, 0x08, 0x23, 0x14, 0x4a, 0xea, 0xb2, 0xe4, 0xa7, 0x62, 0x97, 0x89, 0xd0, 0x3e, 0xa4,
        0xd2, 0xd1, 0x8a, 0xbf, 0x0f, 0xd7, 0xa0, 0x07, 0xd7, 0x96, 0xa1, 0x65, 0x57, 0x28, 0x4b, 0x3f,
    },
};
#elif PRODUCT_BITBOX_MULTI == 1
static const uint8_t _root_pubkeys[BOOT_NUM_ROOT_SIGNING_KEYS][BOOT_PUBKEY_LEN] = { // order is important
    {
        0x2b, 0x8a, 0x21, 0x9f, 0x01, 0x57, 0xf3, 0x12, 0x3e, 0x3c, 0x69, 0xd5, 0x40, 0x0e, 0xff, 0xfe,
        0xd9, 0x55, 0x3f, 0x64, 0xd2, 0x5e, 0xec, 0x10, 0x65, 0x7d, 0x0e, 0x77, 0x6a, 0x8e, 0x17, 0xe2,
        0xac, 0x2c, 0x3d, 0x19, 0xca, 0xfd, 0x18, 0x9b, 0x62, 0x36, 0x68, 0xc4, 0x10, 0x1b, 0x9b, 0x96,
        0x74, 0xf5, 0xe6, 0xe6, 0x43, 0xa3, 0x82, 0x8e, 0x6a, 0xb9, 0x3b, 0x46, 0xe9, 0xc3, 0x87, 0x73,
    },
    {
        0x1e, 0xb6, 0xe7, 0xad, 0x36, 0x1c, 0x40, 0x6b, 0xdd, 0xf4, 0x47, 0x17, 0x7b, 0x38, 0x21, 0x52,
        0x7a, 0x7a, 0x25, 0x75, 0x99, 0x5c, 0x6f, 0x49, 0xc2, 0xd8, 0xe0, 0x9b, 0x89, 0x7a, 0x70, 0xb7,
        0xab, 0x9c, 0x53, 0xa4, 0xcf, 0xbe, 0x29, 0x13, 0x33, 0x27, 0x1e, 0xd6, 0x75, 0x6b, 0xd3, 0xad,
        0x20, 0x77, 0x08, 0x2d, 0xe7, 0x1a, 0xcd, 0xc8, 0xb8, 0x7c, 0x39, 0x2d, 0x94, 0x64, 0xef, 0x51,
    },
    {
        0x9f, 0x39, 0x3d, 0x4a, 0xb6, 0xe8, 0xb0, 0xda, 0xc7, 0xc0, 0x43, 0x62, 0xc5, 0x20, 0xe1, 0xbc,
        0x1b, 0x32, 0x7d, 0x92, 0xee, 0x25, 0x6b, 0xc4, 0x07, 0xf6, 0x82, 0xff, 0xac, 0x12, 0x0d, 0xec,
        0x6b, 0x80, 0x23, 0x28, 0x62, 0xb9, 0x7d, 0xfd, 0x3d, 0xcf, 0x21, 0xdb, 0xb3, 0xf5, 0x4e, 0x4c,
        0x1b, 0xec, 0x2b, 0x99, 0x40, 0x61, 0x3e, 0xef, 0xe7, 0x9e, 0x6a, 0x2b, 0x10, 0xbe, 0xda, 0xc2,
    },
};
#elif PRODUCT_BITBOX_BASE == 1
static const uint8_t _root_pubkeys[BOOT_NUM_ROOT_SIGNING_KEYS][BOOT_PUBKEY_LEN] = { // order is important
    {
        0x89, 0x61, 0xff, 0xaa, 0x89, 0x9b, 0x9d, 0x2d, 0x71, 0xee, 0x31, 0x62, 0xe2, 0x01, 0x20, 0xbe,
        0x63, 0x0a, 0xfb, 0x5d, 0xf3, 0x5c, 0x99, 0xbf, 0x10, 0xa9, 0x15, 0xbf, 0x48, 0xd2, 0xc6, 0xf6,
        0xa0, 0x83, 0xbe, 0x8b, 0xb5, 0x35, 0xf7, 0x69, 0x67, 0xc8, 0x2a, 0xa5, 0xdd, 0x5a, 0xe8, 0x7e,
        0x3e, 0xe6, 0xa0, 0x4d, 0x87, 0x9c, 0xba, 0x08, 0x3a, 0x46, 0x63, 0x62, 0xb7, 0xc1, 0x86, 0x35,
    },
    {
        0x3a, 0xb8, 0x77, 0x41, 0x6e, 0x4e, 0x1d, 0xfc, 0xcb, 0x5c, 0xec, 0xdd, 0xf5, 0xfb, 0x42, 0x18,
        0x51, 0x1b, 0xe3, 0x5e, 0x23, 0x06, 0x9e, 0x86, 0x20, 0x0c, 0x79, 0x7e, 0xc7, 0xc5, 0xd7, 0xe3,
        0x04, 0x1e, 0xc7, 0x23, 0xec, 0x1e, 0xae, 0xbe, 0xf2, 0x22, 0xad, 0x60, 0xda, 0x93, 0xea, 0xe7,
        0xf0, 0x60, 0x48, 0xd1, 0x66, 0x34, 0xf9, 0xf0, 0xcb, 0xa9, 0x7a, 0x26, 0x50, 0x2a, 0x01, 0xd1,
    },
    {
        0x03, 0xc9, 0xb2, 0xd1, 0xea, 0x13, 0x6a, 0x0c, 0x5f, 0xe5, 0x01, 0x91, 0x32, 0xe6, 0x57, 0xf4,
        0x2d, 0xfa, 0x75, 0x8f, 0x74, 0xb0, 0xb3, 0xe3, 0x74, 0x0e, 0x51, 0xdc, 0x5f, 0x7f, 0xd6, 0x0d,
        0xdb, 0x00, 0x94, 0x7a, 0xa3, 0x2a, 0xff, 0x05, 0x20, 0xa9, 0x66, 0xfc, 0xe7, 0xdd, 0x2a, 0x81,
        0x8e, 0x6c, 0xd1, 0x48, 0xc3, 0x54, 0x8a, 0x9d, 0xfb, 0x6b, 0xdf, 0x61, 0xd6, 0xc4, 0xf3, 0xee,
    },
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

void _binExec(void* l_code_addr) __attribute__((noreturn));
void _binExec(void* l_code_addr)
{
    __asm__(
        "mov   r1, r0        \n"
        "ldr   r0, [r1, #4]  \n"
        "ldr   sp, [r1]      \n"
        "blx   r0");
    (void)l_code_addr;
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
    UG_PutString(1, SCREEN_HEIGHT - 9, "BOOTLOADER", false);
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
    UG_PutString(SCREEN_WIDTH / 2 - 3, SCREEN_HEIGHT - 9 * 2, "UPGRADING", false);
    UG_SendBuffer();
}

static void _render_hash(const char* title, const uint8_t* hash)
{
    uint8_t seconds = 10;
    char message[16];
    char hash_hex[2 * SHA256_DIGEST_LENGTH + 1];
    util_uint8_to_hex(hash, SHA256_DIGEST_LENGTH, hash_hex);
    char scratch = 0;
    for (uint8_t i = 1; i <= seconds; i++) {
        snprintf(message, sizeof(message), "HASH  (%2ds)", seconds - i);
        UG_ClearBuffer();
        UG_PutString(0, SCREEN_HEIGHT - 9, message, false);
        UG_PutString(0, SCREEN_HEIGHT - 9 * 2, title, false);

        scratch = hash_hex[16];
        hash_hex[16] = 0;
        UG_PutString(0, 0, hash_hex, false);
        hash_hex[16] = scratch;

        scratch = hash_hex[32];
        hash_hex[32] = 0;
        UG_PutString(0, 9, &hash_hex[16], false);
        hash_hex[32] = scratch;

        scratch = hash_hex[48];
        hash_hex[48] = 0;
        UG_PutString(0, 18, &hash_hex[32], false);
        hash_hex[48] = scratch;

        UG_PutString(0, 27, &hash_hex[48], false);

        UG_SendBuffer();
        delay_ms(1000);
    }
    _render_default_screen();
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
    _loading_ready = 0;

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
        _loading_ready = 1;
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
    _loading_ready = 1;
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
    _loading_ready = 0;
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
        _loading_ready = 1;
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
    _render_hash("FIRMWARE", hash);
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
        _render_hash("FIRMWARE", hash);
    }

    _hash_signing_keys(data, hash);
    memcpy(output + BOOT_OP_LEN + SHA256_DIGEST_LENGTH, hash, SHA256_DIGEST_LENGTH);

    if (input[1]) {
        _render_hash("SIGKEYS", hash);
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
    shared_data_t shared_data;
    memcpy(shared_data.bytes, (uint8_t*)(FLASH_SHARED_DATA_START), FLASH_SHARED_DATA_LEN);
    if (shared_data.fields.auto_enter == sectrue_u8) {
        shared_data.fields.auto_enter = secfalse_u8;
        _write_chunk(FLASH_SHARED_DATA_START, shared_data.bytes);
    }
    _reset_mcu();
}

static size_t _api_screen_rotate(uint8_t* output)
{
#if PLATFORM_BITBOX02 == 1
    if (_loading_ready) {
        return _report_status(OP_STATUS_ERR_LOAD_FLAG, output);
    }
    screen_rotate();
    _render_default_screen();
    return _report_status(OP_STATUS_OK, output);
#elif PLATFORM_BITBOXBASE == 1
    return _report_status(OP_STATUS_ERR_INVALID_CMD, output);
#endif
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
        _loading_ready = 0;
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
    shared_data_t shared_data;

    memcpy(bootdata.bytes, (uint8_t*)(FLASH_BOOTDATA_START), FLASH_BOOTDATA_LEN);
    memcpy(shared_data.bytes, (uint8_t*)(FLASH_SHARED_DATA_START), FLASH_SHARED_DATA_LEN);

    _check_init(&bootdata);

#if PLATFORM_BITBOX02 == 1
    if (shared_data.fields.upside_down) {
        screen_rotate();
    }
#endif

    if (shared_data.fields.auto_enter != sectrue_u8) {
#ifdef BOOTLOADER_DEVDEVICE
#if PLATFORM_BITBOXBASE == 1
        // We don't have touch on base dev bootloader yet
        _binary_exec();
#elif PLATFORM_BITBOX02 == 1
        if (!_devdevice_enter(_firmware_verified_jump(&bootdata, secfalse_u32))) {
            _binary_exec();
            /* no return */
        }
#endif
#else
        _firmware_verified_jump(&bootdata, sectrue_u32); // no return if firmware is valid
        _render_message("Firmware\ninvalid\n \nEntering bootloader", 3000);
#endif
    }

    // App not entered. Start USB API to receive boot commands
    _render_default_screen();
#if PLATFORM_BITBOX02 == 1
    if (usb_start(_api_setup) != ERR_NONE) {
        _render_message("Failed to initialize USB", 0);
    }
#elif PLATFORM_BITBOXBASE == 1
    usart_start();
    _api_setup();
#endif
}

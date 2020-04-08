#include "device.h"

#include <random.h>
#include <screen.h>
#include <workflow/confirm.h>

/*
 * Get the AAGUID (identifier of the type of device authenticating).
 */
void device_read_aaguid(uint8_t * dst) {
    /*
     * Hack:
     * For now, return the AAGUID of a YubiKey 5 (USB-A, No NFC) - ee882879-721c-4913-9775-3dfcce97072a
     * See https://support.yubico.com/support/solutions/articles/15000028710-yubikey-hardware-fido2-aaguids
     */
    const char yubikey_aaguid[16] = {0xee, 0x88, 0x28, 0x79, 0x72, 0x1c, 0x49, 0x13, 0x97, 0x75, 0x3d, 0xfc, 0xce, 0x97, 0x07, 0x2a};
    memcpy(dst, yubikey_aaguid, 16);
}

int ctap_generate_rng(uint8_t* dst, size_t num) {
    /* Generate bytes in chunks of 32 bytes into the destination buffer. */
    size_t n_32bytes_chunks = num / 32;
    for (size_t i = 0; i < n_32bytes_chunks; ++i) {
        random_32_bytes(dst + i * 32);
    }
    /* Generate the last N bytes as needed. */
    int bytes_missing = num % 32;
    if (bytes_missing) {
        int final_word_offset = num - bytes_missing;
        uint8_t last_bytes[32];
        random_32_bytes(last_bytes);
        memcpy(dst + final_word_offset, last_bytes, bytes_missing);
    }
    return 1;
}

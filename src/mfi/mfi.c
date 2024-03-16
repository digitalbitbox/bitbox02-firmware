#include "mfi/mfi.h"
#include "hal_delay.h"
#include "hal_i2c_m_sync.h"
#include "hardfault.h"
#include "util.h"
#include <stdbool.h>

extern struct i2c_m_sync_desc I2C_0;

// Default address is defined in docs. See chapter 73.5.3 Addressing, page 684 of Accessory
// Interface Specification
#define MFI_CHIP_DEFAULT_ADDR 0x10
#define MFI_CHIP_RETRIES 25
#define MFI_CHIP_RETRY_DELAY 10

static bool _send(uint8_t* txdata, int txlen)
{
    struct _i2c_m_msg packet;
    uint8_t retries = MFI_CHIP_RETRIES;
    int32_t r;

    packet.addr = MFI_CHIP_DEFAULT_ADDR;
    packet.len = (int32_t)txlen;
    packet.buffer = txdata;
    packet.flags = I2C_M_SEVEN | I2C_M_STOP;

    do {
        r = i2c_m_sync_transfer(&I2C_0, &packet);
        delay_ms(MFI_CHIP_RETRY_DELAY);
    } while (retries-- && r != I2C_OK);

    return (r == I2C_OK ? true : false);
}

static bool _recv(uint8_t* rxdata, int rxlen)
{
    struct _i2c_m_msg packet;
    uint8_t retries = MFI_CHIP_RETRIES;
    int32_t r;

    packet.addr = MFI_CHIP_DEFAULT_ADDR;
    packet.len = (int32_t)rxlen;
    packet.buffer = rxdata;
    packet.flags = I2C_M_SEVEN | I2C_M_RD | I2C_M_STOP;

    do {
        r = i2c_m_sync_transfer(&I2C_0, &packet);
        delay_ms(MFI_CHIP_RETRY_DELAY);
    } while (retries-- && r != I2C_OK);

    return (r == I2C_OK ? true : false);
}

// See chapter  73.5.7 Registers, page 686 of Accessory Interface Specification
#define MFI_DEVICE_VERSION 0x00
#define MFI_DEVICE_VERSION_LEN 1
#define MFI_AUTHENTICATION_REVISION 0x01
#define MFI_AUTHENTICATION_REVISION_LEN 1
#define MFI_AUTHENTICATION_PROTOCOL_MAJOR_VERSION 0x02
#define MFI_AUTHENTICATION_PROTOCOL_MAJOR_VERSION_LEN 1
#define MFI_AUTHENTICATION_PROTOCOL_MINOR_VERSION 0x03
#define MFI_AUTHENTICATION_PROTOCOL_MINOR_VERSION_LEN 1
#define MFI_DEVICE_ID 0x04
#define MFI_DEVICE_ID_LEN 4
#define MFI_ERROR_CODE 0x05
#define MFI_ERROR_CODE_LEN 1
#define MFI_AUTHENTICATION_CONTROL_AND_STATUS 0x10
#define MFI_AUTHENTICATION_CONTROL_AND_STATUS_LEN 1
#define MFI_CHALLENGE_RESPONSE_DATA_LENGTH 0x11
#define MFI_CHALLENGE_RESPONSE_DATA_LENGTH_LEN 2
#define MFI_CHALLENGE_RESPONSE_DATA 0x12
#define MFI_CHALLENGE_RESPONSE_DATA_LEN 64
#define MFI_CHALLENGE_DATA_LENGTH 0x20
#define MFI_CHALLENGE_DATA_LENGTH_LEN 2
#define MFI_CHALLENGE_DATA 0x21
#define MFI_CHALLENGE_DATA_LEN 32
#define MFI_ACCESSORY_CERTIFICATE_DATA_LENGTH 0x30
#define MFI_ACCESSORY_CERTIFICATE_DATA_LENGTH_LEN 2
#define MFI_ACCESSORY_CERTIFICATE_DATA1 0x31
#define MFI_ACCESSORY_CERTIFICATE_DATA1_LEN 128
#define MFI_ACCESSORY_CERTIFICATE_DATA2 0x32
#define MFI_ACCESSORY_CERTIFICATE_DATA2_LEN 128
#define MFI_ACCESSORY_CERTIFICATE_DATA3 0x33
#define MFI_ACCESSORY_CERTIFICATE_DATA3_LEN 128
#define MFI_ACCESSORY_CERTIFICATE_DATA4 0x34
#define MFI_ACCESSORY_CERTIFICATE_DATA4_LEN 128
#define MFI_ACCESSORY_CERTIFICATE_DATA5 0x35
#define MFI_ACCESSORY_CERTIFICATE_DATA5_LEN 128
#define MFI_SELF_TEST_STATUS 0x40
#define MFI_SELF_TEST_STATUS_LEN 1
#define MFI_DEVICE_CERTIFICATE_SERIAL_NUMBER 0x4E
#define MFI_DEVICE_CERTIFICATE_SERIAL_NUMBER_LEN 32
#define MFI_SLEEP 0x60
#define MFI_SLEEP_LEN 1

static uint8_t _reg_len(uint8_t reg)
{
    switch (reg) {
    case MFI_DEVICE_VERSION:
        return MFI_DEVICE_VERSION_LEN;
    case MFI_AUTHENTICATION_REVISION:
        return MFI_AUTHENTICATION_REVISION_LEN;
    case MFI_AUTHENTICATION_PROTOCOL_MAJOR_VERSION:
        return MFI_AUTHENTICATION_PROTOCOL_MAJOR_VERSION_LEN;
    case MFI_AUTHENTICATION_PROTOCOL_MINOR_VERSION:
        return MFI_AUTHENTICATION_PROTOCOL_MINOR_VERSION_LEN;
    case MFI_DEVICE_ID:
        return MFI_DEVICE_ID_LEN;
    case MFI_ERROR_CODE:
        return MFI_ERROR_CODE;
    case MFI_AUTHENTICATION_CONTROL_AND_STATUS:
        return MFI_AUTHENTICATION_CONTROL_AND_STATUS_LEN;
    case MFI_CHALLENGE_RESPONSE_DATA_LENGTH:
        return MFI_CHALLENGE_RESPONSE_DATA_LENGTH_LEN;
    case MFI_CHALLENGE_RESPONSE_DATA:
        return MFI_CHALLENGE_RESPONSE_DATA_LEN;
    case MFI_CHALLENGE_DATA_LENGTH:
        return MFI_CHALLENGE_DATA_LENGTH_LEN;
    case MFI_CHALLENGE_DATA:
        return MFI_CHALLENGE_DATA_LEN;
    case MFI_ACCESSORY_CERTIFICATE_DATA_LENGTH:
        return MFI_ACCESSORY_CERTIFICATE_DATA_LENGTH_LEN;
    case MFI_ACCESSORY_CERTIFICATE_DATA1:
        return MFI_ACCESSORY_CERTIFICATE_DATA1_LEN;
    case MFI_ACCESSORY_CERTIFICATE_DATA2:
        return MFI_ACCESSORY_CERTIFICATE_DATA2_LEN;
    case MFI_ACCESSORY_CERTIFICATE_DATA3:
        return MFI_ACCESSORY_CERTIFICATE_DATA3_LEN;
    case MFI_ACCESSORY_CERTIFICATE_DATA4:
        return MFI_ACCESSORY_CERTIFICATE_DATA4_LEN;
    case MFI_ACCESSORY_CERTIFICATE_DATA5:
        return MFI_ACCESSORY_CERTIFICATE_DATA5_LEN;
    case MFI_SELF_TEST_STATUS:
        return MFI_SELF_TEST_STATUS_LEN;
    case MFI_DEVICE_CERTIFICATE_SERIAL_NUMBER:
        return MFI_DEVICE_CERTIFICATE_SERIAL_NUMBER_LEN;
    default:
        return 0;
    }
}

// Returns number of bytes read
static uint8_t _read_reg(uint8_t reg, uint8_t* buf, int buflen)
{
    uint8_t reg_len = _reg_len(reg);
    if (buflen < _reg_len(reg)) {
        Abort("buflen to short");
    }

    _send(&reg, reg_len);
    _recv(buf, reg_len);
    return reg_len;
}

void init_mfi(void)
{
    delay_ms(1000);

    uint8_t value;
    _read_reg(MFI_DEVICE_VERSION, &value, 1);
    traceln("recieved 0x%02x, expecting 0x07", value);

    _read_reg(MFI_AUTHENTICATION_REVISION, &value, 1);
    traceln("recieved 0x%02x, expecting 0x01", value);
}

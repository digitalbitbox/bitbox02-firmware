#ifndef _IAP2_H_
#define _IAP2_H_

#include "usbdc.h"
#include <stdint.h>

enum iap2_cb_type { IAP2_CTRL_READ_CB, IAP2_CTRL_WRITE_CB, IAP2_BULK_READ_CB, IAP2_BULK_WRITE_CB };

typedef void (*iap2_ctrl_cb_t)(uint16_t);

int32_t iap2_req(
    struct usbdf_driver* drv,
    uint8_t ep,
    struct usb_req* req,
    enum usb_ctrl_stage stage);

int32_t iap2_init(void);
int32_t iap2_deinit(void);
bool iap2_is_enabled(void);
int32_t iap2_read(uint8_t* buf, uint32_t size);
int32_t iap2_write(const uint8_t* buf, uint32_t size);
int32_t iap2_register_callback(enum iap2_cb_type cb_type, FUNC_PTR func);

#endif

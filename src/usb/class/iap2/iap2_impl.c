
#include "iap2/iap2_impl.h"
#include "iap2/iap2.h"
#include "usbdc.h"

// forward declaration
static int32_t _request(uint8_t ep, struct usb_req* req, enum usb_ctrl_stage stage);

/**
 * Holds a pointer to the USB device core request handler callback.
 */
static struct usbdc_handler _request_handler = {NULL, (FUNC_PTR)_request};


/**
 * The USB device core request handler callback for the iap2 interface.
 */
static int32_t _request(uint8_t ep, struct usb_req* req, enum usb_ctrl_stage stage)
{
    return hid_req(&_func_driver, ep, req, stage);
}

int32_t iap2_impl_init(void) {
    iap2_init(&_func_driver, &_request_handler);
    return 0;
}

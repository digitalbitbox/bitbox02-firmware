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

#include "hid.h"
#include "usb_desc.h"
#if !defined(TESTING)
#include "usb_protocol.h"
#endif
#include "util.h"
#include <string.h>

/**
 * Enables the endpoints for the interface described in the given descriptor.
 * @param desc The descriptor contains information about the interface configuration.
 * @param[out] drv The driver is filled with meta-data about the interface endpoints.
 */
static int32_t _enable(struct usbd_descriptors* desc, struct usbdf_driver* drv)
{
    uint8_t *ifc, *ep, i;
    usb_iface_desc_t ifc_desc;
    usb_ep_desc_t ep_desc;

    struct hid_func_data* func_data = (struct hid_func_data*)(drv->func_data);

    ifc = desc->sod;
    if (NULL == ifc) {
        return ERR_NOT_FOUND;
    }

    ifc_desc.bInterfaceNumber = ifc[2];
    ifc_desc.bInterfaceClass = ifc[5];

    if (HID_CLASS == ifc_desc.bInterfaceClass) {
        if (func_data->func_iface == ifc_desc.bInterfaceNumber) { // Initialized
            return ERR_ALREADY_INITIALIZED;
        }
        if (func_data->func_iface != 0xFF) { // Occupied
            return ERR_NO_RESOURCE;
        }
        func_data->func_iface = ifc_desc.bInterfaceNumber;
    } else { // Not supported by this function driver
        return ERR_NOT_FOUND;
    }

    // Install HID descriptor
    func_data->hid_desc = usb_find_desc(usb_desc_next(desc->sod), desc->eod, USB_DT_HID);

    // Install endpoints
    for (i = 0; i < 2; i++) {
        ep = usb_find_ep_desc(usb_desc_next(desc->sod), desc->eod);
        desc->sod = ep;
        if (NULL != ep) {
            ep_desc.bEndpointAddress = ep[2];
            // traceln("Found endpoint 0x%02x for interface",ep_desc.bEndpointAddress);
            ep_desc.bmAttributes = ep[3];
            ep_desc.wMaxPacketSize = usb_get_u16(ep + 4);
            if (usb_d_ep_init(
                    ep_desc.bEndpointAddress, ep_desc.bmAttributes, ep_desc.wMaxPacketSize)) {
                return ERR_NOT_INITIALIZED;
            }
            if (ep_desc.bEndpointAddress & USB_EP_DIR_IN) {
                func_data->func_ep_in = ep_desc.bEndpointAddress;
                usb_d_ep_enable(func_data->func_ep_in);
            } else {
                func_data->func_ep_out = ep_desc.bEndpointAddress;
                usb_d_ep_enable(func_data->func_ep_out);
            }
        } else {
            return ERR_NOT_FOUND;
        }
    }

    // Installed
    func_data->protocol = 1;
    func_data->enabled = true;

    if (func_data->hid_status_callback) {
        func_data->hid_status_callback();
    }
    return ERR_NONE;
}

/**
 * Disables the endpoints for the interface described in the given descriptor.
 * @param[in] desc The descriptor contains information about the interface configuration.
 * @param[out] drv The driver is reset to a state that indicates that the interface is disabled.
 */
static int32_t _disable(const struct usbd_descriptors* desc, struct usbdf_driver* drv)
{
    struct hid_func_data* func_data = (struct hid_func_data*)(drv->func_data);

    usb_iface_desc_t ifc_desc;

    if (desc) {
        ifc_desc.bInterfaceClass = desc->sod[5];
        if (ifc_desc.bInterfaceClass != HID_CLASS) {
            return ERR_NOT_FOUND;
        }
    }

    if (func_data->func_iface != 0xFF) {
        func_data->func_iface = 0xFF;
    }

    if (func_data->func_ep_in != 0xFF) {
        usb_d_ep_deinit(func_data->func_ep_in);
        func_data->func_ep_in = 0xFF;
    }

    if (func_data->func_ep_out != 0xFF) {
        usb_d_ep_deinit(func_data->func_ep_out);
        func_data->func_ep_out = 0xFF;
    }

    func_data->enabled = false;
    return ERR_NONE;
}

/**
 * The control callback that is called to enable or disable the interface.
 * @param[out] drv The driver is reset to a state that indicates that the interface is disabled.
 * @param[in] ctrl The control flag which indicates which action to take.
 * @param[in] param Additional parameters passed to the callback.
 */
static int32_t _ctrl(struct usbdf_driver* drv, enum usbdf_control ctrl, void* param)
{
    switch (ctrl) {
    case USBDF_ENABLE:
        return _enable((struct usbd_descriptors*)param, drv);

    case USBDF_DISABLE:
        return _disable((const struct usbd_descriptors*)param, drv);

    case USBDF_GET_IFACE:
        return ERR_UNSUPPORTED_OP;

    default:
        return ERR_INVALID_ARG;
    }
}

/**
 * Returns the descriptor for the given USB driver and endpoint.
 * @param[out] drv The driver is reset to a state that indicates that the interface is disabled.
 * @param[in] req The usb request.
 */
static int32_t _get_descriptor(struct usbdf_driver* drv, uint8_t ep, struct usb_req* req)
{
    struct hid_func_data* func_data = (struct hid_func_data*)(drv->func_data);
    switch (req->V.wValue >> 8) {
    case USB_DT_HID:
        return usbdc_xfer(ep, func_data->hid_desc, func_data->hid_desc[0], false);
    case USB_DT_HID_REPORT:
        return usbdc_xfer(ep, func_data->report_desc, func_data->report_desc_len, false);
    default:
        return ERR_INVALID_ARG;
    }
}

/**
 * The USB device core request handler callback.
 * @param[out] drv The driver is reset to a state that indicates that the interface is disabled.
 * @param[in] ep The endpoint.
 * @param[in] req The usb request.
 * @param[in] stage The usb control stage.
 */
int32_t hid_req(
    struct usbdf_driver* drv,
    uint8_t ep,
    struct usb_req* req,
    enum usb_ctrl_stage stage)
{
    struct hid_func_data* func_data = (struct hid_func_data*)(drv->func_data);
    uint8_t* ctrl_buf = usbdc_get_ctrl_buffer();
    uint16_t len = req->L.wLength;

    if ((0x81 == req->bmRequestType) && (0x06 == req->bRequest) &&
        (req->I.wIndex == func_data->func_iface)) {
        return _get_descriptor(drv, ep, req);
    }
    if (0x01 != ((req->bmRequestType >> 5) & 0x03)) { // class request
        return ERR_NOT_FOUND;
    }
    if (req->I.wIndex == func_data->func_iface) {
        if (req->bmRequestType & USB_EP_DIR_IN) {
            return ERR_INVALID_ARG;
        }
        switch (req->bRequest) {
        case 0x03: /* Get Protocol */
            return usbdc_xfer(ep, &func_data->protocol, 1, 0);
        case 0x0B: /* Set Protocol */
            func_data->protocol = req->V.wValue;
            return usbdc_xfer(ep, NULL, 0, 0);
        case USB_REQ_HID_SET_REPORT:
            if (USB_SETUP_STAGE == stage) {
                return usbdc_xfer(ep, ctrl_buf, len, false);
            } else {
                if (NULL != func_data->hid_set_report) {
                    func_data->hid_set_report(ctrl_buf, len);
                }
                return ERR_NONE;
            }
        default:
            return ERR_INVALID_ARG;
        }
    } else {
        return ERR_NOT_FOUND;
    }
}

/**
 * Initializes a HID interface.
 * @param[in] func_driver The driver data that contains the function data.
 * @param[in] hid_req_h The USB device core request handler.
 */
int32_t hid_init(struct usbdf_driver* func_driver, struct usbdc_handler* hid_req_h)
{
    if (usbdc_get_state() > USBD_S_POWER) {
        return ERR_DENIED;
    }

    func_driver->ctrl = _ctrl;

    usbdc_register_function(func_driver);
    usbdc_register_handler(USBDC_HDL_REQ, hid_req_h);

    return ERR_NONE;
}

/**
 * Deinitializes the function driver.
 * @param[in] func_driver The driver data that contains the function data.
 */
int32_t hid_deinit(struct usbdf_driver* func_driver, struct usbdc_handler* hid_req_h)
{
    if (usbdc_get_state() > USBD_S_POWER) {
        return ERR_DENIED;
    }

    func_driver->ctrl = NULL;
    func_driver->func_data = NULL;

    usbdc_unregister_function(func_driver);
    usbdc_unregister_handler(USBDC_HDL_REQ, hid_req_h);
    return ERR_NONE;
}

/**
 * Returns the endpoint for the given direction.
 * @param[in] func_driver The driver data that contains the function data.
 * @param[in] dir The direction of the endpoint:
 *            dir == 1: outgoing (host -> BitBox)
 *            dir == 0: incoming (BitBox -> host)
 */
uint8_t hid_get_ep(struct usbdf_driver* func_driver, uint8_t dir)
{
    if (dir == DIR_OUT) {
        return ((struct hid_func_data*)func_driver->func_data)->func_ep_out;
    }
    return ((struct hid_func_data*)func_driver->func_data)->func_ep_in;
}

/**
 * Checks whether the interface is enabled.
 * @param[in] func_driver The driver data that contains the function data.
 */
bool hid_is_enabled(struct hid_func_data* func_data)
{
    return func_data->enabled;
}

/**
 * Sets the buffer address for the incoming endpoint.
 * @param[IN] func_data The interface meta data.
 * @param[OUT] buf The address of the buffer to which we write.
 * @param[IN] size The size of the buffer.
 */
int32_t hid_read(struct hid_func_data* func_data, uint8_t* buf, uint32_t size)
{
    if (!hid_is_enabled(func_data)) {
        return ERR_DENIED;
    }
    struct usb_d_ep_status status;
    usb_d_ep_get_status(func_data->func_ep_in, &status);
    while (status.state != USB_EP_S_IDLE) {
        usb_d_ep_get_status(func_data->func_ep_in, &status);
    }
    return usbdc_xfer(func_data->func_ep_out, buf, size, false);
}

/**
 * Sets the buffer address for the outgoing endpoint.
 * @param[IN] func_data The interface meta data.
 * @param[IN] buf The address of the buffer from which we read.
 * @param[IN] size The size of the buffer.
 */
int32_t hid_write(struct hid_func_data* func_data, const uint8_t* buf, uint32_t size)
{
    if (!hid_is_enabled(func_data)) {
        return ERR_DENIED;
    }
    struct usb_d_ep_status status;
    usb_d_ep_get_status(func_data->func_ep_in, &status);
    while (status.state != USB_EP_S_IDLE) {
        usb_d_ep_get_status(func_data->func_ep_in, &status);
    }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    // usbdc_xfer is not supposed to modify "buf" in this direction so we can cast it to non-const
    return usbdc_xfer(func_data->func_ep_in, (uint8_t*)buf, size, false);
#pragma GCC diagnostic pop
}

/**
 * Registers a callback for a given transfer type.
 * @param[IN] func_data The interface meta data.
 * @param[in] trans_type The transfer type for which the callback should be registered,
 *            which can be READ, WRITE or SET_REPORT.
 * @param[in] func The function that is registered as a callback.
 */
int32_t hid_register_callback(
    struct hid_func_data* func_data,
    enum hid_trans_type trans_type,
    FUNC_PTR func)
{
    if (!hid_is_enabled(func_data)) {
        return ERR_DENIED;
    }
    int32_t err = ERR_NONE;
    switch (trans_type) {
    case HID_CB_READ:
        err = usb_d_ep_register_callback(func_data->func_ep_out, USB_D_EP_CB_XFER, func);
        break;
    case HID_CB_WRITE:
        err = usb_d_ep_register_callback(func_data->func_ep_in, USB_D_EP_CB_XFER, func);
        break;
    case HID_CB_SET_REPORT:
        func_data->hid_set_report = (hid_set_report_t)func;
        break;
    default:
        return ERR_INVALID_ARG;
    }

    return err;
}

#include "iap2/iap2.h"
#include "usb/usb_protocol_iap2.h"
#include "util.h"
#include "vendor/usb_protocol_vendor.h"
#include <stdint.h>

struct iap2_func_data {
    // Store the interface number. Used to check if the device support already is initialized
    uint8_t func_iface;

    // Store in endpoint addr
    uint8_t func_ep_in;

    // Store out endpoint addr
    uint8_t func_ep_out;

    // Enabled or disabled
    bool enabled;
};

static iap2_ctrl_cb_t _iap2_ctrl_rd = NULL;
static iap2_ctrl_cb_t _iap2_ctrl_wr = NULL;
static FUNC_PTR _iap2_bulk_rd = NULL;
static FUNC_PTR _iap2_bulk_wr = NULL;

/**
 * IAP2 Device function instance
 */
static struct usbdf_driver _iap2;

/**
 * IAP2 Device function data instance
 */
static struct iap2_func_data _iap2_func_data;

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

    struct iap2_func_data* func_data = (struct iap2_func_data*)(drv->func_data);

    ifc = desc->sod;
    if (NULL == ifc) {
        return ERR_NOT_FOUND;
    }

    ifc_desc.bInterfaceNumber = ifc[2];
    ifc_desc.bInterfaceClass = ifc[5];
    ifc_desc.bInterfaceSubClass = ifc[6];

    // Check if it is the vendor interface class and iap2 sub class
    if (VENDOR_CLASS == ifc_desc.bInterfaceClass && MFI_SUBCLASS == ifc_desc.bInterfaceSubClass) {
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
    traceln("%s", "enable");

    // Install endpoints
    for (i = 0; i < 2; i++) {
        ep = usb_find_ep_desc(usb_desc_next(desc->sod), desc->eod);
        desc->sod = ep;
        if (NULL != ep) {
            ep_desc.bEndpointAddress = ep[2];
            traceln("Found endpoint 0x%02x for interface", ep_desc.bEndpointAddress);
            ep_desc.bmAttributes = ep[3];
            ep_desc.wMaxPacketSize = usb_get_u16(ep + 4);
            if (usb_d_ep_init(
                    ep_desc.bEndpointAddress, ep_desc.bmAttributes, ep_desc.wMaxPacketSize)) {
                return ERR_NOT_INITIALIZED;
            }
            if (ep_desc.bEndpointAddress & USB_EP_DIR_IN) {
                func_data->func_ep_in = ep_desc.bEndpointAddress;
                if (NULL != _iap2_bulk_wr) {
                    usb_d_ep_register_callback(
                        func_data->func_ep_in, USB_D_EP_CB_XFER, _iap2_bulk_wr);
                }
            } else {
                func_data->func_ep_out = ep_desc.bEndpointAddress;
                if (NULL != _iap2_bulk_rd) {
                    usb_d_ep_register_callback(
                        func_data->func_ep_out, USB_D_EP_CB_XFER, _iap2_bulk_rd);
                }
            }
            usb_d_ep_enable(ep_desc.bEndpointAddress);
        } else {
            traceln("%s", "ep not found");
            return ERR_NOT_FOUND;
        }
    }

    // Installed
    func_data->enabled = true;

    return ERR_NONE;
}

/**
 * Disables the endpoints for the interface described in the given descriptor.
 * @param[in] desc The descriptor contains information about the interface configuration.
 * @param[out] drv The driver is reset to a state that indicates that the interface is disabled.
 */
static int32_t _disable(const struct usbd_descriptors* desc, struct usbdf_driver* drv)
{
    struct iap2_func_data* func_data = (struct iap2_func_data*)(drv->func_data);

    usb_iface_desc_t ifc_desc;

    if (desc) {
        ifc_desc.bInterfaceClass = desc->sod[5];
        ifc_desc.bInterfaceSubClass = desc->sod[6];
        if (ifc_desc.bInterfaceClass != VENDOR_CLASS ||
            ifc_desc.bInterfaceSubClass != MFI_SUBCLASS) {
            return ERR_NOT_FOUND;
        }
    }
    traceln("%s", "disable");

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
        traceln("%s", "get iface");
        return ERR_UNSUPPORTED_OP;

    default:
        return ERR_INVALID_ARG;
    }
}

static int _req_handler(uint8_t ep, struct usb_req* req, enum usb_ctrl_stage stage)
{
    (void)ep;

    if (0x02 != ((req->bmRequestType >> 5) & 0x03)) { /* vendor request */
        return ERR_NOT_FOUND;
    }

    if (req->I.wIndex == _iap2_func_data.func_iface && 0 == req->bRequest) {
        if (USB_EP_DIR_IN == (0x80 & req->bmRequestType)) {
            if (NULL != _iap2_ctrl_wr && USB_SETUP_STAGE == stage) {
                _iap2_ctrl_wr(req->L.wLength);
            }
            return ERR_NONE;
        } else {
            if (0 != req->L.wLength && NULL != _iap2_ctrl_rd && USB_SETUP_STAGE == stage) {
                _iap2_ctrl_rd(req->L.wLength);
            }
            return ERR_NONE;
        }
    } else {
        return ERR_NOT_FOUND;
    }
}

static struct usbdc_handler _iap2_req_handler = {NULL, (FUNC_PTR)_req_handler};

int32_t iap2_init(void)
{
    if (usbdc_get_state() > USBD_S_POWER) {
        return ERR_DENIED;
    }

    _iap2.ctrl = _ctrl;
    _iap2.func_data = &_iap2_func_data;

    usbdc_register_function(&_iap2);
    usbdc_register_handler(USBDC_HDL_REQ, &_iap2_req_handler);

    return ERR_NONE;
}

int32_t iap2_deinit(void)
{
    if (usbdc_get_state() > USBD_S_POWER) {
        return ERR_DENIED;
    }

    _iap2.ctrl = NULL;
    _iap2.func_data = NULL;

    usbdc_unregister_function(&_iap2);
    usbdc_unregister_handler(USBDC_HDL_REQ, &_iap2_req_handler);

    return ERR_NONE;
}

bool iap2_is_enabled(void)
{
    return _iap2_func_data.enabled;
}

int32_t iap2_read(uint8_t* buf, uint32_t size)
{
    if (!iap2_is_enabled()) {
        return ERR_DENIED;
    }
    return usbdc_xfer(_iap2_func_data.func_ep_out, buf, size, false);
}

int32_t iap2_write(const uint8_t* buf, uint32_t size)
{
    if (!iap2_is_enabled()) {
        return ERR_DENIED;
    }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    return usbdc_xfer(_iap2_func_data.func_ep_in, (uint8_t*)buf, size, false);
#pragma GCC diagnostic pop
}

/**
 * \brief USB HID Generic Function Register Callback
 */
int32_t iap2_register_callback(enum iap2_cb_type cb_type, FUNC_PTR func)
{
    switch (cb_type) {
    case IAP2_CTRL_READ_CB:
        _iap2_ctrl_rd = (iap2_ctrl_cb_t)func;
        break;
    case IAP2_CTRL_WRITE_CB:
        _iap2_ctrl_wr = (iap2_ctrl_cb_t)func;
        break;
    case IAP2_BULK_READ_CB:
        _iap2_bulk_rd = func;
        break;
    case IAP2_BULK_WRITE_CB:
        _iap2_bulk_wr = func;
        break;
    default:
        return ERR_INVALID_ARG;
    }

    return ERR_NONE;
}

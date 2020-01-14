#ifndef __USB_DESC_BYTES_H
#define __USB_DESC_BYTES_H

#include <version.h>

#if APP_U2F == 1
#define USB_DESC_U2F_EP_IN (3 | USB_EP_DIR_IN)
#define USB_DESC_U2F_EP_OUT (4 | USB_EP_DIR_OUT)
#define USB_DESC_IFACE_NUM_U2F 1
#define USB_DESC_NUM_IFACES 2
#else
#define USB_DESC_NUM_IFACES 1
#endif

#if APP_U2F == 1
#define USB_DESC_IFACE_U2F                                                  \
    9, /* iface.bLength */                                                  \
        0x04, /* iface.bDescriptorType: INTERFACE */                        \
        USB_DESC_IFACE_NUM_U2F, /* iface.bInterfaceNumber */                \
        0x00, /* iface.bAlternateSetting */                                 \
        0x02, /* iface.bNumEndpoints */                                     \
        HID_CLASS, /* iface.bInterfaceClass */                              \
        USB_SUBCLASS_NO, /* iface.bInterfaceSubClass */                     \
        USB_PROTOCOL_NO, /* iface.bInterfaceProtocol */                     \
        0x00, /* iface.iInterface */                                        \
        9, /* hid.bLength */                                                \
        USB_DT_HID, /* hid.bDescriptorType: HID */                          \
        USB_DESC_LE16(USB_HID_BDC_V1_11), /* hid.bcdHID */                  \
        0x00, /* hid.bCountryCode */                                        \
        0x01, /* hid.bNumDescriptors */                                     \
        0x22, /* hid.bRDescriptorType */                                    \
        USB_DESC_LE16(USB_DESC_U2F_REPORT_LEN), /* hid.wDescriptorLength */ \
        7, /* ep_in.bLength */                                              \
        0x05, /* ep_in.bDescriptorType: ENDPOINT */                         \
        USB_DESC_U2F_EP_IN, /* ep_in.bEndpointAddress */                    \
        0x03, /* ep_in.bmAttributes */                                      \
        USB_DESC_LE16(USB_DESC_HID_EP_SIZE), /* ep_in.wMaxPacketSize */     \
        4, /* ep_in.bInterval */                                            \
        7, /* ep_out.bLength */                                             \
        0x05, /* ep_out.bDescriptorType: ENDPOINT */                        \
        USB_DESC_U2F_EP_OUT, /* ep_out.bEndpointAddress */                  \
        0x03, /* ep_out.bmAttributes */                                     \
        USB_DESC_LE16(USB_DESC_HID_EP_SIZE), /* ep_out.wMaxPacketSize */    \
        4 /* ep_out.bInterval */
#endif

#if defined(BOOTLOADER)
#if PRODUCT_BITBOX_BTCONLY == 1
#define USB_DESC_IPRODUCT_STR_DESC                                                              \
    38, /* bLength */                                                                           \
        0x03, /* bDescriptorType */                                                             \
        'b', 0, 'b', 0, '0', 0, '2', 0, 'b', 0, 't', 0, 'c', 0, '-', 0, 'b', 0, 'o', 0, 'o', 0, \
        't', 0, 'l', 0, 'o', 0, 'a', 0, 'd', 0, 'e', 0, 'r', 0,
#else
#define USB_DESC_IPRODUCT_STR_DESC                                                              \
    32, /* bLength */                                                                           \
        0x03, /* bDescriptorType */                                                             \
        'b', 0, 'b', 0, '0', 0, '2', 0, '-', 0, 'b', 0, 'o', 0, 'o', 0, 't', 0, 'l', 0, 'o', 0, \
        'a', 0, 'd', 0, 'e', 0, 'r', 0,
#endif
#elif FACTORYSETUP == 1
#define USB_DESC_IPRODUCT_STR_DESC                                                              \
    26, /* bLength */                                                                           \
        0x03, /* bDescriptorType */                                                             \
        'b', 0, 'b', 0, '0', 0, '2', 0, '-', 0, 'f', 0, 'a', 0, 'c', 0, 't', 0, 'o', 0, 'r', 0, \
        'y', 0,
#elif PRODUCT_BITBOX_BTCONLY == 1
#define USB_DESC_IPRODUCT_STR_DESC  \
    24, /* bLength */               \
        0x03, /* bDescriptorType */ \
        'B', 0, 'i', 0, 't', 0, 'B', 0, 'o', 0, 'x', 0, '0', 0, '2', 0, 'B', 0, 'T', 0, 'C', 0,
#else
#define USB_DESC_IPRODUCT_STR_DESC  \
    18, /* bLength */               \
        0x03, /* bDescriptorType */ \
        'B', 0, 'i', 0, 't', 0, 'B', 0, 'o', 0, 'x', 0, '0', 0, '2', 0,
#endif

#if defined(BOOTLOADER_DEVDEVICE) && defined(BOOTLOADER_VERSION_HAS_METADATA)
#define BOOTLOADER_VERSION_APPEND_LEN 4
#define BOOTLOADER_VERSION_APPEND_W16 '.', 0, 'd', 0, 'e', 0, 'v', 0,
#elif defined(BOOTLOADER_DEVDEVICE)
#define BOOTLOADER_VERSION_APPEND_LEN 4
#define BOOTLOADER_VERSION_APPEND_W16 '+', 0, 'd', 0, 'e', 0, 'v', 0,
#else
#define BOOTLOADER_VERSION_APPEND_LEN 0
#define BOOTLOADER_VERSION_APPEND_W16
#endif

#ifdef BOOTLOADER
#define USB_DESC_ISERIALNUM_STR_DESC                                                    \
    (2 + BOOTLOADER_VERSION_LEN * 2 + BOOTLOADER_VERSION_APPEND_LEN * 2), /* bLength */ \
        0x03, /* bDescriptorType */                                                     \
        BOOTLOADER_VERSION_W16 BOOTLOADER_VERSION_APPEND_W16
#else
#define USB_DESC_ISERIALNUM_STR_DESC                    \
    (2 + DIGITAL_BITBOX_VERSION_LEN * 2), /* bLength */ \
        0x03, /* bDescriptorType */                     \
        DIGITAL_BITBOX_VERSION_W16
#endif

#define USB_STR_DESC            \
    USB_DESC_LANGID_DESC        \
    USB_DESC_IMANUFACT_STR_DESC \
    USB_DESC_IPRODUCT_STR_DESC  \
    USB_DESC_ISERIALNUM_STR_DESC

#if APP_U2F == 1
#define USB_DESC_IFACE_NUM_U2F 1
#define USB_DESC_NUM_IFACES 2
#else
#define USB_DESC_NUM_IFACES 1
#endif

#define USB_DESC_IFACE_NUM_HWW 0
#define USB_DESC_IFACE_LEN 32
#define USB_DESC_CONFIG_LEN 9
#define USB_DESC_WTOTALLEN (USB_DESC_CONFIG_LEN + USB_DESC_IFACE_LEN * USB_DESC_NUM_IFACES)

#define USB_DESC_CONFIG                                       \
    USB_DESC_CONFIG_LEN, /* bLength */                        \
        0x02, /* bDescriptorType: CONFIGURATION */            \
        USB_DESC_LE16(USB_DESC_WTOTALLEN), /* wTotalLength */ \
        USB_DESC_NUM_IFACES, /* bNumInterfaces */             \
        USB_DESC_BCONFIGVAL, /* bConfigurationValue */        \
        0x00, /* iConfiguration */                            \
        USB_DESC_BMATTRI, /* bmAttributes */                  \
        USB_DESC_BMAXPOWER /* bMaxPower */

#if APP_U2F == 1
#define USB_DESC_IFACE_U2F                                                  \
    9, /* iface.bLength */                                                  \
        0x04, /* iface.bDescriptorType: INTERFACE */                        \
        USB_DESC_IFACE_NUM_U2F, /* iface.bInterfaceNumber */                \
        0x00, /* iface.bAlternateSetting */                                 \
        0x02, /* iface.bNumEndpoints */                                     \
        HID_CLASS, /* iface.bInterfaceClass */                              \
        USB_SUBCLASS_NO, /* iface.bInterfaceSubClass */                     \
        USB_PROTOCOL_NO, /* iface.bInterfaceProtocol */                     \
        0x00, /* iface.iInterface */                                        \
        9, /* hid.bLength */                                                \
        USB_DT_HID, /* hid.bDescriptorType: HID */                          \
        USB_DESC_LE16(USB_HID_BDC_V1_11), /* hid.bcdHID */                  \
        0x00, /* hid.bCountryCode */                                        \
        0x01, /* hid.bNumDescriptors */                                     \
        0x22, /* hid.bRDescriptorType */                                    \
        USB_DESC_LE16(USB_DESC_U2F_REPORT_LEN), /* hid.wDescriptorLength */ \
        7, /* ep_in.bLength */                                              \
        0x05, /* ep_in.bDescriptorType: ENDPOINT */                         \
        USB_DESC_U2F_EP_IN, /* ep_in.bEndpointAddress */                    \
        0x03, /* ep_in.bmAttributes */                                      \
        USB_DESC_LE16(USB_DESC_HID_EP_SIZE), /* ep_in.wMaxPacketSize */     \
        4, /* ep_in.bInterval */                                            \
        7, /* ep_out.bLength */                                             \
        0x05, /* ep_out.bDescriptorType: ENDPOINT */                        \
        USB_DESC_U2F_EP_OUT, /* ep_out.bEndpointAddress */                  \
        0x03, /* ep_out.bmAttributes */                                     \
        USB_DESC_LE16(USB_DESC_HID_EP_SIZE), /* ep_out.wMaxPacketSize */    \
        4 /* ep_out.bInterval */
#endif

#define USB_DEV_DESC                                       \
    18, /* bLength */                                      \
        0x01, /* bDescriptorType: DEVICE */                \
        USB_DESC_LE16(USB_DESC_BCDUSB), /* bcdUSB */       \
        USB_CLASS_NO, /* bDeviceClass */                   \
        USB_SUBCLASS_NO, /* bDeviceSubClass */             \
        USB_PROTOCOL_NO, /* bDeviceProtocol */             \
        USB_DESC_BMAXPKSZ0, /* bMaxPacketSize0 */          \
        USB_DESC_LE16(USB_DESC_IDVENDER), /* idVendor */   \
        USB_DESC_LE16(USB_DESC_IDPRODUCT), /* idProduct */ \
        USB_DESC_LE16(USB_DESC_BCDDEVICE), /* bcdDevice */ \
        USB_DESC_IMANUFACT, /* iManufacturer */            \
        USB_DESC_IPRODUCT, /* iProduct */                  \
        USB_DESC_ISERIALNUM, /* iSerialNumber */           \
        USB_DESC_BNUMCONFIG /* bNumConfigurations */

//  ** If add an interface, adjust USB_DESC_WTOTALLEN **
// TODO: USB_DESC_D_MAX_EP_N doesn't exist, but there is CONF_USB_D_NUM_EP_SP
// (= supported endpoints) - is that the one that needs to change?
//  ** If add more endpoints, adjust USB_DESC_D_MAX_EP_N  **
#if APP_U2F == 0
#define USB_DESC_FS USB_DEV_DESC, USB_DESC_CONFIG, USB_DESC_IFACE_HWW, USB_STR_DESC
#else
#define USB_DESC_FS \
    USB_DEV_DESC, USB_DESC_CONFIG, USB_DESC_IFACE_HWW, USB_DESC_IFACE_U2F, USB_STR_DESC
#endif // APP_U2F

#endif // __USB_DESC_BYTES_H

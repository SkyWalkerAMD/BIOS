/* Generated from modules.json: exact eight files only. */
#include <stdint.h>
struct module_entry {const char *name,*file;uint64_t bytes;const char *params;};
static const struct module_entry module_list[]={
{"usb_common","usb-common.ko",32407,""},
{"usbcore","usbcore.ko",919591,"autosuspend=-1"},
{"xhci_hcd","xhci-hcd.ko",776335,""},
{"xhci_pci","xhci-pci.ko",52847,""},
{"scsi_common","scsi_common.ko",18175,""},
{"scsi_mod","scsi_mod.ko",625927,"scan=sync"},
{"sg","sg.ko",114223,""},
{"usb_storage","usb-storage.ko",224943,"delay_use=0"}
};

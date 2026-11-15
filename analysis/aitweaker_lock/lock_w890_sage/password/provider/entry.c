#include "provider.h"
/* Deliberate closed entry for the current linkable component. This image is
 * not an installer: the native W890 owner/initial-page binding is still under
 * independent review. No load options can enable it; no Boot/Runtime Service
 * or hardware method is called. Tests invoke actual retained PE functions
 * with modeled host callbacks. Replace this unit only after the native binding
 * and recovery contracts are implemented, not by changing a compatibility flag. */
ES EA efi_main(void *image,void *system_table){(void)image;(void)system_table;return ERR(3);}

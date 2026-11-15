/* Test carrier only. Booting this PE performs no collection or service calls. */
#include "efi_min.h"
ES EA efi_main(HANDLE image,ST *system){(void)image;(void)system;return ERR(3);}

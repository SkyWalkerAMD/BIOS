#include "runtime.h"
/* Native W890 observer is not linked yet. No load option or test callback can
 * activate this entry. The lab uses a separately built, TCG-guarded carrier. */
ES EA efi_main(HANDLE image,ST *st){(void)image;(void)st;return ERR(3);}

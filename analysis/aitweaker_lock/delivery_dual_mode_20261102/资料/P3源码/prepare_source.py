"""Retain the reviewed P2 inventory routines; replace only its output path."""
from pathlib import Path
import hashlib,json
OUT=Path(__file__).resolve().parent
old=OUT.parent/'probe_p2/source/probe.c'
text=old.read_text(encoding='utf-8')
prefix=text.split('static int save_log(HANDLE image) {',1)[0]
prefix=prefix[prefix.index('#include "efi_min.h"'):]
prefix=prefix.replace('#include "profiles.h"','#include "profiles.h"\n#include "kvm.h"')
prefix='\n'.join(line for line in prefix.split('\n') if not line.startswith(('static GUID fs_guid=','static const char marker[]=')))
entry=r'''
/* No SimpleFileSystem or RuntimeServices are called. Display-only log export. */
ES EA efi_main(HANDLE image,ST *system_table) {
    (void)image;st=system_table;
    if(!st||!st->bs)return ERR(2);
    if(!st->bs->allocate_pool||!st->bs->free_pool||!st->bs->handle_protocol||
       !st->bs->locate_handles||!st->bs->locate_protocol||!st->bs->stall)return ERR(3);
    loglen=0;truncated=0;warnings=0;known_modules=0;hii_valid=0;images=0;image_count=0;
    screen("Ai Tweaker P3 KVM - collecting read-only inventory...\r\n");
    emit("AITWEAKER-PROBE-P3-KVM\r\nRead-only interface inventory. No password values collected.\r\n");
    typedef ES (EA *WD)(UN,uint64_t,UN,C16 *);
    ES watchdog=st->bs->set_watchdog?((WD)st->bs->set_watchdog)(0,0,0,0):ERR(3);
    if(FAILED(watchdog))warning("Watchdog.disable",watchdog);
    else status("Watchdog.disable",watchdog);
    inspect_images();inspect_protocols();inspect_hii();
    if(images)release(images);
    images=0;image_count=0;
    if(!hii_valid)warnings++;
    emit("Collection.warnings=");number(warnings);emit("\r\n");
    emit(warnings?"COLLECTION_STATUS=PARTIAL\r\n":"COLLECTION_STATUS=COMPLETE\r\n");
    emit("PROBE_COMPLETE\r\n");
    if(truncated){screen("Log exceeded 64 KiB. Incomplete inventory NOT exported.\r\n");return ERR(9);}
    return kvm_present(st,logbuf,loglen,warnings);
}
'''
(OUT/'source/probe.c').write_text('/* P3 KVM: same P2 inventory, display-only export; not a password lock. */\n'+prefix+entry,encoding='utf-8')
(OUT/'inventory_provenance.json').write_text(json.dumps({'p2_source_sha256':hashlib.sha256(old.read_bytes()).hexdigest(),
 'retained':'inspect_images, inspect_protocols, inspect_hii and their helpers, unchanged',
 'replaced':'file log saving replaced by QR/text pages; disables the UEFI boot watchdog for screenshot capture'},indent=2),encoding='utf-8')

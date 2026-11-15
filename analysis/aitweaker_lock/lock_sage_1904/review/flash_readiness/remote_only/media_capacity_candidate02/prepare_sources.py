"""Stage existing local references and frozen P3 sources; no network operations."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
PRIOR=HERE.parent/'media_usb_inventory01'
REF=HERE/'source/reference';REF.mkdir(parents=True,exist_ok=True)
rows=[]
for source in [PRIOR/'source/reference/UsbIo.h',
               HERE.parent/'media_writeback_client01/review_legacy_data/reference/UefiScsiLib.c',
               HERE.parent/'media_writeback_client01/review_legacy_data/reference/Scsi.h']:
    target=REF/source.name;target.write_bytes(source.read_bytes())
    rows.append({'file':str(target.relative_to(HERE)), 'source':str(source.relative_to(ROOT)),
                 'sha256':hashlib.sha256(target.read_bytes()).hexdigest()})
for name in ['efi_min.h','kvm.h','kvm.c','probe_core.h','probe_core.c','vendor/qrcodegen.c','vendor/qrcodegen.h','compat/string.h','compat/stdlib.h','compat/assert.h']:
    source=PRIOR/'source/p3'/name;target=HERE/'source/p3'/name;target.parent.mkdir(parents=True,exist_ok=True)
    data=source.read_bytes()
    if name=='kvm.c':
        data=data.replace(b'USB INVENTORY 01 - KVM LOG',b'CAPACITY 02 - KVM LOG')
        data=data.replace(b'Existing USB protocol inventory',b'Bounded SCSI capacity observation')
        data=data.replace(b'READ ONLY USB METADATA',b'READ CAPACITY ONLY - NO BLOCK DATA')
        data=data.replace(b'PARTIAL INVENTORY - DIAGNOSTIC ONLY',b'CAPACITY NOT CONFIRMED - SEE LOG')
        data=data.replace(b'USB inventory ended. No storage or firmware writes.',b'Capacity observation ended. No storage or firmware writes.')
    target.write_bytes(data)
    rows.append({'file':str(target.relative_to(HERE)),'source':str(source.relative_to(ROOT)),'original_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                 'sha256':hashlib.sha256(data).hexdigest(),'change':'display labels only' if name=='kvm.c' else 'byte-identical'})
report={'scope':'Local source staging only. No network/BMC/target access.',
        'network_download_attempt':'Prior public header download was blocked, then automatic approval rejected escalation as outside offline task scope. No download workaround used. ABI definitions use official UEFI text already independently obtained and supplied by parent, with provenance in abi_review.json.',
        'files':rows}
(HERE/'sources.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps({'staged':len(rows)}))

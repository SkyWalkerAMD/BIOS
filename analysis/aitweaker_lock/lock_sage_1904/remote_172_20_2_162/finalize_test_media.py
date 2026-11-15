"""Bind local simulation results to the exact SAGE maintenance ISO releases."""
from pathlib import Path
import datetime,hashlib,json
HERE=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf8'))
send=read(HERE.parent/'navigation/sendform_mapping.json')
result={'status':'LOCAL_VALIDATION_PASS_READY_FOR_AUTHORIZED_NO_FLASH_TEST','generated_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'target':'ASUS Pro WS W790E-SAGE SE BIOS 1904','hardware_password_tested':False,'firmware_flashing_performed':False,'production_driver_sha256':sha(HERE.parent/'driver/build/AiTweakerLock1904.efi'),'sendform_evidence_sha256':sha(HERE.parent/'navigation/sendform_mapping.json'),'media':{}}
for kind,name in [('preflight','AiTweaker-SAGE-P4-Preflight.iso'),('ram_test','AiTweaker-SAGE-P5-RAM-Test.iso')]:
    out=HERE/kind;b=read(out/'build.json');v=read(out/'vm_validation.json')
    assert b['production_driver_sha256']==result['production_driver_sha256']==b['production_relinked_sha256']
    assert b['efi_sha256']==sha(out/'BOOTX64.EFI')==v['efi_sha256']
    assert b['iso_sha256']==sha(out/name)==v.get('iso_sha256',v.get('iso_sha256_before'))
    assert v['passed']
    assert sha(out/'source-snapshot.zip')==b['source_archive_sha256']
    for rel,digest in b['source_hashes'].items():assert sha(out/'source'/rel)==digest
    item={'iso':str(out/name),'iso_sha256':b['iso_sha256'],'efi_sha256':b['efi_sha256'],'build_manifest_sha256':sha(out/'build.json'),'vm_validation_sha256':sha(out/'vm_validation.json'),'source_archive_sha256':b['source_archive_sha256'],'scope':v.get('scope','Read-only inventory QR/console byte equivalence, transport controls and non-target board identification on OVMF.')}
    if kind=='ram_test':
        safety=read(out/'safety_validation.json');assert safety['passed'] and safety['efi_sha256']==b['efi_sha256']
        item['compiled_safety_cases']=len(safety['cases']);item['safety_validation_sha256']=sha(out/'safety_validation.json')
        item['menus']={'1':'Main 0x2713','2':'Ai Tweaker 0x2714','3':'My Favorites 0x2712','4':'ASUS Profile 0x272c','5':'OC Presets 0x2eb8','6':'Memory Presets 0x2eba','Q':'QR diagnostic log','R':'QR then cold reset after ESC','S':'QR then shutdown after ESC'}
    result['media'][kind]=item
(HERE/'test_media_delivery.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
print(json.dumps(result,indent=2))

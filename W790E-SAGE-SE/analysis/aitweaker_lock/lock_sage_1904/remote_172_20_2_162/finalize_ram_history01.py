"""Bind exact HISTORY01 media to local tests without changing any baseline artifacts."""
from pathlib import Path
import datetime,hashlib,json
HERE=Path(__file__).resolve().parent;OUT=HERE/'ram_test_history01'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf8'))
b=read(OUT/'build.json');v=read(OUT/'vm_validation.json');s=read(OUT/'safety_validation.json')
target=OUT/'AiTweaker-SAGE-P5-History01-RAM-Test.iso'
assert v['passed'] and s['passed'] and len(s['cases'])==4
assert b['iso_sha256']==v['iso_sha256']==sha(target)
assert b['efi_sha256']==v['efi_sha256']==s['efi_sha256']==sha(OUT/'BOOTX64.EFI')
assert s['source_sha256']==sha(OUT/'source/ram_lock_test.c')
assert b['production_driver_sha256']==b['production_relinked_sha256']==sha(HERE.parent/'driver/build/AiTweakerLock1904.efi')
assert b['candidate_driver_sha256']==b['candidate_relinked_sha256']==sha(OUT/'candidate-relinked.efi')
for name,digest in b['source_hashes'].items():assert sha(OUT/'source'/name)==digest
assert sha(OUT/'source-snapshot.zip')==b['source_archive_sha256']
for name,digest in b['baseline_ram_media_hashes_unchanged'].items():assert sha(HERE/'ram_test'/name)==digest
for name,digest in b['linked_objects'].items():
    assert sha(OUT/('candidate_objects' if name=='platform' else 'production_objects')/(name+'.obj'))==digest
    if name!='platform':assert digest==b['production_objects'][name]
history=read(OUT/'source/history_candidate/history_candidate_result.json')
assert history['candidate_driver_sha256']==b['candidate_driver_sha256'] and history['status']=='PASS_CANDIDATE_ONLY'
report={'status':'LOCAL_VALIDATION_PASS_CANDIDATE_RAM_ONLY','generated_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'target':'ASUS Pro WS W790E-SAGE SE BIOS 1904','build_identifier':'HISTORY01','iso':str(target),'iso_bytes':target.stat().st_size,'iso_sha256':b['iso_sha256'],'efi_sha256':b['efi_sha256'],'production_baseline_sha256':b['production_driver_sha256'],'candidate_driver_sha256':b['candidate_driver_sha256'],'only_production_object_changed':'platform','all_other_linked_production_objects_unchanged':True,'baseline_media_unchanged':True,'core_and_write_denial_harness_unchanged_except_build_label':True,'ram_only_credential_storage':True,'new_hardware_test_complete':False,'firmware_flash_or_permanent_deployment':False,'local_smoke':{'ovmf_unsupported_board_qr_and_exit':'PASS','actual_compiled_cleanup_and_write_denial_cases':len(s['cases']),'included_candidate_history_check_count':history['checks']},'evidence_sha256':{name:sha(OUT/name) for name in ['build.json','vm_validation.json','safety_validation.json','source-snapshot.zip']},'limits':['OVMF does not execute ASUS visual Setup or reproduce the actual hardware history problem.','ResetSystem, firmware CRC and memory-patch callbacks are controlled stubs in the four safety cases.','This is the candidate RAM test application, not a replacement CAP, BIOS firmware release or persistent lock installation.']}
(OUT/'delivery.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');print(json.dumps(report,indent=2))

"""Bounded semantic review of root-assembled physical P04 evidence.

QR independent transport verification belongs to uefi_lab; this report does not
pretend that rereading the assembled text independently decodes the PNG pages.
"""
from pathlib import Path
import hashlib,json,re
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[3]
HW=CASE/'remote_172_20_2_162/hardware-native13-prerequisite04-1793704790283'
log=HW/'hardware-log.txt';raw=log.read_bytes();text=raw.decode('ascii')
assert len(raw)==12125 and hashlib.sha256(raw).hexdigest()=='2af56b709f22663d502de32f4e7b22a4e49f256ad6f57deea1168b1af4958c91'
assert text.startswith('AITWK-P3-KVM\r\nSAGE_NATIVE13_PREREQUISITE04_OWNED_ONLY\r\n')
assert text.endswith('SAGE_NATIVE13_PREREQUISITE04_END\r\n')
assert text.count('NO_FLASH_NO_HOOKS_NO_VARIABLE_WRITES_NO_DISK_WRITES')==2
assert 'LOG_COMPLETE=YES' in text and 'LOG_OVERFLOW=NO' in text and 'WARN 'not in text
patches=re.findall(r'PATCH (\S+) RVA=([0-9A-F]{16}) ORIGINAL_OK\r\nPATCH_PAGE ([0-9A-F]{16})[^\r]*\r\nCPU_PTE \3 P=1 RW=1 NX=0 US=0 LEVEL=2 PATIDX=0 IDENTITY=YES',text)
assert len(patches)==12 and len({x[2]for x in patches})==8
assert 'CPU.CR0=0000000080010013' in text and 'CPU.CR4=0000000000000668'in text
for line in ['OwnedCodeReturn=000000004E313304','PASS original target permission snapshots unchanged','PASS AMITSE original text unchanged after owned fixture','PASS Setup original text unchanged after owned fixture','RetainedOwnedPages=0000000000000000','EBSObserved=0000000000000000','ResidentHoldRequired=0000000000000000','LaunchOuterReturnRVA=000000000000960C']:
 assert line in text,line
assert text.count('PASS owned allocation cycle complete')==2 and text.count('PASS owned original semantic permissions restored')==2
OUT=HERE/'ram_transaction05';OUT.mkdir(exist_ok=True)
r={'status':'PHYSICAL_STANDARD_OWNED_PERMISSION_PREREQUISITES_OBSERVED_NOT_INSTALLER_OR_UI_ACCEPTANCE','input_log':str(log),'input_sha256':hashlib.sha256(raw).hexdigest(),'input_bytes':len(raw),'independent_raw_QR_decode_claimed':False,'patch_sites':[{'name':n,'rva':'0x'+r.lstrip('0'),'page':'0x'+p.lstrip('0')}for n,r,p in patches],'observed_pages':8,'observed_permissions':{'identity':True,'present':True,'supervisor':True,'writable':True,'executable':True,'leaf_level':2,'CR0_WP_enabled':True,'CR4':'0x668'},'standard_service_observation':{'CPU_Arch_SetMemoryAttributes_available':True,'memory_attribute_protocol_available':False,'owned_code_cycle_passed':True,'owned_data_cycle_passed':True,'owned_fixed_code_return':'0x4e313304','original_code_and_page_semantics_unchanged':True},'transaction_consequences':['Reacquire and revalidate current module identities/map/effective permissions each boot; addresses from this log are evidence, not reusable constants.','Do not request any foreign-page permission change. This candidate may proceed only when all exact target pages are already supervisor RWX with the expected cache semantics.','Allocate guard/code/state exclusively through standard services; set only owned allocations RO+X / RW+NX using the tested service and verify actual effective translations and foreign-page invariants.','RaiseTPL/RestoreTPL surround only bounded byte validation/copy/readback and CPU serialization. Do not invoke AllocatePages/LoadImage/CPU SetMemoryAttributes or variable/HII services while at TPL_HIGH_LEVEL.','The small detour transaction assumes conformant UEFI BSP-only browser execution. TPL does not stop APs/SMM; no arbitrary-concurrency guarantee is inferred.','Both observed original boot-option paths are valid evidence: EP3 return2D7D and P04 F8 return960C, each through the pinned AMITSE9F78 -> A8E6 -> Core88AF chain. This is not a proof of absent older browser frames.','No return address can legitimately remain inside these overwritten prologue windows: they contain complete non-branch/non-call instructions. The one replaced CALL retains its original return address. This bounded fact, rather than stage7/app0, informs suspended-caller safety.','Permanent cold-boot guard installation and vendor signature acceptance remain separate unresolved release issues.'],'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
(OUT/'physical_prerequisite_review.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'status':r['status'],'path':str(OUT/'physical_prerequisite_review.json'),'pages':8,'sites':12}))

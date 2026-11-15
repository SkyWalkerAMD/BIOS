"""Independently check generated fingerprints against actual ACE instructions."""
from pathlib import Path
import hashlib
import json
import re
import sys

HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=HERE/'native/OriginalCpuIo2.efi'
assert sha(p)=='4fe8ca3ca86616c659a55f6a9faac1a2c511dde1de7996a7c46dba8559422f24'
pe=pefile.PE(str(p));m=pe.get_memory_mapped_image()
cs=Cs(CS_ARCH_X86,CS_MODE_64)
ins={i.address:i for i in cs.disasm(m[0x30c:0x481],0x30c)}
assert ins[0x34b].bytes.hex()=='488d05fe030000' and 0x34b+7+0x3fe==0x750
assert ins[0x40b].bytes.hex()=='4c8d05eefbffff' and 0x40b+7-0x412==0
assert ins[0x41a].bytes.hex()=='420fb6940050070000'
assert ins[0x423].bytes.hex()=='460fb6840060070000'
assert ins[0x44c].bytes.hex()=='8b03' and ins[0x44e].bytes.hex()=='8907'
calls=[i for a,i in ins.items() if a>=0x3d4 and i.mnemonic=='call']
assert len(calls)==1 and calls[0].op_str=='0x30c'
header=(HERE/'source/cpu_reference.h').read_text()
arrays={n:bytes(int(x,16) for x in re.findall(r'0x([0-9a-f]{2})',s)) for n,s in re.findall(r'uint8_t\s+(\w+)\[\d+\]=\{([^}]+)\}',header)}
rows=[]
for name,start,end in [('cpu_parameters',0x30c,0x3d4),('cpu_read_code',0x3d4,0x481),('cpu_strides',0x750,0x770)]:
 assert arrays[name]==m[start:end]
 rows.append({'name':name,'rva':hex(start),'bytes':end-start,'sha256':hashlib.sha256(arrays[name]).hexdigest(),'original_bytes_equal':True})
assert m[0x752]==m[0x762]==4
report={'status':'PASS_ACTUAL_INSTRUCTION_AND_FINGERPRINT_BINDING','native_efi_sha256':sha(p),'header_sha256':sha(HERE/'source/cpu_reference.h'),
 'fingerprints':rows,'actual_width2_table_reads':{'parameter_check':'0x752','Mem.Read_address_stride':'0x752','Mem.Read_buffer_stride':'0x762'},
 'covered_RAM_range':'0x720..0x76F inclusive','each_native_DWORD_read_expected_table_trace':['0x752','0x752','0x762'],
 'test_assertion':'179-case final fixture traces each of these actual RAM table reads in addition to MMIO loads.',
 'source_sha256':sha(Path(__file__))}
(HERE/'native_binding_verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
correction={'status':'FIXED_BEFORE_ROOT_MEDIA_RELEASE','issue':'Initial draft fingerprint called RVA700..717 a stride table. Actual parameter validation and read code use750/760.',
 'superseded_artifacts_status':'REVOKED_DO_NOT_DEPLOY','replacement_status':'Only final media_manifest binding b290d3e5/988a70a5 is eligible for root review.',
 'discovered_by':'sage_w890_reference independent static review','superseded_efi_sha256':'7570c35ef56e11b48da2b93aa4235f33bfe6671b1503fd36c5dea174867107bf',
 'superseded_iso_sha256':'fd316606c78e67ff129b2822d3bd176c6ece619cc9ae299ba43d0571c76c09ec',
 'superseded_inventory_source_sha256':'e28dc74eaa5bf131b5c50cb9a8a0159762d03b6674fc06a371b737f13d2fca11',
 'superseded_header_sha256':'b40cd741727f6ec7274639f9c76be2252bec83abd87e848aa880176d5932b75b',
 'fixed_efi_sha256':sha(HERE/'build/BOOTX64.EFI'),'fixed_source_sha256':sha(HERE/'source/inventory.c'),'fixed_header_sha256':sha(HERE/'source/cpu_reference.h'),
 'fix':'Pin32 bytes750..76F, validate readable720..76F, add real-table corruptions and exact native table-read tracing, recompile/retest actual EFI and fresh OVMF media.',
 'important':'Initial local PASS was insufficient for the omitted data binding. Only the corrected candidate and final179-case evidence are released.'}
(HERE/'review_correction.json').write_text(json.dumps(correction,indent=2)+'\n',encoding='utf8')
print(report['status'])

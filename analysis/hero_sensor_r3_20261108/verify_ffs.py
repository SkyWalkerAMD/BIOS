"""Check the R3 section stream with the exact target HERO DxeCore validator.
No modified firmware is loaded or dispatched. Unicorn stops before calls.
"""
from pathlib import Path
import sys,hashlib,json,struct,uuid
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
core_path=ROOT/'analysis/hero_ipmi_r2_followup_20261108/dispatch-audit/DxeCore.efi'
core=core_path.read_bytes();assert hashlib.sha256(core).hexdigest()=='5a4a8d96f7de6f714fd4d91e5579d701e4e4a6394b7dc46968d6cb1f07f8efcf'
image=pefile.PE(data=core).get_memory_mapped_image()
def execute(body):
    u=Uc(UC_ARCH_X86,UC_MODE_64);u.mem_map(0x100000,0x20000);u.mem_write(0x100000,image)
    u.mem_map(0x200000,0x2000);u.mem_map(0x300000,((len(body)+4095)//4096+1)*4096);u.mem_write(0x300000,body)
    rsp=0x201000;u.reg_write(UC_X86_REG_RSP,rsp);u.mem_write(rsp+0x48,struct.pack('<Q',len(body)));u.reg_write(UC_X86_REG_R11,0x300000)
    found=[]
    def hook(uc,address,size,_):
        if address in (0x10e636,0x10e62a):found.append(address==0x10e636);uc.emu_stop()
    u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x10e5c4,0x10e63a,count=100000)
    assert len(found)==1;return found[0]
raw=(OUT/'HeroIpmiCoreR3.ffs').read_bytes();body=raw[24:]
assert str(uuid.UUID(bytes_le=raw[:16]))=='89924765-f984-4ad3-839b-51fdce378d88'
assert int.from_bytes(raw[20:23],'little')==len(raw) and raw[18:20]==b'\x07\x00'
header=bytearray(raw[:24]);header[17]=header[23]=0;assert sum(header)%256==0
sections=[];at=0
while at<len(body):
    n=int.from_bytes(body[at:at+3],'little');kind=body[at+3];assert n>=4 and at+n<=len(body)
    sections.append({'offset':at,'bytes':n,'type':kind});end=at+n
    if end==len(body):break
    at=(end+3)&~3;assert not any(body[end:at])
assert end==len(body) and [s['type'] for s in sections]==[0x13,0x10,0x15]
part=sections[1];binary=body[part['offset']+4:part['offset']+part['bytes']]
assert binary==(OUT/'USB/EFI/HERO/HeroIpmiR3.efi').read_bytes()
assert execute(body) and not execute(body+b'\0\0')
p=pefile.PE(data=binary);assert p.OPTIONAL_HEADER.Subsystem==11 and p.FILE_HEADER.Machine==0x8664
assert not hasattr(p,'DIRECTORY_ENTRY_IMPORT') and p.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size and p.verify_checksum()
result={'passed':True,'ffs_sha256':hashlib.sha256(raw).hexdigest(),'driver_sha256':hashlib.sha256(binary).hexdigest(),
 'final_section_ends_exactly_at_stream_end':True,'sections':sections,'native_HERO_DxeCore_accepts':True,'negative_reintroduced_two_byte_tail_rejected':True,
 'validator_rva':['E5C4','E636','E62A'],'source_DxeCore_sha256':hashlib.sha256(core).hexdigest(),
 'PE':{'machine':p.FILE_HEADER.Machine,'subsystem':p.OPTIONAL_HEADER.Subsystem,'file_alignment':p.OPTIONAL_HEADER.FileAlignment,
 'section_alignment':p.OPTIONAL_HEADER.SectionAlignment,'size_of_image':p.OPTIONAL_HEADER.SizeOfImage,'entry_rva':p.OPTIONAL_HEADER.AddressOfEntryPoint,'relocations':p.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size},
 'limitation':'This proves section-stream validation and PE structural checks, not target firmware dispatch or flash acceptance.'}
(OUT/'ffs-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

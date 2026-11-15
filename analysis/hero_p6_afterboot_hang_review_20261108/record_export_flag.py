"""Scope-limited static flag/entry-event cross-reference on the exact HII PE."""
from pathlib import Path
import hashlib,json,struct,sys,uuid
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import capstone,pefile
raw=(OUT/'HiiDatabase.efi').read_bytes()
assert hashlib.sha256(raw).hexdigest()=='eb6c77a2a4a41e9434490eb52611239d39a65e47a28db6aed07a26ee5767003b'
pe=pefile.PE(data=raw);mapped=pe.get_memory_mapped_image();cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
direct=[];nearby=[];code_coverage=[]
for section in pe.sections:
 if not section.Characteristics&0x20:continue
 data=mapped[section.VirtualAddress:section.VirtualAddress+section.Misc_VirtualSize]
 items=list(cs.disasm(data,section.VirtualAddress))
 code_coverage.append({'section':section.Name.decode('ascii').rstrip('\0'),'start':hex(section.VirtualAddress),'bytes':len(data),'decoded_bytes':sum(i.size for i in items)})
 for i in items:
  for op in i.operands:
   if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
    target=i.address+i.size+op.mem.disp
    if 0x16fc0<=target<0x17000:
     row={'rva':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str,'target':hex(target),'access':op.access,'operand_bytes':op.size}
     nearby.append(row)
     if target<=0x16fe0<target+op.size:direct.append(row)
relocations=[]
for block in pe.DIRECTORY_ENTRY_BASERELOC:
 for entry in block.entries:
  if entry.type==10:
   value=struct.unpack_from('<Q',mapped,entry.rva)[0]
   if 0x16fc0<=value<0x17000:relocations.append({'slot':hex(entry.rva),'target':hex(value)})
event=uuid.UUID(bytes_le=mapped[0x16600:0x16610])
result={
 'subject_sha256':hashlib.sha256(raw).hexdigest(),
 'entry_event':{'call_rva':'0x3cf','event_guid_rva':'0x16600','event_guid':str(event),'notify_tpl':16,'notify_function_rva':'0x4a8','notify_bytes':mapped[0x4a8:0x4ab].hex(),'notify_disassembly':[i.mnemonic+' '+i.op_str for i in cs.disasm(mapped[0x4a8:0x4ab],0x4a8)]},
 'flag':{'rva':'0x16fe0','initial_value':mapped[0x16fe0],'direct_rip_references':direct,'nearby_relocation_pointer_values':relocations},
 'code_coverage':code_coverage,'nearby_rip_references':nearby,
 'conclusion':'Exact entry callback is a no-op. Decoded direct references to export flag are reads only; no direct setter or relocated pointer to it was found. Do not infer the upstream optional ReadyToBoot setter is enabled here. Runtime flag value was not sampled.',
 'limits':'Static cross-reference is not a proof against every computed alias or externally modified memory. No hardware read, target execution or firmware modification performed.'}
assert mapped[0x4a8:0x4ab]==b'\xc2\x00\x00'
assert not any(r['access']&capstone.CS_AC_WRITE for r in direct)
assert not relocations
(OUT/'export-flag-evidence.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'event_guid':str(event),'callback':'ret 0','flag_direct_reads':len(direct),'direct_writes':0,'nearby_pointer_relocations':0,'coverage':code_coverage}))

"""Bounded original-byte inspection for the post-TX05 blackout review.

No production source, image, or frozen report is modified.
"""
from pathlib import Path
import hashlib,json,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[7]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import capstone,pefile
PATH=HERE.parent.parent/'boot_context/AMITSE.original.efi'
p=pefile.PE(str(PATH));b=p.get_memory_mapped_image()
assert hashlib.sha256(PATH.read_bytes()).hexdigest()=='531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1'
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
ranges={
 'sendform_complete':(0x20ee4,0x214d8),
 'native_events':(0x5a04,0x5b90),
 'native_page_renderer':(0x16a90,0x16c20),
 'native_frame_input':(0x15320,0x15900),
 'native_control_base':(0x12730,0x12c80),
 'native_frame_initialize':(0x148e4,0x14a80),
 'native_frame_render':(0x14a80,0x15320),
 'native_page_initialize':(0x16720,0x16a90),
 'native_static_text_injection':(0x171d4,0x17238),
 'native_frame_populate':(0x33634,0x33824),
 'native_static_control':(0x16354,0x165e4),
 'native_subtitle_class':(0x1bd14,0x1c474),
 'native_generic_control':(0x187b0,0x18ac0),
 'native_base_control_initialize':(0x1cafc,0x1cc20),
 'native_memory_helpers':(0x360,0x3a0),
 'native_zero_allocator':(0x3f714,0x3f780),
 'native_control_condition':(0x31da4,0x32000),
 'native_string_lookup':(0x33da4,0x33ee0),
 'native_subtitle_token':(0x1ccc4,0x1cce8),
 'native_exit_notifications':(0x6320,0x6400),
 'native_gui_teardown':(0x122c,0x13a0),
}
out=[]
for name,(start,end)in ranges.items():
 decoded=[]
 for i in cs.disasm(b[start:end],start):
  targets=[]
  for op in i.operands:
   if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
    targets.append(i.address+i.size+op.mem.disp)
  decoded.append(f'{i.address:08X} {i.bytes.hex():32} {i.mnemonic} {i.op_str}'+(' ; '+','.join(f'RVA {x:X}'for x in targets)if targets else''))
 (HERE/(name+'.asm.txt')).write_text('\n'.join(decoded)+'\n')
 out.append({'name':name,'start':hex(start),'end':hex(end),'range_sha256':hashlib.sha256(b[start:end]).hexdigest()})
# Data tables which contain the exact page-render or frame-input method.
tables=[]
for target in [0x16a90,0x15320]:
 for pos in range(0x6ab40,0x93958-7,8):
  if struct.unpack_from('<Q',b,pos)[0]==target:
   lo=max(0x6ab40,pos-32);hi=min(0x93958,pos+64)
   tables.append({'target':hex(target),'at':hex(pos),'qwords':[[hex(at),hex(struct.unpack_from('<Q',b,at)[0])]for at in range(lo,hi,8)]})
(HERE/'native_range_index.json').write_text(json.dumps({'original_file_sha256':hashlib.sha256(PATH.read_bytes()).hexdigest(),'ranges':out,'vtables':tables},indent=2)+'\n')
print(json.dumps({'ranges':len(out),'vtables':tables}))

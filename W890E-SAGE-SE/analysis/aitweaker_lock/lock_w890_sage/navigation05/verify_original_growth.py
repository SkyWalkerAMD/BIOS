"""Preserve original W890 growth behavior: native callsites and FC40/59B50.
Only Boot Services AllocatePool/CopyMem/FreePool are modeled. Stop immediately
before the first record write; never execute the observed out-of-range write.
"""
from pathlib import Path
import json,hashlib
from verify_navigation import VM,TSE,DATA,ns,Q,I
from unicorn.x86_const import *
H=Path(__file__).resolve().parent
cases=[]
for entry,stop,reg_old,reg_count in [(0x19598,0x195f5,UC_X86_REG_RBX,UC_X86_REG_EAX),(0x1ba65,0x1bacd,UC_X86_REG_RDI,UC_X86_REG_ECX)]:
 v=VM();v.pages();old=DATA+0x28000;old_bytes=24*32;v.w(old,bytes([0x6b])*old_bytes);v.allocations[old]=old_bytes
 v.w(TSE+0xafde8,Q(old));v.w(TSE+0xafde0,I(24));v.w(TSE+0xafe00,I(24))
 sp=ns['STACK']+0x1f0000;v.w(sp,bytes(0x400));v.u.reg_write(UC_X86_REG_RSP,sp);v.u.reg_write(reg_old,old);v.u.reg_write(reg_count,24);v.u.reg_write(UC_X86_REG_RSI,2);v.u.reg_write(UC_X86_REG_RBP,DATA+0x2c000);v.u.reg_write(UC_X86_REG_R13,1)
 v.w(0x70001000,b''.join(Q((i<<30)|0x83)for i in range(8)))
 v.target_stop=TSE+stop
 try:v.u.emu_start(TSE+entry,0,count=1000000)
 except Exception:
  print('exception RIP',hex(v.u.reg_read(UC_X86_REG_RIP)),'alloc',v.alloc_trace,'calls',v.call_trace);raise
 assert v.u.reg_read(UC_X86_REG_RIP)==TSE+stop
 p,n=v.alloc_trace[-1];dest=v.u.reg_read(UC_X86_REG_R9)+v.u.reg_read(reg_old)
 assert n==44 and v.copy_trace==[(p,old,24)]and v.free_trace==[old]and dest==p+24*32 and dest+8>p+n
 cases.append({'entry_rva':entry,'stop_before_write_rva':stop,'native_calls':v.call_trace,'old_requested_bytes':old_bytes,'AllocatePool_requested_bytes':n,'CopyMem_bytes':v.copy_trace[0][2],'freed_old_exactly_once':True,'next_record_offset':dest-p,'next_write_size':8,'out_of_requested_extent':True,'scope':'original native instructions from explicitly modeled growth-branch state; ordinary UI reachability has not been proved; exact Boot Services requested extent; allocator may round its backing pages but does not promise extra object bytes'})
 print(hex(entry),'AllocatePool',n,'CopyMem',v.copy_trace[0][2],'next write offset',dest-p,flush=True)
report={'original_sha256':hashlib.sha256((H.parent/'navigation/modules/AMITSE.efi').read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'status':'TWO_ORIGINAL_BOUNDARIES_REPRODUCED_NO_OOB_WRITE_EXECUTED','cases':cases}
(H/'build/original_growth_evidence.json').write_text(json.dumps(report,indent=2)+'\n')

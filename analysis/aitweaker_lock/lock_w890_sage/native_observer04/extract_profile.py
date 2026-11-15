"""Extract only exact shipped bytes; do not alter frozen predecessor evidence."""
from pathlib import Path
import sys, json, hashlib
ROOT=Path(__file__).resolve().parents[4]
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone

def main():
    source=HERE.parent/'navigation/modules'
    pe=pefile.PE(str(source/'AMITSE.efi')); image=pe.get_memory_mapped_image()
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64); md.detail=True
    out=[]
    for name,rva in [('cold_entry',0x6480),('browser_loop',0x190f4),('send_form',0x36da4)]:
        span=0; ins=[]; relative=False
        for i in md.disasm(image[rva:rva+48],rva):
            ins.append({'rva':i.address,'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
            span+=i.size
            relative|=any(o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP for o in i.operands)
            relative|=i.group(capstone.CS_GRP_JUMP) or i.group(capstone.CS_GRP_CALL)
            if span>=14:break
        assert not relative
        out.append({'role':name,'rva':rva,'bytes':span,'hex':image[rva:rva+span].hex(),'pc_relative':False,'resume_rva':rva+span,'instructions':ins})
    calls=[]
    for s in pe.sections:
        if s.Name.rstrip(b'\0')!=b'.text':continue
        # Capstone skipdata keeps alignment after isolated data, confirming sites with actual CALL bytes.
        md.skipdata=True
        for i in md.disasm(image[s.VirtualAddress:s.VirtualAddress+s.Misc_VirtualSize],s.VirtualAddress):
            if i.mnemonic=='call' and len(i.bytes)==5 and i.bytes[0]==0xe8:
                target=i.address+5+int.from_bytes(i.bytes[1:],'little',signed=True)
                if target in (0x190f4,0x36da4,0x3e700):calls.append({'rva':i.address,'return_rva':i.address+5,'target':target,'hex':i.bytes.hex()})
    report={'original_file_sha256':hashlib.sha256((source/'AMITSE.efi').read_bytes()).hexdigest(),'windows':out,'direct_call_sites':calls,'limits':'Static calls only; runtime ownership requires private wrapper entry and current module/native/HII revalidation. cold_entry is firmware-load-only, never BootOverride retrofit.'}
    (HERE/'hook_windows.json').write_text(json.dumps(report,indent=2)+'\n')
    text=['/* Extracted exact W890 0603 bytes. See hook_windows.json. */']
    for w in out:
        text.append('static const uint8_t original_'+w['role']+'[]={'+','.join('0x'+w['hex'][i:i+2] for i in range(0,len(w['hex']),2))+'};')
    loop=[x['return_rva'] for x in calls if x['target']==0x190f4]
    text.append('static const uint32_t loop_callers[]={'+','.join(hex(x) for x in loop)+'};')
    (HERE/'profile_windows.h').write_text('\n'.join(text)+'\n')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()

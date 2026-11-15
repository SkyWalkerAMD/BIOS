"""Read-only indexes for reverse-engineering the exact OEM binaries."""
import bisect
import csv
import json
import re
import struct
import sys
import uuid
from inspect_setup import OUT, ROOT, TAGS, get_module
import capstone
import pefile


def build(tag):
    _,_,data=get_module(tag,'AMITSE')
    pe=pefile.PE(data=data)
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    md.detail=True
    md.skipdata=True
    refs, starts={}, {pe.OPTIONAL_HEADER.AddressOfEntryPoint}
    for sec in pe.sections:
        if not sec.Characteristics & 0x20000000:
            continue
        pad=True
        for ins in md.disasm(sec.get_data(),sec.VirtualAddress):
            if pad and ins.mnemonic!='int3':
                starts.add(ins.address)
            pad=ins.mnemonic=='int3'
            if not ins.id:
                continue
            for op in ins.operands:
                if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
                    target=ins.address+ins.size+op.mem.disp
                elif ins.mnemonic in ('call','jmp') and op.type==capstone.x86.X86_OP_IMM:
                    target=op.imm
                    if ins.mnemonic=='call':starts.add(target)
                else:
                    continue
                refs.setdefault(str(target),[]).append({'rva':ins.address,'instruction':ins.mnemonic+' '+ins.op_str})
    guids=[]
    for row in csv.reader((ROOT/'analysis/uefitool_guids.csv').read_text(encoding='utf-8-sig').splitlines()):
        if len(row)!=2:
            continue
        try:g=uuid.UUID(row[0])
        except ValueError:continue
        for match in re.finditer(re.escape(g.bytes_le),data):
            offset=match.start()
            guids.append({'guid':str(g),'name':row[1],'offset':offset,'rva':pe.get_rva_from_offset(offset)})
    result={'starts':sorted(starts),'refs':refs,'guids':guids}
    (OUT/tag/'AMITSE_code_index.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    print(tag,'functions',len(starts),'reference targets',len(refs),'named GUIDs',len(guids))


def main():
    if sys.argv[1]=='build':
        for tag in TAGS:build(tag)
        return
    tag=TAGS[int(sys.argv[1])]
    idx=json.loads((OUT/tag/'AMITSE_code_index.json').read_text())
    mode=sys.argv[2]
    if mode=='guids':
        for g in idx['guids']:
            if re.search(sys.argv[3],g['name'],re.I):
                print(g['name'],g['guid'],hex(g['rva']),idx['refs'].get(str(g['rva']),[]))
        return
    for arg in sys.argv[3:]:
        addr=int(arg,16)
        if mode=='refs':
            print(hex(addr),idx['refs'].get(str(addr),[]))
        elif mode=='fn':
            i=bisect.bisect_right(idx['starts'],addr)-1
            lo,hi=idx['starts'][i:i+2]
            print('function',hex(lo),hex(hi),'refs',idx['refs'].get(str(lo),[]))
            for line in (OUT/tag/'AMITSE_disassembly.txt').read_text().splitlines():
                if lo<=int(line[:8],16)<hi:print(line)


if __name__=='__main__':main()

"""Corroborate ported struct offsets using reachable direct-control-flow bodies.

Every opcode/register/ordinary constant must match. Only branch immediates and
RIP displacements are masked; their actual targets are retained for review.
This is static evidence, not a claim about unobserved indirect runtime edges.
"""
from map_native import *

def normalized(ins):
    data=bytearray(ins.bytes)
    if any(o.type==C.CS_OP_MEM and o.mem.base==X86_REG_RIP for o in ins.operands):
        data[ins.disp_offset:ins.disp_offset+ins.disp_size]=b'\0'*ins.disp_size
    if ins.group(C.CS_GRP_JUMP) or ins.group(C.CS_GRP_CALL):
        data[ins.imm_offset:ins.imm_offset+ins.imm_size]=b'\0'*ins.imm_size
    return bytes(data)

def routine(data,start):
    out=[]
    for ins in cs.disasm(data[start:start+0x10000],start):
        out.append(ins)
        if ins.mnemonic=='ret':return out
    raise ValueError(hex(start))

def reachable(data,start):
    pending=[start];seen={};unknown=[]
    while pending:
        addr=pending.pop()
        while addr not in seen:
            if not start<=addr<start+0x10000:
                unknown.append({'kind':'out_of_boundary_branch','target':hex(addr)});break
            ins=next(cs.disasm(data[addr:addr+16],addr));seen[addr]=ins
            end=addr+ins.size
            if ins.mnemonic=='ret':break
            if ins.group(C.CS_GRP_JUMP):
                targets=[o.imm for o in ins.operands if o.type==C.CS_OP_IMM]
                if targets:pending+=targets
                else:unknown.append({'kind':'indirect_jump','address':hex(addr)})
                if ins.mnemonic=='jmp':break
            addr=end
    return sorted(seen.values(),key=lambda i:i.address),unknown

def main():
    a=image(OLD/'AMITSE.efi');b=image(NEW/'AMITSE.efi')
    pairs=[('Browser loop',0xe208,0xe1b8),('Frame input',0x15370,0x15320),
           ('Page render',0x16ae0,0x16a90),('Page input',0x16c70,0x16c20),
           ('App input',0x121b8,0x12168),('Navigation dispatcher',0x62bc,0x626c),
           ('Poll helper',0x34b7c,0x34b2c),('Default navigation',0x1200c,0x11fbc)]
    results=[]
    for name,old,new in pairs:
        ai,au=reachable(a,old);bi,bu=reachable(b,new)
        an=b''.join(normalized(x) for x in ai);bn=b''.join(normalized(x) for x in bi)
        same=an==bn and [x.address-old for x in ai]==[x.address-new for x in bi]
        branch_edges_equal=all(
          [o.imm-old for o in x.operands if o.type==C.CS_OP_IMM]==[o.imm-new for o in y.operands if o.type==C.CS_OP_IMM]
          for x,y in zip(ai,bi) if x.group(C.CS_GRP_JUMP))
        same=same and branch_edges_equal
        r={'routine':name,'old_start':hex(old),'new_start':hex(new),'old_end':hex(ai[-1].address+ai[-1].size),'new_end':hex(bi[-1].address+bi[-1].size),'old_instructions':len(ai),'new_instructions':len(bi),'normalized_bytes_identical':same,'direct_branch_edges_equal':branch_edges_equal,'normalized_sha256':hashlib.sha256(an).hexdigest() if same else None,'old_unknowns':au,'new_unknowns':bu,'old_refs':refs(ai),'new_refs':refs(bi)}
        results.append(r)
        print(name,same,len(ai),len(bi),hex(ai[-1].address),hex(bi[-1].address))
    (HERE/'routine_equivalence.json').write_text(json.dumps({'module_sha256':hashlib.sha256((NEW/'AMITSE.efi').read_bytes()).hexdigest(),'scope':__doc__,'routines':results},indent=2),encoding='utf8')
    assert all(x['normalized_bytes_identical'] for x in results)
if __name__=='__main__':main()

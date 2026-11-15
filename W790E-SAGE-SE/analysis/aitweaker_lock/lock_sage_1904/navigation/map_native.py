from pathlib import Path
import hashlib,json,re,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone as C
from capstone.x86_const import X86_REG_RIP
OLD=HERE.parent.parent/'hardware_20261102_W790_ACE_E9B906DF/modules'
NEW=HERE.parent/'analysis/modules'
cs=C.Cs(C.CS_ARCH_X86,C.CS_MODE_64);cs.detail=True
def image(p):return pefile.PE(str(p)).get_memory_mapped_image()
def pattern(data,start,n):
    ins=list(cs.disasm(data[start:start+1024],start))[:n]
    if not ins:return None,None
    end=ins[-1].address+ins[-1].size
    b=data[start:end];wild=set()
    for x in ins:
        if any(o.type==C.CS_OP_MEM and o.mem.base==X86_REG_RIP for o in x.operands):
            wild.update(range(x.address-start+x.disp_offset,x.address-start+x.disp_offset+x.disp_size))
        if x.group(C.CS_GRP_JUMP) or x.group(C.CS_GRP_CALL):
            wild.update(range(x.address-start+x.imm_offset,x.address-start+x.imm_offset+x.imm_size))
    return b''.join(b'.' if i in wild else re.escape(bytes([v])) for i,v in enumerate(b)),ins
def refs(ins):
    out=[]
    for x in ins:
        for o in x.operands:
            if o.type==C.CS_OP_MEM and o.mem.base==X86_REG_RIP:out.append({'instruction':hex(x.address),'kind':'rip','target':hex(x.address+x.size+o.mem.disp),'text':x.mnemonic+' '+x.op_str})
            if o.type==C.CS_OP_IMM and (x.group(C.CS_GRP_JUMP) or x.group(C.CS_GRP_CALL)):out.append({'instruction':hex(x.address),'kind':'branch','target':hex(o.imm),'text':x.mnemonic+' '+x.op_str})
    return out
def main():
    out={}
    sets={'AMITSE':[0x62bc,0xe208,0xe6f4,0x15370,0x16ae0,0x16c70,0x121b8,0x34b7c,0x1701c,0x17040,0x17206,0xe70d,0x322b4,0x11d8c,0x11518,0x54a24,0x541cc,0x4cc1c,0x4c850,0x32d30,0x49788], 'Setup':[0x1524,0x152c,0x1534]}
    for module,anchors in sets.items():
        a=image(OLD/(module+'.efi'));b=image(NEW/(module+'.efi'));out[module]={'old_sha256':hashlib.sha256((OLD/(module+'.efi')).read_bytes()).hexdigest(),'new_sha256':hashlib.sha256((NEW/(module+'.efi')).read_bytes()).hexdigest(),'anchors':[]}
        for addr in anchors:
            allres=[]
            for count in [16,32,64,8]:
                pat,ins=pattern(a,addr,count)
                found=[m.start() for m in re.finditer(pat,b,re.S)]
                if len(found)==1:
                    dest=found[0];ni=list(cs.disasm(b[dest:dest+sum(x.size for x in ins)],dest))
                    allres.append({'old':hex(addr),'new':hex(dest),'instruction_count':count,'old_refs':refs(ins),'new_refs':refs(ni)})
                    break
            if not allres:allres=[{'old':hex(addr),'new':None}]
            out[module]['anchors']+=allres
    (HERE/'anchor_mapping.json').write_text(json.dumps(out,indent=2),encoding='utf8')
    print(json.dumps({k:[{f:x[f] for f in ['old','new']} for x in v['anchors']] for k,v in out.items()},indent=2))
if __name__=='__main__':main()

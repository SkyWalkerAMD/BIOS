"""Role corroboration from original vtable/GUID and reachable instruction bodies.
Not a patch authorizer: target-relative constants may change meaning.
"""
from map_w890 import *
import struct
PAIRS=[('navigation_dispatch',0x626c,0x10594),('browser_loop',0xe1b8,0x190f4),
 ('page_render',0x16a90,0x2372c),('page_input',0x16c20,0x238bc),
 ('frame_input',0x15320,0x21ef4),('app_input',0x12168,0x1d9c8),
 ('poll',0x34b2c,0x4cd14),('side_menu_callback',0x15c44,0x22818),
 ('history_lookup',0x1012c,0x1b814),('history_update',0x10220,0x1b928),
 ('sendform',0x20ee4,0x36da4)]
def normalized(ins):
    raw=bytearray(ins.bytes)
    if any(o.type==C.CS_OP_MEM and o.mem.base==X86_REG_RIP for o in ins.operands):raw[ins.disp_offset:ins.disp_offset+ins.disp_size]=bytes(ins.disp_size)
    if ins.group(C.CS_GRP_JUMP) or ins.group(C.CS_GRP_CALL):raw[ins.imm_offset:ins.imm_offset+ins.imm_size]=bytes(ins.imm_size)
    return bytes(raw)
def reachable(data,start):
    pending=[start];seen={};unknown=[]
    while pending:
        addr=pending.pop()
        while addr not in seen:
            if not start<=addr<start+0x8000:
                unknown.append({'reason':'outside-bounded-body','address':addr});break
            ins=next(cs.disasm(data[addr:addr+16],addr),None)
            if ins is None:unknown.append({'reason':'decode-failed','address':addr});break
            seen[addr]=ins
            if ins.group(C.CS_GRP_RET):break
            if ins.group(C.CS_GRP_JUMP):
                dest=[o.imm for o in ins.operands if o.type==C.CS_OP_IMM]
                pending+=dest
                if not dest:unknown.append({'reason':'indirect-jump','address':addr})
                if ins.mnemonic=='jmp':break
            addr+=ins.size
    return sorted(seen.values(),key=lambda i:i.address),unknown
def main():
    a=image(OLD/'AMITSE.efi');b=image(NEW/'AMITSE.efi');result=[]
    for name,old,new in PAIRS:
        ai,au=reachable(a,old);bi,bu=reachable(b,new)
        oldn=b''.join(normalized(i) for i in ai);newn=b''.join(normalized(i) for i in bi)
        equal=oldn==newn and [i.address-old for i in ai]==[i.address-new for i in bi]
        internal_edges=equal and all([o.imm-old for o in i.operands if o.type==C.CS_OP_IMM]==[o.imm-new for o in j.operands if o.type==C.CS_OP_IMM] for i,j in zip(ai,bi) if i.group(C.CS_GRP_JUMP))
        result.append({'role':name,'old_rva':old,'w890_rva':new,'old_instructions':len(ai),'new_instructions':len(bi),'normalized_instruction_and_internal_edges_equal':equal and internal_edges,'old_unknowns':au,'new_unknowns':bu,'old_refs':refs(ai),'new_refs':refs(bi),'new_body_sha256':sha(b''.join(i.bytes for i in bi))})
    observations=[]
    for name,oldslot,newslot,target in [('app_input',0x6b840,0x93d10,0x1d9c8),('frame_input',0x6b8d8,0x93da8,0x21ef4),('page_render',0x6b928,0x93df8,0x2372c),('page_input',0x6b930,0x93e00,0x238bc),('sendform',0x6bed8,0x943a8,0x36da4)]:
        assert struct.unpack_from('<Q',b,newslot)[0]==target
        observations.append({'role':name,'old_slot':oldslot,'w890_slot':newslot,'w890_target':target,'slot_bytes':b[newslot:newslot+8].hex()})
    out={'scope':'STATIC_NATIVE_ROLE_CORROBORATION_NOT_PATCH_APPROVAL','module_sha256':sha((NEW/'AMITSE.efi').read_bytes()),'roles':result,'pointer_slots':observations,'rejected_prefix_match':{'old_role':'sendform','false_candidate':0x81bd4,'actual_target':0x36da4,'reason':'8-instruction prefix matched an unrelated password-input function. Actual target comes from FormBrowser2 GUID install at 0xB394/0xB39E and pointer at 0x943A8.'}}
    (HERE/'role_verification.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
    print(json.dumps({'roles':[{k:v for k,v in r.items() if k in ['role','old_rva','w890_rva','old_instructions','new_instructions','normalized_instruction_and_internal_edges_equal','new_unknowns']} for r in result],'pointer_slots':observations},indent=2))
if __name__=='__main__':main()

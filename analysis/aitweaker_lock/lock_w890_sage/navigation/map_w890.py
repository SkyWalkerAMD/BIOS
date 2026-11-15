"""Read-only W790 1904 -> W890 0603 native anchor comparison.

Address-relative operands are masked only to locate candidates. This does not
approve any patch offset. Full original bytes and actual references are retained.
"""
from pathlib import Path
import hashlib,json,re,sys,datetime
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone as C
from capstone.x86_const import X86_REG_RIP
cs=C.Cs(C.CS_ARCH_X86,C.CS_MODE_64);cs.detail=True
OLD=ROOT/'analysis/aitweaker_lock/lock_sage_1904/analysis/modules'
NEW=HERE/'modules'
def sha(b):return hashlib.sha256(b).hexdigest()
def image(p):return pefile.PE(str(p)).get_memory_mapped_image()
def refs(ins):
    out=[]
    for x in ins:
        for o in x.operands:
            if o.type==C.CS_OP_MEM and o.mem.base==X86_REG_RIP:
                out.append({'rva':x.address,'kind':'rip','target':x.address+x.size+o.mem.disp,'assembly':x.mnemonic+' '+x.op_str})
            if o.type==C.CS_OP_IMM and (x.group(C.CS_GRP_JUMP) or x.group(C.CS_GRP_CALL)):
                out.append({'rva':x.address,'kind':'branch','target':o.imm,'assembly':x.mnemonic+' '+x.op_str})
    return out
def pattern(data,start,n):
    ins=list(cs.disasm(data[start:start+2048],start))[:n]
    end=ins[-1].address+ins[-1].size
    raw=data[start:end];wild=set()
    for x in ins:
        if any(o.type==C.CS_OP_MEM and o.mem.base==X86_REG_RIP for o in x.operands):
            wild.update(range(x.address-start+x.disp_offset,x.address-start+x.disp_offset+x.disp_size))
        if x.group(C.CS_GRP_JUMP) or x.group(C.CS_GRP_CALL):
            wild.update(range(x.address-start+x.imm_offset,x.address-start+x.imm_offset+x.imm_size))
    return b''.join(b'.' if i in wild else re.escape(bytes([v])) for i,v in enumerate(raw)),ins
ANCHORS={
 'navigation_dispatch':0x626c,'browser_loop':0xe1b8,'frame_input':0x15320,
 'page_render':0x16a90,'page_input':0x16c20,'app_input':0x12168,
 'poll':0x34b2c,'default_navigation':0x11fbc,'history_push':0x10220,
 'history_pop':0x1012c,'sendform':0x20ee4,'side_menu_construct':0x33634,
 'side_menu_input':0x4ecfc,'side_menu_selection':0x4ecb8,
 'side_menu_callback':0x15c44,'pending_update':0x29ae4,
 'frame_render_call':0x16fcc,'page_input_dispatch':0x16ff0,
 'form_open_call':0x1715f,'form_open_tail':0x171b6,
 'browser_loop_tail':0xe6a4,'browser_loop_callback':0xe6bd,
 'setup_enter_notify':0x5f6c7,'defaults_handler':0x330e0,
 'setup_event':0x5abc,'menu_event':0x5a04,
}
def main():
    NEW.mkdir(parents=True,exist_ok=True)
    meta=json.loads((ROOT/'analysis/aitweaker_lock/integration_map.json').read_text('utf-8'))['W890_SAGE_0603']
    source=[]
    for name,info in meta['modules'].items():
        p=ROOT/'analysis/workstation_20261008'/info['section_path'];b=p.read_bytes()
        assert sha(b)==info['pe_sha256']
        (NEW/(name+'.efi')).write_bytes(b)
        pe=pefile.PE(data=b)
        source.append({'module':name,'source':str(p),'sha256':sha(b),'file_bytes':len(b),'image_size':pe.OPTIONAL_HEADER.SizeOfImage,'entry':pe.OPTIONAL_HEADER.AddressOfEntryPoint,'sections':[{'name':s.Name.decode().rstrip('\0'),'rva':s.VirtualAddress,'virtual_size':s.Misc_VirtualSize,'raw_size':s.SizeOfRawData} for s in pe.sections]})
    result={'generated_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'baseline':'W890_SAGE_0603','hardware_version_verified':False,'patch_offsets_approved':False,'sources':source,'anchors':[]}
    for module,anchors in [('AMITSE',ANCHORS),('Setup',{'extract':0x1524,'route':0x152c,'callback':0x1534})]:
        a=image(OLD/(module+'.efi'));b=image(NEW/(module+'.efi'))
        for name,addr in anchors.items():
            rr={'module':module,'name':name,'old':addr,'new':None,'tests':[]}
            for n in [64,32,16,8]:
                pat,ins=pattern(a,addr,n)
                found=[m.start() for m in re.finditer(pat,b,re.S)]
                rr['tests'].append({'instructions':n,'matches':found})
                if len(found)==1:
                    dest=found[0];ln=ins[-1].address+ins[-1].size-addr
                    ni=list(cs.disasm(b[dest:dest+ln],dest))
                    rr.update(new=dest,instruction_count=len(ins),bytes_count=ln,old_bytes=a[addr:addr+ln].hex(),new_bytes=b[dest:dest+ln].hex(),old_refs=refs(ins),new_refs=refs(ni));break
            result['anchors'].append(rr)
    (HERE/'anchor_mapping.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({'sources':source,'anchors':[{k:(hex(v) if k in ('old','new') and v is not None else v) for k,v in x.items() if k in ('name','old','new','instruction_count')} for x in result['anchors']]},indent=2))
if __name__=='__main__':main()

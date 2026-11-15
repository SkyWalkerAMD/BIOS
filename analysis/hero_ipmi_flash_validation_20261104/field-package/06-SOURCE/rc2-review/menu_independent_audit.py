from pathlib import Path
import sys, json, hashlib, struct

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile, capstone
OUT=Path(__file__).resolve().parent

def sha(b):return hashlib.sha256(b).hexdigest()
def u16(b,o):return int.from_bytes(b[o:o+2],'little')
def u32(b,o):return int.from_bytes(b[o:o+4],'little')

old=(ROOT/'analysis/hero_remote_bios_r3/reference/HERO-3107-Setup.efi').read_bytes()
new=(ROOT/'analysis/hero_ipmi_p5/Setup-P5-RESOURCE-REVIEW.efi').read_bytes()
a,b=pefile.PE(data=old),pefile.PE(data=new)
rels=[]
for block in a.DIRECTORY_ENTRY_BASERELOC:
    for e in block.entries:
        if e.type:rels.append({'rva':e.rva,'type':e.type,'target':a.get_qword_at_rva(e.rva)})
rsrc=a.sections[-2]; relocate=a.sections[-1]
start,end=rsrc.VirtualAddress,relocate.VirtualAddress+relocate.Misc_VirtualSize
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True;md.skipdata=True
refs=[];instructions=0
for section in a.sections:
    if not section.Characteristics&0x20000000:continue
    for ins in md.disasm(section.get_data()[:section.Misc_VirtualSize],section.VirtualAddress):
        if ins.id==0:continue
        instructions+=1
        for op in ins.operands:
            target=None
            if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
                target=ins.address+ins.size+op.mem.disp
            elif op.type==capstone.x86.X86_OP_IMM:target=op.imm
            if target is not None and start<=target<end:
                refs.append({'at':hex(ins.address),'instruction':ins.mnemonic+' '+ins.op_str,'target':hex(target),
                    'kind':'rip-relative' if op.type==capstone.x86.X86_OP_MEM else 'immediate-value-not-necessarily-address'})
report={'method':'Independent pefile relocation walk and Capstone linear executable-section decode; not REA or complete control-flow proof',
'original_setup_sha256':sha(old),'candidate_setup_sha256':sha(new),
'decoded_instructions':instructions,'resource_or_reloc_direct_code_references':refs,
'relocation_count':len(rels),'relocations_targeting_resource_or_reloc':[r for r in rels if start<=r['target']<end],
'relocation_storage_in_resource_or_reloc':[r for r in rels if start<=r['rva']<end],
'section_equality':[{'name':s.Name.rstrip(b'\0').decode(),'equal':s.get_data()==t.get_data(),'old_rva':hex(s.VirtualAddress),'new_rva':hex(t.VirtualAddress)} for s,t in zip(a.sections,b.sections)]}
(OUT/'menu-pe-independent.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='resource_or_reloc_direct_code_references'},indent=2))
print('RIP-relative references into moved resource/relocation region:',sum(x['kind']=='rip-relative' for x in refs))

# Reuse retained real REA records. Keep exact subject/evidence association.
evidence=[]
rea=ROOT/'analysis/hero_rea_20261102'
dest=OUT/'retained-menu-rea';dest.mkdir(exist_ok=True)
for directory in ('p1b-tse-data','p2-native-update','p3-parser','p3b-reuse'):
    for f in (rea/directory/'responses').glob('*.json'):
        d=json.loads(f.read_text()).get('result',{}).get('structuredContent',{})
        norm=d.get('normalized_result') or {}
        items=norm if isinstance(norm,list) else norm.get('items') or []
        if not items and isinstance(norm,dict) and isinstance(norm.get('pseudocode'),str):items=[norm]
        for item in items:
            if not isinstance(item,dict):continue
            pseudo=item.get('pseudocode')
            if not pseudo:continue
            address=item.get('procedure',{}).get('address',item.get('address','unknown'))
            name=f'{directory}-{f.stem}-{address}.txt'
            (dest/name).write_text(pseudo,encoding='utf-8')
            evidence.append({'source':str(f.relative_to(ROOT)),'evidence_id':d.get('evidence_id'),
              'target_sha256':d.get('subject',{}).get('digest',{}).get('sha256'),'address':address,'extracted':name})
(OUT/'retained-menu-rea-index.json').write_text(json.dumps(evidence,indent=2)+'\n')
print('Retained pseudocode records:',len(evidence))

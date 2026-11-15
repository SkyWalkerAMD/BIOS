"""Pin the current isolated static-guard build; regenerate after any guard change."""
from pathlib import Path
import hashlib,json,sys
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=CASE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
GUARD=HERE.parent/'native12_safety_review/implementation';build=json.loads((GUARD/'build/build.json').read_text())
sha=lambda b:hashlib.sha256(b).hexdigest();bound={};decl=[]
for name in ['AMITSE','Setup']:
    item=build['modules'][name];path=GUARD/item['path'];raw=path.read_bytes();assert sha(raw)==item['sha256']
    pe=pefile.PE(data=raw);rva=int(item['appended_rva'],16);size=item['payload_bytes'];payload=pe.get_data(rva,size)
    assert len(payload)==size
    for block in getattr(pe,'DIRECTORY_ENTRY_BASERELOC',[]):
        for e in block.entries:assert not(e.type and rva<=e.rva<rva+size),'Payload must be relocation-free'
    snapshot=HERE/'bound_guard'/sha(raw)/(name+'.UNSIGNED.review.efi');snapshot.parent.mkdir(parents=True,exist_ok=True)
    if snapshot.exists():assert snapshot.read_bytes()==raw
    else:snapshot.write_bytes(raw)
    record={'module_file':str(snapshot),'source_module_file':str(path),'module_sha256':sha(raw),'image_bytes':pe.OPTIONAL_HEADER.SizeOfImage,
            'payload_rva':rva,'payload_bytes':size,'payload_sha256':sha(payload),
            'callback_rva':int(item['payload_symbols']['gate_callback'],16),'route_rva':int(item['payload_symbols']['gate_route'],16)}
    if name=='AMITSE':
        record['context_head_rva']=int(item['context_head_rva'],16)
        sy={k:int(v,16)for k,v in item['payload_symbols'].items()};start=sy['gate_loop'];end=min(v for v in sy.values()if v>start)
        cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;calls={}
        for ins in cs.disasm(pe.get_data(start,end-start),start):
            if ins.mnemonic=='call'and len(ins.operands)==1 and ins.operands[0].type==capstone.x86.X86_OP_MEM:
                displacement=ins.operands[0].mem.disp
                if displacement in (16,24):
                    assert displacement not in calls;calls[displacement]=ins.address+ins.size
        assert set(calls)=={16,24},calls
        record['begin_return_rva']=calls[16];record['end_return_rva']=calls[24]
        for key in ['context_head_rva','begin_return_rva','end_return_rva']:decl.append(f'#define BOUND_{key.upper()} 0x{record[key]:x}u')
    tag=name.upper()
    for key in ['image_bytes','payload_rva','payload_bytes','callback_rva','route_rva']:decl.append(f'#define {tag}_{key.upper()} 0x{record[key]:x}u')
    decl.append(f'static const uint8_t {name.lower()}_payload_hash[32]={{'+','.join(f'0x{x:02x}'for x in bytes.fromhex(record['payload_sha256']))+'};')
    bound[name]=record
(HERE/'source/guard_binding.h').write_text('/* Generated from isolated static modules; no hardware acceptance. */\n'+ '\n'.join(decl)+'\n')
report={'status':'BOUND_TO_LOCAL_GUARD_BUILD','guard_build_sha256':sha((GUARD/'build/build.json').read_bytes()),'modules':bound,
        'source_sha256':sha(Path(__file__).read_bytes()),'header_sha256':sha((HERE/'source/guard_binding.h').read_bytes())}
(HERE/'guard_binding.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'begin':hex(bound['AMITSE']['begin_return_rva']),'end':hex(bound['AMITSE']['end_return_rva']),'context':hex(bound['AMITSE']['context_head_rva'])}))

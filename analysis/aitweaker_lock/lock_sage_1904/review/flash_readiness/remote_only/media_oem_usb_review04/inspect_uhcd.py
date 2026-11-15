from pathlib import Path
import hashlib,json,sys,re,argparse,uuid
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_REG_RIP
EFI=HERE/'580DD900-385D-11D7-883A-00500473D4EB.efi'
EXPECTED='62df9b675b3e8e5a573fe04c99555796c066fa5ff8622ce11765f38c7c9d272f'

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--guid',default=EFI.stem);a=ap.parse_args()
    file=HERE/(a.guid+'.efi');assert file.parent==HERE
    raw=file.read_bytes()
    if a.guid==EFI.stem:assert hashlib.sha256(raw).hexdigest()==EXPECTED
    pe=pefile.PE(data=raw);md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True;md.skipdata=True
    selected=[]
    mapped=pe.get_memory_mapped_image()
    guid=uuid.UUID('964e5b21-6459-11d2-8e39-00a0c969723b').bytes_le
    guid_addresses=[];pos=0
    while True:
        pos=mapped.find(guid,pos)
        if pos<0:break
        guid_addresses.append(pos);pos+=16
    guidrefs=[]
    for sec in pe.sections:
        if not sec.Characteristics&0x20000000:continue
        items=list(md.disasm(sec.get_data()[:sec.Misc_VirtualSize],sec.VirtualAddress))
        for j,i in enumerate(items):
            if i.id==0:continue
            if any(o.type==X86_OP_MEM and o.mem.base==X86_REG_RIP and i.address+i.size+o.mem.disp in guid_addresses for o in i.operands):
                guidrefs.append({'rva':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str})
            if any(o.type==X86_OP_IMM and o.imm in [0x400,0x40000,0x3ffff,0x3fff,0x25] for o in i.operands):
                selected.append({'match_rva':hex(i.address),'context':[{'rva':hex(x.address),'bytes':x.bytes.hex(),'instruction':x.mnemonic+' '+x.op_str} for x in items[max(0,j-5):j+6]]})
    (HERE/(a.guid+'_immediates.json')).write_text(json.dumps({'source_sha256':hashlib.sha256(raw).hexdigest(),'matches':selected,'block_io_guid_rvas':[hex(x) for x in guid_addresses],'block_io_guid_refs':guidrefs},indent=2),encoding='utf8')
    print(json.dumps({'matches':[{'rva':r['match_rva'],'matched':next(x['instruction'] for x in r['context'] if x['rva']==r['match_rva'])} for r in selected],'block_io_guid_refs':guidrefs},indent=2))
if __name__=='__main__':main()

"""ELF32 symbols/strings only, no execution or external access."""
from pathlib import Path
import hashlib,json,re,struct
HERE=Path(__file__).resolve().parent
def inventory(p):
    b=p.read_bytes();assert b[:6]==b'\x7fELF\x01\x01'
    shoff=struct.unpack_from('<I',b,32)[0];sz,n,si=struct.unpack_from('<HHH',b,46)
    sh=[struct.unpack_from('<10I',b,shoff+i*sz) for i in range(n)]
    def cs(data,off):return data[off:].split(b'\0',1)[0].decode('utf8',errors='replace')
    sym=[]
    for s in sh:
        if s[1] not in (2,11):continue
        st=sh[s[6]];strings=b[st[4]:st[4]+st[5]]
        for off in range(s[4],s[4]+s[5],s[9]):
            name,va,size,info,other,ndx=struct.unpack_from('<IIIBBH',b,off)
            if name:sym.append({'name':cs(strings,name),'address':hex(va),'size':size,'type':info&15,'defined':ndx!=0})
    strings=[{'offset':hex(m.start()),'text':m.group().decode('ascii')} for m in re.finditer(rb'[\x20-\x7e]{5,}',b)]
    result={'source':str(p),'sha256':hashlib.sha256(b).hexdigest(),'symbols':sym,'strings':strings}
    (HERE/(p.name+'.inventory.json')).write_text(json.dumps(result,indent=2),encoding='utf8')
    print('\nFILE',p.name)
    print('\n'.join(x['address']+' '+x['name'] for x in sym if x['defined'] and x['type']==2))
    print('KEY STRINGS')
    print('\n'.join(x['offset']+' '+x['text'] for x in strings if re.search(r'auth|insert|attach|capacity|block|init|client|media|SCSI|hdisk',x['text'],re.I)))
if __name__=='__main__':
    for p in (HERE/'backend').rglob('*'):
        if p.is_file() and p.read_bytes().startswith(b'\x7fELF'):inventory(p)

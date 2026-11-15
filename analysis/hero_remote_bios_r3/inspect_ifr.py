"""Extract HERO 3107 settings from its own IFR; no donor variable offsets."""
from pathlib import Path
import hashlib,json,struct,uuid
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[1]
b=(OUT/'reference/HERO-3107-Setup.efi').read_bytes()
assert hashlib.sha256(b).hexdigest()=='1c4683574c36e972ae0615bb4a899929c1edaa61d5b23dc86da333a62edb53fe'
strings=json.loads((ROOT/'analysis/hero_3107_official/hii_en_us.json').read_text())['strings']
def u16(o):return struct.unpack_from('<H',b,o)[0]
def label(i):return strings.get(str(i),'')
start=0x7c0f4;length=int.from_bytes(b[start:start+3],'little')
assert b[start+3]==2
stores={};questions=[];scopes=[];forms=[];p=start+4
while p<start+length:
    op=b[p];n=b[p+1]&127;scope=bool(b[p+1]&128)
    assert n>=2 and p+n<=start+length,(hex(p),op,n)
    item={'opcode':op,'offset':hex(p),'length':n}
    if op==0x24:
        assert n>=23
        guid=str(uuid.UUID(bytes_le=b[p+2:p+18]));sid=u16(p+18)
        stores[sid]={'id':sid,'guid':guid,'size':u16(p+20),'name':b[p+22:p+n].rstrip(b'\0').decode('ascii'),'kind':'buffer','ifr_offset':hex(p)}
    elif op==0x26:
        # Modern EFI varstore: Header, VarStoreId, GUID, Attributes, Size, Name.
        if n>=27:
            sid=u16(p+2)
            stores[sid]={'id':sid,'guid':str(uuid.UUID(bytes_le=b[p+4:p+20])),'attributes':int.from_bytes(b[p+20:p+24],'little'),'size':u16(p+24),'name':b[p+26:p+n].rstrip(b'\0').decode('ascii'),'kind':'efi','ifr_offset':hex(p)}
    elif op==1:
        item.update(form_id=u16(p+2),title=label(u16(p+4)));forms.append(item.copy())
    elif op in (5,6,7,8,0xc,0xf,0x1c,0x23):
        assert n>=13
        q={'ifr_offset':hex(p),'opcode':op,'prompt_id':u16(p+2),'prompt':label(u16(p+2)),'help':label(u16(p+4)),'question_id':u16(p+6),'store_id':u16(p+8),'var_offset':u16(p+10),'flags':b[p+12],'form':next((s.get('title','') for s in reversed(scopes) if s['opcode']==1),''),'conditions':[{'opcode':s['opcode'],'ifr_offset':s['offset']} for s in scopes if s['opcode'] in (0xa,0x19,0x1e,0x10,0x11,0x63)],'options':[],'raw':b[p:p+n].hex()}
        if op in (5,7):
            q['numeric_flags']=b[p+13];q['width']=1<<(b[p+13]&3)
            w=q['width'];q.update(minimum=int.from_bytes(b[p+14:p+14+w],'little'),maximum=int.from_bytes(b[p+14+w:p+14+2*w],'little'),step=int.from_bytes(b[p+14+2*w:p+14+3*w],'little'))
        if op==6:q['width']=1
        questions.append(q);item['question']=q
    elif op==9:
        q=next((s['question'] for s in reversed(scopes) if 'question' in s),None)
        if q is not None:
            typ=b[p+5];width={0:1,1:2,2:4,3:8,4:1}.get(typ)
            q['options'].append({'label':label(u16(p+2)),'flags':b[p+4],'type':typ,'value':int.from_bytes(b[p+6:p+6+width],'little') if width else b[p+6:p+n].hex()})
    if op==0x29:
        assert scopes;scopes.pop()
    elif scope:scopes.append(item)
    p+=n
assert p==start+length and not scopes
for q in questions:q['store']=stores.get(q['store_id'])
report={'source_sha256':hashlib.sha256(b).hexdigest(),'bios':'3107','forms_package_offset':hex(start),'forms_package_length':length,'stores':list(stores.values()),'forms':forms,'questions':questions}
(OUT/'hero-3107-ifr.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
selected=[q for q in questions if any(t in q['prompt'].lower() for t in ('numlock','boot logo','post delay','wait for','setup mode','option rom messages'))]
(OUT/'hero-3107-candidate-settings.json').write_text(json.dumps(selected,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
print(json.dumps({'stores':len(stores),'forms':len(forms),'questions':len(questions),'candidates':selected},ensure_ascii=False,indent=2))

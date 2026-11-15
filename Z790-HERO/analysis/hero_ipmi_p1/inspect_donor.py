"""Extract donor menu definitions as evidence, never as executable instructions."""
from pathlib import Path
import hashlib,json,struct,uuid
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1]
OUT=BASE/'reference';OUT.mkdir(exist_ok=True)
inventory=json.loads((ROOT/'analysis/inventory.json').read_text())['ProArt-Z790-CREATOR-WIFI-ASUS-IPMI-3002.CAP']
modules={}
for guid,name in [('1B08A1DB-F91A-4FA1-A911-255C417F1CF7','Creator-Setup'),('6372357A-06D7-43EF-B55C-1964F3DD6916','Creator-DxeIpmiInitialize'),('05602C82-5F85-4735-AF53-053502178D02','Creator-BmcFanCtrl')]:
    row=next(m for m in inventory if m['guid']==guid)
    paths=[p for p in (ROOT/row['path']).rglob('body.bin') if 'PE32 image' in p.parent.name];assert len(paths)==1
    raw=paths[0].read_bytes();(OUT/(name+'.efi')).write_bytes(raw)
    modules[name]={'guid':guid,'source':paths[0].relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'depex':row['depex']}
(OUT/'module-origin.json').write_text(json.dumps(modules,indent=2)+'\n')
b=(OUT/'Creator-Setup.efi').read_bytes()
u16=lambda p:struct.unpack_from('<H',b,p)[0]
def strings_at(start):
    length=int.from_bytes(b[start:start+3],'little');info=int.from_bytes(b[start+8:start+12],'little')
    assert b[start+3]==4 and 46<=info<length and start+length<=len(b)
    end=start+length;p=start+info;i=1;strings={}
    while p<end:
        op=b[p];p+=1
        if op==0:assert p==end;return strings
        if op==0x14:
            q=p
            while p+2<=end and b[p:p+2]!=b'\0\0':p+=2
            assert p+2<=end;strings[i]=b[q:p].decode('utf-16-le');p+=2;i+=1
        elif op==0x20:strings[i]=strings[u16(p)];p+=2;i+=1
        elif op==0x21:i+=u16(p);p+=2
        elif op==0x22:i+=b[p];p+=1
        else:raise ValueError((hex(start),hex(p-1),hex(op)))
    raise ValueError('Missing strings end')
candidates=[];pos=0
while (pos:=b.find(b'en-US\0',pos))>=0:
    start=pos-46;pos+=1
    if start>=0 and b[start+3]==4:
        try:candidates.append((start,strings_at(start)))
        except (AssertionError,ValueError,KeyError):pass
assert len(candidates)==1,[(hex(x),len(y)) for x,y in candidates]
start,strings=candidates[0]
(OUT/'creator-en-us.json').write_text(json.dumps({'offset':hex(start),'strings':strings},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def label(i):return strings.get(i,'')

def parse(start):
    length=int.from_bytes(b[start:start+3],'little');assert b[start+3]==2 and start+length<=len(b)
    p=start+4;scopes=[];stores={};questions=[];forms=[];sets=[]
    while p<start+length:
        op=b[p];n=b[p+1]&127;scope=bool(b[p+1]&128)
        assert n>=2 and p+n<=start+length
        item={'opcode':op,'offset':hex(p),'length':n,'raw':b[p:p+n].hex()}
        if op==0xe:
            assert n>=23
            item.update(guid=str(uuid.UUID(bytes_le=b[p+2:p+18])),title=label(u16(p+18)),help=label(u16(p+20)),classes=[str(uuid.UUID(bytes_le=b[x:x+16])) for x in range(p+23,p+n,16)])
            sets.append(item.copy())
        elif op==0x24:
            stores[u16(p+18)]={'id':u16(p+18),'guid':str(uuid.UUID(bytes_le=b[p+2:p+18])),'size':u16(p+20),'name':b[p+22:p+n].rstrip(b'\0').decode(),'kind':'buffer'}
        elif op==0x26 and n>=27:
            stores[u16(p+2)]={'id':u16(p+2),'guid':str(uuid.UUID(bytes_le=b[p+4:p+20])),'attributes':int.from_bytes(b[p+20:p+24],'little'),'size':u16(p+24),'name':b[p+26:p+n].rstrip(b'\0').decode(),'kind':'efi'}
        elif op==1:
            item.update(form_id=u16(p+2),title=label(u16(p+4)));forms.append(item.copy())
        elif op in (5,6,7,8,0xc,0xf,0x1c,0x23):
            assert n>=13
            q={'offset':hex(p),'opcode':op,'prompt_id':u16(p+2),'prompt':label(u16(p+2)),'help':label(u16(p+4)),
               'question_id':u16(p+6),'store_id':u16(p+8),'var_offset':u16(p+10),'flags':b[p+12],
               'form':next((s['title'] for s in reversed(scopes) if s['opcode']==1),''),
               'formset':next((s['title'] for s in reversed(scopes) if s['opcode']==0xe),''),
               'conditions':[s for s in scopes if s['opcode'] in (0xa,0x19,0x1e,0x10,0x11,0x63)],'options':[],'raw':b[p:p+n].hex()}
            if op in (5,7):
                w=1<<(b[p+13]&3);q.update(width=w,minimum=int.from_bytes(b[p+14:p+14+w],'little'),maximum=int.from_bytes(b[p+14+w:p+14+2*w],'little'),step=int.from_bytes(b[p+14+2*w:p+14+3*w],'little'))
            questions.append(q);item['question']=q
        elif op==9:
            q=next((s['question'] for s in reversed(scopes) if 'question' in s),None)
            if q is not None:
                typ=b[p+5];w={0:1,1:2,2:4,3:8,4:1}.get(typ)
                q['options'].append({'label':label(u16(p+2)),'flags':b[p+4],'value':int.from_bytes(b[p+6:p+6+w],'little') if w else b[p+6:p+n].hex()})
        if op==0x29:assert scopes;scopes.pop()
        elif scope:scopes.append(item)
        p+=n
    assert not scopes and p==start+length
    for q in questions:q['store']=stores.get(q['store_id'])
    return dict(start=hex(start),length=length,formsets=sets,forms=forms,stores=list(stores.values()),questions=questions)
candidates=[];pos=0
while (pos:=b.find(b'\x02\x0e',pos))>=0:
    start=pos-3;pos+=1
    if start<0:continue
    try:candidates.append(parse(start))
    except (AssertionError,ValueError,IndexError,KeyError):pass
assert candidates
(OUT/'creator-ifr.json').write_text(json.dumps(candidates,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
selected=[q for c in candidates for q in c['questions'] if q['formset']=='IPMI' or any(t in q['prompt'].lower() for t in ('watchdog','wtd timer','light synchron','in-band driver','erase sel','erase log','station ip','router ip'))]
(OUT/'creator-ipmi-questions.json').write_text(json.dumps(selected,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'module_bytes':len(b),'strings':len(strings),'form_packages':len(candidates),'formsets':[f['title'] for c in candidates for f in c['formsets']],'ipmi_questions':len(selected),'selected':[{'prompt':q['prompt'],'form':q['form'],'qid':hex(q['question_id']),'store':q['store'],'offset':hex(q['var_offset'])} for q in selected[:24]]},ensure_ascii=False,indent=2))

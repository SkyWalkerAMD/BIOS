"""Independent structural audit of the P6 native resource components.

Does not import the resource generator or its parsing helpers. No hardware
access. Decodes IFR/SPF independently and checks changes against P5 bytes.
"""
from pathlib import Path
import hashlib, json, struct, sys, uuid

HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile

def U(b,p,n=4):
    assert p>=0 and p+n<=len(b)
    return int.from_bytes(b[p:p+n],'little')
def S(b,p,n=8):return int.from_bytes(b[p:p+n],'little',signed=True)
def digest(b):return hashlib.sha256(b).hexdigest()

def packages(b):
    assert U(b,16)==len(b)
    out=[];at=20
    while at<len(b):
        n=U(b,at)&0xffffff;assert n>=4 and at+n<=len(b)
        out.append(b[at:at+n]);at+=n
    assert out[-1]==b'\x04\0\0\xdf' and at==len(b)
    return out

def strings(b):
    assert b[3]==4
    p=U(b,8);id=1;out={}
    while p<len(b):
        k=b[p];p+=1
        if k==0:
            assert p==len(b);return out,id
        if 0x14<=k<=0x17:
            if k in (0x15,0x17):p+=1
            n=1
            if k in (0x16,0x17):n=U(b,p,2);p+=2
            for _ in range(n):
                start=p
                while b[p:p+2]!=b'\0\0':p+=2;assert p+2<=len(b)
                out[id]=b[start:p].decode('utf-16le');id+=1;p+=2
        elif k==0x20:out[id]=out[U(b,p,2)];id+=1;p+=2
        elif k in (0x21,0x22):w=2 if k==0x21 else 1;id+=U(b,p,w);p+=w
        else:raise AssertionError(('unsupported string block',k,p))
    raise AssertionError('no string terminator')

def ifr(b):
    assert b[3]==2 and U(b,0)&0xffffff==len(b)
    ops={};forms={};stack=[];p=4
    while p<len(b):
        n=b[p+1]&127;assert n>=2 and p+n<=len(b)
        raw=b[p:p+n];form=next((x[1] for x in reversed(stack) if x[0]==1),None)
        ops[p]=dict(raw=raw,form=form,parents=tuple(x[2] for x in stack))
        if raw[0]==0x29:
            assert n==2 and stack
            code,fid,start=stack.pop()
            if code==1:forms[fid]['end']=p
        elif raw[1]&128:
            fid=U(raw,2,2) if raw[0]==1 else None
            if fid is not None:
                assert fid not in forms;forms[fid]=dict(start=p,title=U(raw,4,2))
            stack.append((raw[0],fid,p))
        p+=n
    assert p==len(b) and not stack
    return ops,forms

def spf(b):
    assert b[:4]==b'$SPF' and U(b,0x44)==len(b)
    pt,cs,vs,aux=[U(b,p) for p in (0x2c,0x30,0x34,0x38)]
    assert pt<cs<vs<aux<=len(b)
    count=U(b,pt);pages=[];controls={}
    for i in range(count):
        p=U(b,pt+4+4*i);end=U(b,pt+8+4*i) if i+1<count else cs
        assert pt+4+4*count<=p<end<=cs
        r=b[p:end];n=U(r,28);assert U(r,16,2)==i and len(r)>=32+4*n
        refs=[U(r,32+j*4) for j in range(n)];pages.append(dict(raw=r,refs=refs))
        for rel in refs:
            if rel in controls:continue
            c=cs+rel;w=U(b,c+58,2);nd=b[c+16]
            tail=nd*4+2 if w==1 else (nd+1)*w*2
            assert c+64+tail<=vs
            controls[rel]=b[c:c+64+tail]
    cnt=U(b,vs);variables=[]
    for i in range(cnt):
        p=vs+U(b,vs+4+i*4);end=vs+U(b,vs+8+i*4) if i+1<cnt else aux
        assert end-p==124;variables.append(b[p:end])
    return dict(pages=pages,controls=controls,variables=variables,pt=pt,cs=cs,vs=vs,aux=aux)

def validate(old_hii,old_spf,new_hii,new_spf,old_pe,new_pe,meta):
    old_pk=packages(old_hii);new_pk=packages(new_hii)
    assert [x[3] for x in old_pk]==[x[3] for x in new_pk]==[2]+[4]*10+[0xdf]
    oo,of=ifr(old_pk[0]);no,nf=ifr(new_pk[0]);assert set(of)==set(nf)
    mapping={int(k):v for k,v in meta['old_ifr_offset_map'].items()}
    assert set(mapping)==set(oo) and len(set(mapping.values()))==len(mapping)
    for p,item in oo.items():assert item['raw']==no[mapping[p]]['raw']
    keep=set(meta['hii_metadata']['replaced_string_ids'].values());changes=[]
    for a,b in zip(old_pk[1:-1],new_pk[1:-1]):
        av,_=strings(a);bv,_=strings(b);modified={i for i in av if av[i]!=bv[i]}
        assert modified==keep
        for id in meta['value_ids'].values():assert id in bv
        changes.append(len(modified))
    original_meta=json.loads((ROOT/'analysis/hero_ipmi_p5/native-payload.json').read_text())
    assert list(meta['value_ids'].items())[:40]==list(original_meta['value_ids'].items())
    assert list(meta['value_ids'])[-1]=='CONFIG_STATUS' and len(meta['value_ids'])==41
    schema=meta['settings'];assert schema['name']=='HeroIpmiSettings'
    assert schema['guid']=='bef09fe1-8540-4be1-9082-e6624328f435'
    assert (schema['size'],schema['attributes'],schema['varstore_id'],schema['spf_variable_index'])==(32,3,0x3f00,119)
    default=bytes.fromhex(schema['default_hex']);assert default==bytes([0,0,0,10,1]+[0]*27)
    fields={f['question_id']:f for f in schema['fields']}
    assert len(fields)==21 and sorted(f['offset'] for f in fields.values())==list(range(21))
    assert schema['reserved_offsets']==list(range(21,32))
    assert all(f['width']==1 and f['minimum']<=default[f['offset']]<=f['maximum'] for f in fields.values())
    old_qids={U(x['raw'],6,2) for x in oo.values() if x['raw'][0] in (5,6,7,8,0xc,0xf,0x1a,0x1b,0x1c,0x23)}
    assert not old_qids&set(fields)
    retained_offsets=set(mapping.values())
    added={at:x for at,x in no.items() if at not in retained_offsets}
    declarations=[(at,x['raw']) for at,x in added.items() if x['raw'][0]==0x26]
    assert len(declarations)==1
    at,d=declarations[0]
    assert not (d[1]&128) and U(d,2,2)==schema['varstore_id']
    assert str(uuid.UUID(bytes_le=d[4:20]))==schema['guid'] and U(d,20)==3 and U(d,24,2)==32
    assert d[26:]==b'HeroIpmiSettings\0'
    assert all(not (x['raw'][0] in (0x24,0x25,0x26) and U(x['raw'],18 if x['raw'][0]==0x24 else 2,2)==0x3f00) for x in oo.values())
    questions={U(x['raw'],6,2):(at,x) for at,x in added.items() if x['raw'][0] in (5,7)}
    assert set(questions)==set(fields)
    defaults={}
    for qid,(at,item) in questions.items():
        raw=item['raw'];f=fields[qid];assert len(raw)==17 and raw[1]&128
        assert item['form']==f['form_id'] and raw[12]==0 # no callback/reset/read-only flags
        assert U(raw,8,2)==0x3f00 and U(raw,10,2)==f['offset'] and raw[13]==0x10
        assert raw[14:17]==bytes([f['minimum'],f['maximum'],1])
        assert U(raw,2,2)==meta['string_ids'][f['title_key']] and U(raw,4,2)==meta['string_ids'][f['help_key']]
        children=[v['raw'] for p,v in no.items() if v['parents'] and v['parents'][-1]==at and v['raw'][0]!=0x29]
        if raw[0]==5:
            assert all(len(c)==7 and c[0]==9 and c[5]==0 for c in children)
            assert [(c[6],U(c,2,2)) for c in children]==[(v,meta['string_ids'][s]) for v,s in f['options']]
            sd=[c[6] for c in children if c[4]&0x10];md=[c[6] for c in children if c[4]&0x20]
            assert sd==md==[default[f['offset']]]
        else:
            assert [c for c in children if c[0]!=0x5b]==[] and len(children)==2
            assert [(U(c,2,2),c[4],c[5]) for c in children]==[(0,0,default[f['offset']]),(1,0,default[f['offset']])]
        defaults[qid]=default[f['offset']]
    assert {v['raw'][0] for v in added.values()}=={3,5,7,9,0x26,0x29,0x5b}
    assert sum(x['raw'][0]==3 for x in added.values())==1
    os=spf(old_spf);ns=spf(new_spf)
    assert len(ns['pages'])==len(os['pages'])==304
    assert ns['variables'][:119]==os['variables'] and len(ns['variables'])==120
    vr=ns['variables'][119];assert str(uuid.UUID(bytes_le=vr[:16]))==schema['guid']
    assert vr[16:96].decode('utf-16le').rstrip('\0')==schema['name']
    assert (U(vr,0x60),U(vr,0x64),U(vr,0x68),U(vr,0x78,2))==(3,0x3f00,0x1000,32)
    assert vr[0x6c:0x78]==bytes(12) and vr[0x7a:]==b'\0\0'
    assert new_spf[ns['aux']+4:]==old_spf[os['aux']+4:]
    assert U(new_spf,ns['aux'])==len(new_pk[0])
    assert new_spf[:0x30]==old_spf[:0x30] and new_spf[0x48:0x60]==old_spf[0x48:0x60]
    old_len=os['vs']-os['cs'];new_controls={k:v for k,v in ns['controls'].items() if k>=old_len}
    assert len(new_controls)==22
    old_cb=bytearray(new_spf[ns['cs']:ns['cs']+old_len])
    for rel,raw in os['controls'].items():
        now=ns['controls'][rel];restored=bytearray(now)
        if U(raw,38,2)==1:
            old_at=U(raw,40,8);new_at=U(now,40,8);cond=S(raw,48)
            assert new_at==(mapping[old_at] if old_at else 0)
            if cond:
                target=old_at+cond if old_at else cond
                assert S(now,48)==mapping[target]-new_at if old_at else S(now,48)==mapping[target]
            else:assert S(now,48)==0
            restored[40:56]=raw[40:56]
        if U(raw,22,2)==299:restored[36:38]=raw[36:38]
        assert bytes(restored)==raw
        old_cb[rel:rel+len(raw)]=restored
    assert old_cb==old_spf[os['cs']:os['vs']]
    new_control_qids=set()
    for rel,c in new_controls.items():
        at=U(c,40,8);item=no[at];assert at in added
        assert U(c,38,2)==1 and U(c,28)==1 and U(c,24,2)==0xffff and S(c,48)==0
        assert c[:8]==bytes(8) and c[14:16]==bytes(2) and c[17:20]==bytes(3) and c[26:28]==bytes(2)
        assert U(c,32,2)==U(item['raw'],4,2) and U(c,34,2)==0 and U(c,60,2)==U(item['raw'],2,2)
        if item['raw'][0]==3:
            assert len(c)==64 and U(c,20,2)==3 and U(c,8)==0 and U(c,12,2)==0 and c[56:60]==bytes(4)
            continue
        qid=U(c,12,2);f=fields[qid];new_control_qids.add(qid)
        assert U(c,8)==119 and U(c,20,2)==(6 if f['control']=='oneof' else 11)
        assert U(c,56,2)==U(c,58,2)==1
        assert c[64:66]==bytes([f['default']]*2)
        if f['control']=='oneof':assert c[16]==0 and len(c)==66
        else:
            assert c[16]==2 and len(c)==74
            assert c[66:]==struct.pack('<HBBHBB',0,f['default'],0,1,f['default'],0)
    assert new_control_qids==set(fields)
    for i,(a,b) in enumerate(zip(os['pages'],ns['pages'])):
        old_refs=a['refs'];new_refs=b['refs']
        assert [x for x in new_refs if x<old_len]==old_refs
        if i not in (299,300,301,302):assert b['raw']==a['raw']
        else:
            assert a['raw'][:28]==b['raw'][:28]
            for j,rel in enumerate(new_refs):assert U(ns['controls'][rel],36,2)==j
            assert [U(ns['controls'][r],40,8) for r in new_refs]==sorted(U(ns['controls'][r],40,8) for r in new_refs)
    a=pefile.PE(data=old_pe);b=pefile.PE(data=new_pe)
    assert a.OPTIONAL_HEADER.AddressOfEntryPoint==b.OPTIONAL_HEADER.AddressOfEntryPoint
    assert b.verify_checksum() and len(a.sections)==len(b.sections)==6
    for sa,sb in zip(a.sections[:4],b.sections[:4]):
        assert sa.get_data()==sb.get_data() and sa.VirtualAddress==sb.VirtualAddress
    assert a.sections[-1].get_data()==b.sections[-1].get_data()
    assert [(e.type,e.rva) for x in a.DIRECTORY_ENTRY_BASERELOC for e in x.entries]==[(e.type,e.rva) for x in b.DIRECTORY_ENTRY_BASERELOC for e in x.entries]
    entry=b.DIRECTORY_ENTRY_RESOURCE.entries[0].directory.entries[0].directory.entries[0].data.struct
    off=b.get_offset_from_rva(entry.OffsetToData);assert new_pe[off:off+len(new_hii)]==new_hii
    return dict(old_ifr_opcodes_preserved=len(oo),old_form_count=len(of),old_controls_preserved=len(os['controls']),
                old_variables_preserved=119,added_variable_index=119,new_question_controls=21,new_status_controls=1,
                dynamic_status_strings=41,language_count=10,explicit_existing_string_changes=changes,
                native_defaults_match_backend_32_bytes=True,no_callback_flags=True,
                old_setup_code_sections_byte_identical=True,relocations_byte_identical=True)

def main():
    p5=ROOT/'analysis/hero_ipmi_p5';meta=json.loads((HERE/'native-payload.json').read_text())
    old_hii=(p5/'Setup-HII-P5.bin').read_bytes();old_spf=(p5/'AMITSESetupData-P5.bin').read_bytes()
    new_hii=(HERE/'Setup-HII-P6.bin').read_bytes();new_spf=(HERE/'AMITSESetupData-P6.bin').read_bytes()
    old_pe=(ROOT/'analysis/hero_remote_bios_r3/reference/HERO-3107-Setup.efi').read_bytes();new_pe=(HERE/'Setup-P6-RESOURCE-REVIEW.efi').read_bytes()
    report=validate(old_hii,old_spf,new_hii,new_spf,old_pe,new_pe,meta)
    # Mutations are applied only in memory to prove rejection at the
    # independent boundaries; no artifact or firmware is altered.
    cases=[];s=spf(new_spf)
    for name,pos,bit in [('new_variable_attrs',s['vs']+U(new_spf,s['vs']+4+119*4)+0x60,4),
                         ('new_variable_size',s['vs']+U(new_spf,s['vs']+4+119*4)+0x78,1),
                         ('old_variable_modified',s['vs']+U(new_spf,s['vs']+4)+16,1),
                         ('old_control_modified',s['cs']+min(s['controls'])+20,1)]:
        mutated=bytearray(new_spf);mutated[pos]^=bit
        try:validate(old_hii,old_spf,new_hii,bytes(mutated),old_pe,new_pe,meta)
        except (AssertionError,KeyError,ValueError,UnicodeError):cases.append(dict(name=name,rejected=True))
        else:raise AssertionError(('corruption not rejected',name))
    report.update(result='PASS',negative_mutations=cases,
        artifacts={f:dict(bytes=(HERE/f).stat().st_size,sha256=digest((HERE/f).read_bytes())) for f in meta['files']},
        verification_script_sha256=digest(Path(__file__).read_bytes()),
        limitations=['Offline structural validation does not prove target hardware F10 behavior or backend command correctness.'])
    (HERE/'independent-verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()

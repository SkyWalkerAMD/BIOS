"""Read-only inventory of native HERO IFR and SPF variable/control records."""
from pathlib import Path
from collections import Counter
import importlib.util,json,struct,sys,uuid
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
sys.dont_write_bytecode=True
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
b=load('p5build',ROOT/'analysis/hero_ipmi_p5/build_native_payload.py')
v=load('p5verify',ROOT/'analysis/hero_ipmi_p5/verify_native_payload.py')
u=lambda x,o,n=4:int.from_bytes(x[o:o+n],'little')
spf=(ROOT/'analysis/hero_ipmi_p1b/reference/HERO-3107-AMITSESetupData.bin').read_bytes()
forms=(ROOT/'analysis/hero_ipmi_p3/reference/HERO-3107-forms.bin').read_bytes()
pages,controls=v.spf(spf);formmap,ops=v.ifr(forms)
hii=(ROOT/'analysis/hero_ipmi_p5/Setup-HII-P5.bin').read_bytes()
tokens=next(vals for lang,_,vals in [b.string_tokens(p) for p in b.read_packages(hii) if p[3]==4] if lang=='en-US')
vs=u(spf,0x34);ve=u(spf,0x38);count=u(spf,vs)
records=[]
for i in range(count):
 start=u(spf,vs+4+4*i);end=u(spf,vs+8+4*i) if i+1<count else ve-vs
 raw=spf[vs+start:vs+end]
 assert len(raw)==124
 records.append(dict(index=i,relative_offset=hex(start),guid=str(uuid.UUID(bytes_le=raw[:16])),
  name=raw[16:96].decode('utf-16le').rstrip('\0'),attrs=hex(u(raw,96)),var_id=hex(u(raw,100)),
  flags_104=hex(u(raw,104)),name_token_108=hex(u(raw,108,2)),hii_handle_112=hex(u(raw,112,8)),size=u(raw,120,2),raw=raw.hex()))
ifr_stores=[]
for off,raw in ops.items():
 if raw[0] in (0x24,0x25,0x26):
  ifr_stores.append(dict(offset=hex(off),op=hex(raw[0]),raw=raw.hex()))
selected=[];types=Counter();default_shapes=Counter()
for off,raw in controls.items():
 types[(u(raw,20,2),u(raw,38,2))]+=1
 if u(raw,38,2)!=1:continue
 code=u(raw,40,8)
 if code not in ops or ops[code][0] not in (5,6,7):continue
 op=ops[code];default_shapes[(raw[16],u(raw,58,2),len(raw))]+=1
 selected.append(dict(offset=hex(off),ifr_offset=hex(code),name=tokens.get(u(op,2,2)),
  help=tokens.get(u(op,4,2)),type=u(raw,20,2),varindex=u(raw,8),question=hex(u(raw,12,2)),
  explicit_default_count=raw[16],page=u(raw,22,2),value_width=u(raw,58,2),raw=raw.hex(),ifr=op.hex()))
out=dict(variable_section_offset=hex(vs),variable_section_bytes=ve-vs,variable_record_bytes=124,variables=records,
 ifr_stores=ifr_stores,control_examples=selected,control_type_counts={str(k):x for k,x in types.items()},default_shapes={str(k):x for k,x in default_shapes.items()})
(P/'native-inventory.json').write_text(json.dumps(out,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
print('variables',len(records),'stores',len(ifr_stores),'controls',len(selected),'default_shapes',dict(default_shapes))
for r in records:print(r['index'],r['name'],r['var_id'],r['attrs'],r['flags_104'],r['name_token_108'],r['hii_handle_112'],r['size'])
for typ in (5,6,7):
 print('CONTROL TYPE',typ)
 for r in [x for x in selected if int(x['ifr'][:2],16)==typ][:5]:print(r)

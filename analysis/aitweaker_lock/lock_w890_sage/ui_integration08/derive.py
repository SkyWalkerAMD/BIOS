"""Prepare unified headers and source; compile only after pinned inputs freeze."""
from pathlib import Path
import hashlib,json,re
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3];N=B/'navigation05';A=B/'navigation08';F=B/'foreign_page08';G=B/'observer_generation08/revision03'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def quoted_includes(text,source):
 return re.sub(r'^#include "([^"]+)"',lambda m:'#include "'+(source.parent/m.group(1)).resolve().as_posix()+'"',text,flags=re.M)
def replace(text,before,after):
 assert text.count(before)==1,before
 return text.replace(before,after)
inputs={
 'foreign':(F/'component_manifest.json','1e6b5ee40846e8fb8b37287f99f3d7955bd5636bd3c1fb845fc7025f2e906f5c'),
 # The exact final navigation/generation digests are supplied by the local
 # composition record after their independent reviews, not inferred here.
}
pins=json.loads((H/'input_pins.json').read_text())
for name in ('navigation','generation'):
 inputs[name]=(R/pins[name]['path'],pins[name]['sha256'])
for name,(p,d) in inputs.items():
 assert sha(p)==d,(name,p)
 m=json.loads(p.read_text())
 for key in ('files','local_bindings','external_bindings','dependencies'):
  for x in m.get(key,[]):
   if isinstance(x,dict) and 'path' in x and 'sha256' in x:assert sha(R/x['path'])==x['sha256'],x['path']

# One forced-included snapshot ABI for every C translation unit.
gh=B/'navigation/gate_adapter.h';g=gh.read_text()
g=replace(g,' uint8_t formset[16],ifr[127];',' uint8_t formset[16],ifr[127];\n uint64_t catalog_generation;int32_t classification;uint32_t reserved_scope;')
(H/'gate_adapter.h').write_text(g)

s=(G/'observer08r3.c').read_text()
s='#include "'+(F/'foreign_page.h').as_posix()+'"\n'+s
s=replace(s,'uint8_t active,pad[7];};','uint8_t active,pad[7];FP08_VIEW foreign_view;};')
insert='static int form_opcode(uint16_t wanted,const uint8_t *opcode,UN length){'
s=replace(s,insert,'#include "foreign_observer.inc"\n'+insert)
start=s.index('API ES EA no_native_send_form(');end=s.index('API ES EA no_native_entry(',start)
s=s[:start]+(A/'send_form08.inc').read_text()+s[end:]
old='uintptr_t app,page;uint32_t index;if(!app_read(&app,&index,&page)||!page_identity(page,index))return 0;mint(&s.effect,kind,object,caller);'
new='uintptr_t app,page;uint32_t index;FP08_VIEW view;uint64_t generation=s.catalog_generation;if(!app_read(&app,&index,&page)||!ui08_page_view(page,index,&view)||generation!=s.catalog_generation||!frame_active()||s.effect.active)return 0;mint(&s.effect,kind,object,caller);s.effect.foreign_view=view;'
s=replace(s,old,new)
s=replace(s,' return page_identity(page,index);\n}\nint EA no_scope_validate(',
 ' return ui08_ticket_page_cached(t,page,index);\n}\nint EA no_scope_validate(')
old=' if(!page_identity(page,index))return 0;WG_SNAPSHOT q;zero(&q,sizeof(q));q.session=s.native_visit;'
new=' if(!no_range(page,0x68,NO_READ))return 0;int foreign=u64((void *)(page+0x20))!=(uintptr_t)s.setup_hii;if(!foreign&&!page_identity(page,index))return 0;WG_SNAPSHOT q;zero(&q,sizeof(q));q.classification=W890_UNKNOWN;q.catalog_generation=s.catalog_generation;q.session=s.native_visit;'
s=replace(s,old,new)
old=' if(point==WG_CONTROL_INPUT){if(!control||!control_identity(page,control,q.ifr,&q.ifr_size))return 0;q.control=control;q.proof|=WG_CONTROL;}\n if(!frame_active()||readg(0xafdd0)!=app)return 0;cp(out,&q,sizeof(q));return 1;'
new=''' if(foreign){if(!ui08_foreign_snapshot(app,page,index,point==WG_CONTROL_INPUT?control:0,&q))return 0;}
 else{
  if(point==WG_CONTROL_INPUT){if(!control||!control_identity(page,control,q.ifr,&q.ifr_size))return 0;q.control=control;q.proof|=WG_CONTROL;}
  q.classification=point==WG_CONTROL_INPUT?w890_classify_control(q.formset,q.form,q.ifr,q.ifr_size):w890_classify_form(q.formset,q.form);
 }
 if(!frame_active()||readg(0xafdd0)!=app||q.catalog_generation!=s.catalog_generation)return 0;cp(out,&q,sizeof(q));return 1;'''
s=replace(s,old,new)
# Keep the published Setup management path and its private token validation.
old_include='#include "'+(B/'observer_generation08/visit/form_descriptor.inc').as_posix()+'"'
fd=(N/'visit/form_descriptor.inc').read_text()
fd=replace(fd,' if(!no_scope_validate_cached(t)||readg(0xbaaf0)!=pt',
 ' q.catalog_generation=s.catalog_generation;q.classification=w890_classify_control(q.formset,q.form,q.ifr,q.ifr_size);\n if(!no_scope_validate_cached(t)||readg(0xbaaf0)!=pt')
(H/'form_descriptor.inc').write_text(fd)
s=replace(s,old_include,'#include "form_descriptor.inc"')
s+='\nAPI size_t EA ui08_snapshot_bytes(void){return sizeof(WG_SNAPSHOT);}\n'
(H/'observer08.c').write_text(s)

nav=quoted_includes((N/'navigation.c').read_text(),N/'navigation.c')
nav=replace(nav,'&&s->session&&s->hii==(uintptr_t)bound.hii;','&&s->session;')
nav=replace(nav,'u64(page+0x20)!=p->source.hii','u64(page+0x20)!=(uintptr_t)bound.hii')
nav=replace(nav,'int kind=point==WG_CONTROL_INPUT?w890_classify_control(first.formset,first.form,first.ifr,first.ifr_size):w890_classify_form(first.formset,first.form);','int kind=first.classification;')
(H/'navigation08.c').write_text(nav)
br=(A/'bridges08.c').read_text()
br=quoted_includes(br,A/'bridges08.c')
br=replace(br,'int kind=w890_classify_control(out->formset,out->form,out->ifr,out->ifr_size);','int kind=out->classification;')
(H/'bridges08.c').write_text(br)
sources=[H/'derive.py',H/'foreign_observer.inc',gh,G/'observer08r3.c',N/'navigation.c',N/'visit/form_descriptor.inc',A/'bridges08.c',A/'send_form08.inc']
record={'status':'UNIFIED_SOURCE_NOT_A_FLASHABLE_IMAGE','parents':{k:{'path':str(p.relative_to(R)),'sha256':sha(p)} for k,(p,_) in inputs.items()},
 'derivation_sources':{str(p.relative_to(R)):sha(p) for p in sources},
 'generated':{str(p.relative_to(R)):sha(p) for p in [H/x for x in ('gate_adapter.h','observer08.c','navigation08.c','bridges08.c','form_descriptor.inc')]},
 'test_host_included':False,'test_consumer_included':False}
(H/'derivation.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'generated_files':len(record['generated']),'parents':list(inputs)}))

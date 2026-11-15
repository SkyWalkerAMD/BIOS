"""Separate catalog invalidation from private BIOS-visit identity.

Compile only a local component. Frozen sources and firmware stay unchanged.
"""
from pathlib import Path
import hashlib,json
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3];N=B/'navigation05'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
mf=N/'component_manifest.json'
assert sha(mf)=='cef2904ca901f91b1b63d3ff23b7e262754e8513380382e85ec0c55e7c912497'
pins={N/'visit/observer_visit05.c':'5099f88d05c317e80a6c50c86bd1858f757254b2508ddd10f81ce2361fa9dc9a',
 N/'build.py':'edbcf0c186c0a83a57d87fff6f27634857727ce8e02800ba548a1de67b073cc2'}
for p,d in pins.items():assert sha(p)==d
V=H/'visit';V.mkdir(exist_ok=True)
for name in ('restricted_profile.h','restricted_check.inc','form_descriptor.inc'):(V/name).write_bytes((N/'visit'/name).read_bytes())
s=(N/'visit/observer_visit05.c').read_text()
def change(before,after):
 global s
 assert s.count(before)==1, before
 s=s.replace(before,after)
change('uint64_t magic,epoch,sequence;','uint64_t magic,epoch,sequence,catalog_generation;')
change('uint64_t epoch,sequence,provider_token,pubtoken,native_visit,visit_sequence;',
 'uint64_t epoch,sequence,provider_token,pubtoken,native_visit,visit_sequence,catalog_generation;')
change('s.getvar=st->rt->get_variable;s.epoch=1;',
 's.getvar=st->rt->get_variable;s.epoch=1;s.catalog_generation=1;')
change('t->active&&t->epoch==s.epoch&&t->depth==s.depth',
 't->active&&t->epoch==s.epoch&&t->catalog_generation==s.catalog_generation&&t->depth==s.depth')
change('t->epoch=s.epoch;t->sequence=++s.sequence;',
 't->epoch=s.epoch;t->catalog_generation=s.catalog_generation;t->sequence=++s.sequence;')
old=''' (void)guid;(void)package;if(type==2&&(kind&11)){
  s.epoch++;s.effect.active=s.lease.active=s.manage.active=0;'''
new=''' (void)guid;(void)package;if(type==2&&(kind&11)){
  if(!handle||s.catalog_generation==UINT64_MAX){revoke();return 0;}
  s.catalog_generation++;
  if(handle!=s.setup_hii){
   /* A foreign catalog change invalidates proofs, not the native visit.
    * Keep an existing ticket occupied until its original owner leaves:
    * otherwise reentry could reuse the same private ticket pointer. */
   return 0;
  }
  s.epoch++;s.effect.active=s.lease.active=s.manage.active=0;'''
change(old,new)
s+='''
/* Read-only stamp. A private active native visit is still required; this
 * cannot create a ticket or authorize a page, callback or variable write. */
API int EA no_catalog_generation(uint64_t *out){
 if(!out||!frame_active()||!identity_live(0)||!no_range((uintptr_t)out,8,NO_WRITE))return 0;
 *out=s.catalog_generation;return s.catalog_generation!=0;
}
'''
(V/'observer08.c').write_text(s)
t=(N/'build.py').read_text()
t=t.replace("O=H/'build'",'O=Path('+repr(str(H/'build'))+')')
t=t.replace("B/'native_observer04/observer.c'",','.join('Path('+repr(str(p))+')' for p in (V/'observer08.c',N/'visit/restricted_catalog.c',H/'test_consumer.c')))
t=t.replace('assert len(calls)==2,calls','assert len(calls)==4,calls')
t=t.replace("out=O/'W890Navigation05.TESTONLY.dll'","exports += ['no_native_visit_identity','no_describe_form_callback','no_catalog_generation','og08_test_read','og08_test_nested']\nout=O/'W890ObserverGeneration08.TESTONLY.dll'")
exec(compile(t,str(N/'build.py'),'exec'),{'__file__':str(N/'build.py'),'__name__':'generation08_build'})
p=H/'build/build.json';m=json.loads(p.read_text())
extra=[H/'build.py',mf,*pins,*[V/x for x in ('restricted_profile.h','restricted_check.inc','form_descriptor.inc')]]
m['sources'].update({str(p.relative_to(R)):sha(p) for p in extra})
m['status']='CATALOG_GENERATION_CANDIDATE_NOT_AGGREGATE'
m['unchanged_boundaries']=['Unknown Setup FORMS changes still revoke identity.',
 'Original navigation05 limited page recognition and pending bridges are not claimed repaired by this isolated component.',
 'Foreign callbacks gain no new invocation or variable permission.']
p.write_text(json.dumps(m,indent=2)+'\n')

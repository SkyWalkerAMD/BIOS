"""Post-service revalidation repair; preserve the frozen revision01 evidence."""
from pathlib import Path
import hashlib,json,re
H=Path(__file__).resolve().parent;P=H.parent;B=P.parent;R=B.parents[2];N=B/'navigation05'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
mf=P/'component_manifest.json'
assert sha(mf)=='4fc68d969c583e39cf1bfbf798dcf52c5bcc6a7fe4e00e8616eb168b9e778d30'
j=json.loads(mf.read_text())
for x in j['files']+j['external_bindings']:assert sha(R/x['path'])==x['sha256']
src=P/'visit/observer08.c';s=src.read_text()
def change(before,after):
 global s
 assert s.count(before)==1,before
 s=s.replace(before,after)
# A modeled service may deliver a registered notification before returning.
change(' return 1;\nfailed:revoke();return 0;\n}',
 ' return !s.fault&&!s.ended;\nfailed:revoke();return 0;\n}')
change('if(!frame_active()||!s.native_visit||!identity_live(0)||!no_range((uintptr_t)visit,8,NO_WRITE)',
 'if(!frame_active()||!s.native_visit||!identity_live(0)||!frame_active()||!s.native_visit||!no_range((uintptr_t)visit,8,NO_WRITE)')
change('if(!out||!frame_active()||!identity_live(0)||!no_range((uintptr_t)out,8,NO_WRITE))return 0;',
 'if(!out||!frame_active()||!identity_live(0)||!frame_active()||!no_range((uintptr_t)out,8,NO_WRITE))return 0;')
change('!callsite(caller,NO_CALL_EFFECT)||!identity_live(1)||!no_range((uintptr_t)out,sizeof(*out),NO_WRITE)',
 '!callsite(caller,NO_CALL_EFFECT)||!identity_live(1)||!frame_active()||s.effect.active||!no_range((uintptr_t)out,sizeof(*out),NO_WRITE)')
change('if(!out||s.lease.active||!cold()||!identity_live(1)||!no_range((uintptr_t)out,sizeof(*out),NO_WRITE))',
 'if(!out||s.lease.active||!cold()||!identity_live(1)||s.lease.active||!cold()||!no_range((uintptr_t)out,sizeof(*out),NO_WRITE))')
change('return ticket&&ticket==s.pubtoken&&cold()&&identity_live(0);',
 'return ticket&&ticket==s.pubtoken&&cold()&&identity_live(0)&&ticket==s.pubtoken&&cold();')
change('!frame_active()||!identity_live(0)||!no_range((uintptr_t)value,2,NO_READ)',
 '!frame_active()||!identity_live(0)||!frame_active()||s.manage.active||!no_range((uintptr_t)value,2,NO_READ)')
change('&&management_control(page,s.manage.object,s.management_qid);',
 '&&management_control(page,s.manage.object,s.management_qid)&&ticket_valid(&s.manage)&&frame_active();')
# Resolve local quoted includes against their actual immutable input location.
s=re.sub(r'^#include "([^"]+)"',lambda m:'#include "'+(src.parent/m.group(1)).resolve().as_posix()+'"',s,flags=re.M)
(H/'observer08r2.c').write_text(s)
t=(N/'build.py').read_text().replace("O=H/'build'",'O=Path('+repr(str(H/'build'))+')')
t=t.replace("B/'native_observer04/observer.c'",','.join('Path('+repr(str(p))+')' for p in (H/'observer08r2.c',N/'visit/restricted_catalog.c',P/'test_consumer.c')))
t=t.replace('assert len(calls)==2,calls','assert len(calls)==4,calls')
t=t.replace("out=O/'W890Navigation05.TESTONLY.dll'","exports += ['no_native_visit_identity','no_describe_form_callback','no_catalog_generation','og08_test_read','og08_test_nested']\nout=O/'W890ObserverGeneration08r2.TESTONLY.dll'")
exec(compile(t,str(N/'build.py'),'exec'),{'__file__':str(N/'build.py'),'__name__':'generation08r2_build'})
p=H/'build/build.json';m=json.loads(p.read_text())
extra=[Path(__file__),mf,src,N/'build.py',*[P/'visit'/x for x in ('restricted_profile.h','restricted_check.inc','form_descriptor.inc')]]
m['sources'].update({str(p.relative_to(R)):sha(p) for p in extra})
m['status']='POST_SERVICE_REVALIDATION_REPAIR_NOT_AGGREGATE'
m['test_only_exports']=['og08_test_read','og08_test_nested']
p.write_text(json.dumps(m,indent=2)+'\n')
v=(P/'verify_generation.py').read_text().replace('H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]',
 'H=Path(__file__).resolve().parent;B=H.parents[1];R=B.parents[2]')
v=v.replace('W890ObserverGeneration08.TESTONLY.dll','W890ObserverGeneration08r2.TESTONLY.dll')
(H/'verify_generation.py').write_text(v)

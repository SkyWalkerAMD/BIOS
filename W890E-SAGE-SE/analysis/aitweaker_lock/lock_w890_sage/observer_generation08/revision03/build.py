"""Retire tickets only when their actual owning frame leaves."""
from pathlib import Path
H=Path(__file__).resolve().parent;prior=H.parent/'revision02/build.py'
t=prior.read_text()
anchor='# Resolve local quoted includes against their actual immutable input location.'
assert t.count(anchor)==1
fix='''change('s.depth--;zero(f,sizeof(*f));s.effect.active=s.manage.active=s.lease.active=0;',
 'NO_TICKET *owned[3]={&s.effect,&s.manage,&s.lease};for(unsigned i=0;i<3;i++)if(owned[i]->frame==(uintptr_t)f&&owned[i]->depth==s.depth)owned[i]->active=0;s.depth--;zero(f,sizeof(*f));')
'''
t=t.replace(anchor,fix+anchor).replace('observer08r2.c','observer08r3.c').replace('W890ObserverGeneration08r2','W890ObserverGeneration08r3')
exec(compile(t,str(prior),'exec'),{'__file__':str(H/'build.py'),'__name__':'generation08r3_build'})
# The derivation script above is also part of the exact reproducible input.
import json,hashlib
p=H/'build/build.json';j=json.loads(p.read_text());R=H.parents[4]
j['sources'][str(prior.relative_to(R))]=hashlib.sha256(prior.read_bytes()).hexdigest()
j['status']='FRAME_OWNED_TICKET_RETIREMENT_AND_POST_SERVICE_REVALIDATION_NOT_AGGREGATE'
p.write_text(json.dumps(j,indent=2)+'\n')

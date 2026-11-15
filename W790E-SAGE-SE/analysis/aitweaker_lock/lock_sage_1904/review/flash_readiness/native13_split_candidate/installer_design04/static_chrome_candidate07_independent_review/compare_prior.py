"""Check whether post-HII generic fallback predates the isolated exception."""
from pathlib import Path
import hashlib,json,sys
HERE=Path(__file__).resolve().parent
source=(HERE/'independent_cases.py').read_text().split('\nv=ChromeVM();assert',1)[0]
source=source.replace("split_source=(SNAP/'verify_split.py').read_text()","split_source=(D04/'split_core/verify_split.py').read_text()")
source=source.replace("module.__file__=str(SNAP/'verify_split.py')","module.__file__=str(D04/'split_core/verify_split.py')")
scope={'__file__':str(HERE/'independent_cases.py')}
exec(compile(source,str(HERE/'independent_cases.py')+' [old frozen split input]','exec'),scope)
V,TSE,q,ns=[scope[x]for x in ['ChromeVM','TSE','q','ns']]
rows=[]
for name,mutate in [
 ('nonzero_object_callback',lambda v:v.u.mem_write(v.control+8,q(TSE+0x11164))),
 ('nonzero_expression',lambda v:v.u.mem_write(v.control+0x50,q(v.ifr))),
 ('wrong_control_vtable',lambda v:v.u.mem_write(v.control,q(TSE+0x6bbe0))),
]:
 for hii in ['sentinel','setup','foreign']:
  v=V();handle={'sentinel':0xffffffffffffffff,'setup':v.handle,'foreign':0x99998888}[hii]
  v.u.mem_write(v.control+0x20,q(handle));mutate(v)
  result=v.classified();assert result==0 if hii!='sentinel'else result in [0xffffffff,0xffffffffffffffff]
  rows.append({'case':name+'_source_'+hii,'classification':hex(result),'accepted':result==0})
report={'status':'CONFIRMED_EXISTING_GENERIC_FALLBACK_NOT_INTRODUCED_BY_CHROME_EXCEPTION',
 'prior_template_sha256':ns['SPLIT_META']['template_sha256'],'cases':rows,
 'limit':'Post-HII acceptance already exists in frozen guard; this is not evidence of a new credential bypass. A new strict static-class guarantee must still avoid silently inheriting that fallback.'}
(HERE/'prior_fallback_comparison.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))

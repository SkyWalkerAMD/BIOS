"""Stage the known P5 sources for P6; never change RC2/RC3 inputs."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
P5=ROOT/'analysis/hero_ipmi_p5/source'
OUT=HERE/'source'

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    selected=['common.c','probe_core.c','probe_core.h','command_policy.c','presentation.c',
        'publisher.c','transport.c','driver.c','p1.h','p5.h','r2.h','efi_min.h',
        'compat/string.h','compat/stdlib.h','compat/assert.h']
    records=[]
    for name in selected:
        b=(P5/name).read_bytes();p=OUT/name
        if p.exists(): raise RuntimeError('Refusing to overwrite work in progress: '+str(p))
        p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
        records.append(dict(path=name,sha256=hashlib.sha256(b).hexdigest()))
    (HERE/'source-baseline.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
    print('Staged',len(records),'P5 source files')

if __name__=='__main__':main()

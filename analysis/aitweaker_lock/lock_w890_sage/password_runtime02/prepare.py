from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
SRC=ROOT/'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness/native13_split_candidate/installer_design04/provider15_diagnostic09/source'
OUT=HERE/'source';OUT.mkdir(parents=True,exist_ok=True)
rows=[]
for name in ['efi.h','cpu_entropy.c']:
    source=SRC/name;text=source.read_text(encoding='utf8')
    # Remove the doubled line endings in the historical archive, no token edit.
    text='\n'.join(text.splitlines()[::2]) if '\n\n' in text[:100] else text
    if name=='cpu_entropy.c':text=text.replace('#include "provider.h"','#include "runtime.h"')
    target=OUT/name;target.write_text(text+'\n',encoding='utf8',newline='\n')
    rows.append({'source':str(source.relative_to(ROOT)),'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                 'target':str(target.relative_to(HERE)),'target_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
                 'changes':['normalize historical doubled line breaks']+(['include runtime.h']if name.endswith('.c')else[])})
(HERE/'derivation.json').write_text(json.dumps({'rows':rows},indent=2)+'\n')

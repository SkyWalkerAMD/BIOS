"""Copy immutable reviewed core/UI inputs into this isolated candidate only."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2]
if (HERE/'source_origins.json').exists():
    raise SystemExit('Bootstrap already recorded. Preserve the reviewed source snapshot; build_state.py and build_driver.py use it directly. This bootstrap must not overwrite adapted UI code.')
SRC=HERE/'source';SRC.mkdir(parents=True,exist_ok=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
sources={}
for name,src in {
 'efi.h':CASE/'driver/efi.h',
 'password_core.h':CASE/'core/password_core.h',
 'password_core.c':CASE/'core/password_core.c',
 'password_crypto.c':CASE/'core/password_crypto.c',
 'cpu_entropy.c':CASE/'driver/cpu_entropy.c',
 'ui.c':HERE.parent/'late_attach_candidate/ui.c',
 'policy.c':CASE/'driver/policy.c',
 'policy_data.h':CASE/'driver/policy_data.h',
}.items():
    raw=src.read_bytes();text=raw.decode('utf-8').replace('#include "lock.h"','#include "provider.h"')
    (SRC/name).write_text(text,encoding='utf-8')
    sources[name]={'source_path':str(src),'source_sha256':sha(src),'copied_sha256':sha(SRC/name),
                   'change':'include provider.h' if raw.decode('utf-8')!=text else 'none'}
(HERE/'source_origins.json').write_text(json.dumps(sources,indent=2)+'\n')
print(json.dumps({'sources':len(sources),'output':str(SRC)}))

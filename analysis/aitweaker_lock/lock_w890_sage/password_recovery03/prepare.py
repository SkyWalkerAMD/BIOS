from pathlib import Path
import hashlib,json,re,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;R=HERE.parent/'password_runtime02';P=HERE.parent/'password'
S=HERE/'source';S.mkdir(parents=True,exist_ok=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for base in [R,P]:
    manifest=json.loads((base/'component_manifest.json').read_text())
    for path,item in manifest['bindings'].items():assert sha(base/path)==item['sha256'],str(base/path)
rows=[]
for source,target in [(R/'source/efi.h',S/'efi.h'),(P/'core/password_core.h',S/'password_core.h'),
                      (P/'core/password_core.c',S/'password_core.c'),(P/'core/password_crypto.c',S/'password_crypto.c')]:
    target.write_bytes(source.read_bytes());rows.append({'source':str(source),'sha256':sha(source),'target':str(target.relative_to(HERE)),'changes':[]})
source=R/'source/ui.c'
text=source.read_text().split('static void message(AP_STATUS status)')[0]
text=text.replace('#include "runtime.h"','#include "recovery.h"')
for old,new in [('w890_runtime_active','rc_alive'),('w890_system_table','rc_st'),('w890_memory_present','rc_present'),('w890_alloc','rc_alloc'),('w890_release','rc_release')]:text=text.replace(old,new)
(S/'ui_engine.inc').write_text(text,encoding='utf8')
rows.append({'source':str(source),'sha256':sha(source),'target':'source/ui_engine.inc','changes':['copy only capture/restore/masked-input engine before management message()','rename runtime helpers to standalone recovery lifecycle']})
source=R/'source/services.c';text=source.read_text();text=text[text.index('int w890_memory_present('):text.index('AP_READ_RESULT w890_read_record(')]
text=text.replace('w890_memory_present','rc_present').replace('w890_runtime_ended','rc_ended')
(S/'memory.inc').write_text(text,encoding='utf8')
rows.append({'source':str(source),'sha256':sha(source),'target':'source/memory.inc','changes':['extract standalone page-walker function','rename lifecycle/helper symbols']})
(HERE/'derivation.json').write_text(json.dumps({'sources':rows,'frozen_runtime_manifest':sha(R/'component_manifest.json'),'frozen_password_manifest':sha(P/'component_manifest.json')},indent=2)+'\n')
print('Prepared frozen source derivations',len(rows))

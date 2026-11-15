"""Create an isolated permission/owned-allocation prerequisite; preserve EP3."""
from pathlib import Path
import hashlib,json,shutil
HERE=Path(__file__).resolve().parent
OLD=HERE/'entry_probe03';NEW=HERE/'installer_design04/prerequisite_probe04'
NEW.mkdir(parents=True,exist_ok=True)
if (NEW/'source').exists():raise FileExistsError('Initial seed only; preserving reviewed candidate source edits')
shutil.copytree(OLD/'source',NEW/'source')
for name in ['build_probe.py','run_ovmf_probe.py','decode_probe.py']:
 text=(OLD/name).read_text().replace('CASE=HERE.parents[3]','CASE=HERE.parents[4]')
 text=text.replace('SageNative13EntryContext03','SageNative13Prerequisite04').replace('SAGE-N13-READONLY-ENTRY-CONTEXT03','SAGE-N13-OWNED-PREREQUISITE04').replace('SAGE_NATIVE13_ENTRY_CONTEXT03_READONLY','SAGE_NATIVE13_PREREQUISITE04_OWNED_ONLY').replace('SAGE_NATIVE13_ENTRY_CONTEXT03_END','SAGE_NATIVE13_PREREQUISITE04_END')
 (NEW/name).write_text(text)
shutil.copyfile(OLD/'identity_binding.json',NEW/'identity_binding.json')
source=(OLD/'source/preflight.c').read_text()
source=source[source.index('#include "efi.h"'):]
source='/* Diagnostic prerequisite. Only exclusively allocated temporary pages may be written or have attributes changed. No OEM patch, variable, native UI, flash or disk writes. */\n'+source
source=source.replace('SAGE_NATIVE13_ENTRY_CONTEXT03_READONLY','SAGE_NATIVE13_PREREQUISITE04_OWNED_ONLY').replace('SAGE_NATIVE13_ENTRY_CONTEXT03_END','SAGE_NATIVE13_PREREQUISITE04_END')
source=source.replace('static void page_info(', '#include "pagewalk.inc"\nstatic void page_info(',1)
source=source.replace('else add(" ACTUAL_ATTR=UNKNOWN");add("\\r\\n");','else add(" ACTUAL_ATTR=UNKNOWN");add("\\r\\n");pagewalk_log(page);')
source=source.replace('#include "context_inspect.inc"','#include "context_inspect.inc"\n#include "owned_fixture.inc"')
source=source.replace('inspect_interfaces();inspect_entry_context();','inspect_interfaces();inspect_entry_context();inspect_prerequisites();')
source=source.replace('if(map){st->bs->free_pool(map);','if(map&&!prerequisite_ended){st->bs->free_pool(map);')
source=source.replace('if(st&&st->bs&&st->out&&st->in){','if(!prerequisite_ended&&st&&st->bs&&st->out&&st->in){')
source=source.replace('return 0;\n}', 'return 0;\n}')
source=source.replace(' return 0;\n}\n', ' return 0;\n}\n')
tail=' return 0;\n}\n'
assert source.endswith(tail)
source=source[:-len(tail)]+' if(prerequisite_hold||prerequisite_ended)for(;;)__asm__ volatile("pause");\n return 0;\n}\n'
(NEW/'source/preflight.c').write_text(source)
efi=(OLD/'source/efi.h').read_text().replace('void *free_pages;','ES (EA *free_pages)(uint64_t,UN);').replace('void *set_attributes;','ES (EA *set_attributes)(CPU *,uint64_t,uint64_t,uint64_t);')
(NEW/'source/efi.h').write_text(efi)
sources=[{'path':str(p.relative_to(OLD)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in (OLD/'source').rglob('*')if p.is_file()]
(NEW/'source_origins.json').write_text(json.dumps({'original_ep3_sources':sources,'scope':'Snapshot only; additions pagewalk.inc/owned_fixture.inc and local preflight/build/transport marker adaptation.'},indent=2)+'\n')
print(NEW)

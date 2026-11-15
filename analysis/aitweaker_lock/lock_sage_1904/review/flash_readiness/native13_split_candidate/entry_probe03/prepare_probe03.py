"""Derive a separate two-slot AMITSE outer-frame observation from frozen EP2."""
from pathlib import Path
import hashlib,json,shutil
HERE=Path(__file__).resolve().parent;N13=HERE.parent;OLD=N13/'entry_probe02'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((OLD/'entry_context02_manifest.json').read_text())
for a in manifest['artifacts']:assert sha(N13/a['path'])==a['sha256'],a['path']
for p in (OLD/'source').rglob('*'):
    if p.is_file():dest=HERE/'source'/p.relative_to(OLD/'source');dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
replacements={'SageNative13EntryContext02':'SageNative13EntryContext03','SAGE-N13-READONLY-ENTRY-CONTEXT02':'SAGE-N13-READONLY-ENTRY-CONTEXT03','SAGE_NATIVE13_ENTRY_CONTEXT02_READONLY':'SAGE_NATIVE13_ENTRY_CONTEXT03_READONLY','SAGE_NATIVE13_ENTRY_CONTEXT02_END':'SAGE_NATIVE13_ENTRY_CONTEXT03_END','SAGE N13 - ENTRY CONTEXT02':'SAGE N13 - ENTRY CONTEXT03','SAGE N13 context02 - READ ONLY':'SAGE N13 context03 - READ ONLY','N13 context02 read-only probe ended.':'N13 context03 read-only probe ended.'}
for name in ['build_probe.py','run_ovmf_probe.py','decode_probe.py']:
    s=(OLD/name).read_text()
    for a,b in replacements.items():s=s.replace(a,b)
    (HERE/name).write_text(s)
for name in ['preflight.c','transport/kvm.c']:
    p=HERE/'source'/name;s=p.read_text()
    for a,b in replacements.items():s=s.replace(a,b)
    if name=='preflight.c':s=s.replace('RuntimeTableChanged=NO\\r\\nProviderStarted=NO\\r\\n','BROWSER_ABSENCE_PROOF=NO\\r\\nRuntimeTableChanged=NO\\r\\nProviderStarted=NO\\r\\n')
    p.write_text(s)
proof=json.loads((N13/'amitse_launch_frame_verification.json').read_text());assert all(proof['checks'].values())
digest=bytes.fromhex(proof['function_sha256']);header='static const uint8_t amitse_launch_hash[32]={'+','.join(f'0x{x:02x}'for x in digest)+'};\n'
(HERE/'source/launch_binding.h').write_text(header)
p=HERE/'source/context_inspect.inc';s=p.read_text();s=s.replace('static void inspect_entry_context(void){','#include "launch_frame.inc"\nstatic void inspect_entry_context(void){')
needle='result("exact known native StartImage callsite",known);'
assert needle in s;s=s.replace(needle,needle+'\n if(kind==1&&known&&rva==0xa8e6)inspect_amitse_outer_frame(captured_entry.rsp,u64(sp+0x78));')
s=s.replace('VALIDATED_CHAIN_LIMIT=CORE_ENTRY_AND_ONE_NATIVE_PARENT','VALIDATED_CHAIN_LIMIT=AT_MOST_CORE_AMITSE_LAUNCH_AND_ONE_OUTER_RETURN');p.write_text(s)
s=p.read_text().replace('BROWSER_ABSENCE_PROOF=NO\\r\\n','');p.write_text(s)
binding=json.loads((OLD/'identity_binding.json').read_text());binding.update(revision='ENTRY_CONTEXT03_ONE_AMITSE_OUTER_FRAME',predecessor_manifest_sha256=sha(OLD/'entry_context02_manifest.json'),physical_ep2_review_sha256=sha(N13/'entry02_hardware_readonly_review.json'),launch_function_rva=0x9f78,launch_function_end=0xaada,launch_function_sha256=proof['function_sha256'],launch_saved_rbp_required_delta=0x131,next_saved_rbp_slot=0x188,next_return_slot=0x190,known_outer_return_rvas=proof['known_outer_return_rvas'],frame_replay_report_sha256=sha(N13/'amitse_launch_frame_verification.json'))
(HERE/'identity_binding.json').write_text(json.dumps(binding,indent=2)+'\n');print(json.dumps({'revision':binding['revision'],'function_sha256':proof['function_sha256']}))

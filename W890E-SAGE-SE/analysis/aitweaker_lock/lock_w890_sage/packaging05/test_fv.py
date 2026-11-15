"""Check actual original LZMA decoder against each compressed composed stream."""
from bind_layout import *
from pack_fv import compose_fv
from verify_native_lzma import execute,MODULE
import verify_native_lzma,validate_layout,lzma_known_size
import sys

aggregate='--aggregate'in sys.argv
if aggregate:
    latest=json.loads((HERE/'latest_aggregate.json').read_text());module=Path(latest['pe']);profile_path=Path(latest['report'])
    merged=module.read_bytes();profile=json.loads(profile_path.read_text());need(sha(merged)==latest['sha256']==profile['merged_sha256'],'canonical aggregate')
    component_inputs=[module,profile_path];out=module.parent/'fv_composition_test.json'
else:
    ext=(HERE/'build/LAYOUT-FIXTURE.dll').read_bytes()
    w=next(w for w in json.loads((BASE/'native_observer04/hook_windows.json').read_text())['windows']if w['rva']==0x190f4)
    patch={'rva':w['rva'],'original_hex':w['hex'],'mode':'jmp','export':'i05_fixture_hook','trampoline':'original_loop'}
    merged,profile=compose(ext,sha(ext),'i05_fixture_entry',[patch]);merged,profile=bind_layout(merged,profile)
    component_inputs=[HERE/'build/LAYOUT-FIXTURE.dll'];out=HERE/'fv_composition_test.json'
encoding='plain_sections'if'--plain'in sys.argv else'original_lzma'
dictionary=0x2000000 if '--dict32'in sys.argv else 0x1000000
depth=int(sys.argv[sys.argv.index('--depth')+1])if '--depth'in sys.argv else 0
memory,report=compose_fv(merged,sha(merged),encoding,dictionary,depth);checks=[]
streams=[('outer_FV_composed',memory['outer_section'],memory['outer_payload'])]
if memory['tse_section']is not None:streams.insert(0,('nested_AMITSE_composed',memory['tse_section'],memory['tse_payload']))
for name,section,payload in streams:
    print(json.dumps({'phase':'native_decoder','case':name}),flush=True)
    checks.append(execute(section,payload,name));print(json.dumps(checks[-1]),flush=True)
report.update(status=('PASS_ACTUAL_AGGREGATE_CONTAINER_ORIGINAL_DECODER'if aggregate else'PASS_PACKAGING_FIXTURE_ORIGINAL_DECODER'),native_decoder_checks=checks,
    scope=f'Actual original IA32 PEIM extraction code accepts {len(streams)} compressed stream(s) in bounded local emulation; not whole firmware boot or proof of which DXE handler is dispatched. Plain inner PE32/UI sections are structurally checked without claiming a second decompression.',
    bindings=[{'path':str(p),'sha256':sha(p.read_bytes())}for p in [HERE/'test_fv.py',HERE/'pack_fv.py',HERE/'lzma_search05.py',HERE/'merge_pe.py',HERE/'bind_layout.py',Path(verify_native_lzma.__file__),Path(validate_layout.__file__),Path(lzma_known_size.__file__),lzma_known_size.DLL,MODULE]+component_inputs])
out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':report['status'],'moved_target':report['appended_after_pad'],'inner_bytes':report['inner_bytes'],'other_files_unchanged':report['preserved_other_inner_files']}),flush=True)

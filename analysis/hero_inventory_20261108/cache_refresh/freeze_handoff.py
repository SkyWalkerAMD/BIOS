"""Run independent native tests and record the exact cache-library handoff."""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

logs=[]
for name in ('test_cache_refresh.py','test_response_bounds.py'):
    p=subprocess.run([sys.executable,'-X','utf8',str(HERE/name)],cwd=HERE,capture_output=True,text=True,encoding='utf8')
    logs.append(name+'\n'+p.stdout+p.stderr)
    if p.returncode: raise SystemExit('\n'.join(logs))
(HERE/'build/test-results.txt').write_text('\n'.join(logs),encoding='utf8')
dll=(HERE/'build/cache.dll').read_bytes()
pe=struct.unpack_from('<I',dll,0x3c)[0]
assert struct.unpack_from('<H',dll,pe+24)[0]==0x20b
imports=struct.unpack_from('<II',dll,pe+24+112+8)
assert imports==(0,0),imports
frozen={
 'inventory_legacy71.c':'7b210c8b367211cf5534e4b6d747d101f6313baaa56c1d5d4e27bbeed2c6056b',
 'inventory_legacy71.h':'f6d73e785357114291e05bb4ff0370f9aa07fe62fd373a96a132f351fa10f410',
 'catalog71.h':'578cb00bd06f3601e93e6aad732e02e7c85de7568e4bae76f67e9107948879dd',
 'legacy71_json.h':'f9ba47674881a8e0a36cf1f106e49b13d2198d3b5af024057f41ddaa8abcf1ad'}
for name,wanted in frozen.items(): assert sha(HERE.parent/'native_i3d'/name)==wanted,name
build=json.loads((HERE/'build/build.json').read_text())
report={
 'kind':'independent-exact-SRK-cache-invalidation-library',
 'live_operations_by_this_agent':False,
 'integrated_into_I3d_or_BIOS':False,
 'internal_USB_GlobalLuaTables_DELETE_live_verified':False,
 'external_CPU_cache_success_evidence':['996-evaluate.json','997-evaluate.json','998-get.json'],
 'current_memory_live_result':'four DIMMs indexed immediately; no cache invalidation was needed',
 'native_unit_tests':27,
 'readonly_response_guard_page_tests':12,
 'context_bytes':build['context_bytes'],
 'dll_import_directory_empty':True,
 'frozen_native_I3d_unchanged':frozen,
 'limits':{'json_response_bytes':32768,'json_tokens':2048,'json_depth':12,
           'cpu_members':8,'memory_members':32,'single_cpu_operation_exchanges':8,
           'four_DIMM_operation_exchanges':14,'maximum_group_operation_exchanges':70,
           'DELETE_attempts_per_target_per_context':1},
 'files':{}
}
names=['hero_inventory_cache.c','hero_inventory_cache.h','cache_json.h','test_cache_refresh.py',
       'test_response_bounds.py','freeze_handoff.py','接入说明与原厂证据.txt','自动库存集成最小路线.txt',
       'build/cache.obj','build/cache.dll','build/build.json','build/test-results.txt','build/response-bounds.json']
for name in names:
    p=HERE/name;report['files'][name]={'bytes':p.stat().st_size,'sha256':sha(p)}
(HERE/'handoff.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
print(json.dumps({'handoff':str(HERE/'handoff.json'),'tests':27,'guard_page_tests':12,
                  'context_bytes':report['context_bytes'],
                  'source_sha256':report['files']['hero_inventory_cache.c']['sha256'],
                  'header_sha256':report['files']['hero_inventory_cache.h']['sha256'],
                  'dll_sha256':report['files']['build/cache.dll']['sha256']},indent=2))

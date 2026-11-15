from pathlib import Path
import hashlib
import json
import struct

here=Path(__file__).resolve().parent
pe=(here/'build/catalog.dll').read_bytes();base=struct.unpack_from('<I',pe,0x3c)[0];optional=base+24
assert struct.unpack_from('<H',pe,optional)[0]==0x20b
import_rva,import_bytes=struct.unpack_from('<II',pe,optional+112+8)
assert import_rva==import_bytes==0
names=['hero_inventory_catalog.c','hero_inventory_catalog.h','test_dynamic_catalog.py','test_read_bounds.py',
       'build/catalog.obj','build/catalog.dll','build/actual-parity.json','build/read-bounds.json']
result={'kind':'bounded-dynamic-SMBIOS-to-legacy-JSON-library','live_operations':False,
        'automatic_firmware_ready':False,'native_unit_tests':24,'seeded_corruptions':400,'guard_page_tests':8,
        'actual_hero71_frozen_payloads_byte_identical':6,'dll_import_directory_empty':True,
        'source_limits':{'table':262144,'records':1024,'cpus':8,'dimms':32,'string_bytes':255,'json_storage':32768},
        'caller_workspace_bytes':{'catalog':34608,'scratch':8904},
        'files':{name:{'bytes':(here/name).stat().st_size,'sha256':hashlib.sha256((here/name).read_bytes()).hexdigest()} for name in names}}
(here/'handoff.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'source':result['files']['hero_inventory_catalog.c'],'header':result['files']['hero_inventory_catalog.h'],
                  'tests':24,'guards':8,'imports':import_rva},indent=2))

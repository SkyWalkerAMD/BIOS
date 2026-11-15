"""Bind official source, paired-state observations and mock-only operation tests."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,shutil
HERE=Path(__file__).resolve().parent;BASE=HERE.parent;CASE=BASE.parents[2]
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir());HW=CASE/'remote_172_20_2_162'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p.relative_to(ROOT)).replace('\\','/'),'size':p.stat().st_size,'sha256':sha(p)}
def write(p,o):p.write_text(json.dumps(o,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
KEYS=['BootSourceOverrideEnabled','BootSourceOverrideMode','BootSourceOverrideTarget']
def triple(b):return {k:b[k] for k in KEYS}
def main():
    restored=HW/'media-override-restored08-1793703255135.json';pre=HW/'manager-restart08-capability-1793704023580.json';post=HW/'manager-restart08-capability-1793704391712.json'
    a,b,c=[json.loads(p.read_text()) for p in [restored,pre,post]]
    wanted={'BootSourceOverrideEnabled':'Disabled','BootSourceOverrideMode':'Legacy','BootSourceOverrideTarget':'None'}
    stale={'BootSourceOverrideEnabled':'Disabled','BootSourceOverrideMode':'UEFI','BootSourceOverrideTarget':'Cd'}
    assert triple(a['after'])==wanted and triple(b['settings']['Boot'])==wanted
    assert triple(b['system']['Boot'])==triple(c['system']['Boot'])==triple(c['settings']['Boot'])==stale
    assert b['system']['Boot']['BootOrder']==c['system']['Boot']['BootOrder'] and b['system']['Boot']['BootNext'] is c['system']['Boot']['BootNext'] is None
    op=HW/'operations/restore_media_overrides09.mjs';oldop=HW/'operations/restore_media_overrides08.mjs'
    assert sha(op)=='2cc09ca5ae382c3829219933588e7b36dadfb3dfb8b787a6ac29b85bbceba9f0'
    assert sha(oldop)=='d6456057bfea8a9c1c4f060a1e1b8065327bf1c596e25a10f57fa40a27b948bc'
    tests=json.loads((HERE/'restore09_tests.json').read_text());assert tests['status']=='PASS' and tests['cases']==28 and tests['operation']['sha256']==sha(op)
    assert all(x['status']=='PASS' for x in tests['results'])
    for manifest in ['lua_decode_manifest.json','lua_inventory_decode_manifest.json']:
        m=json.loads((HERE/manifest).read_text())
        for x in m['files']:
            assert x['decompile_return']==x['asm_return']==0 and sha(Path(x['input']))==x['input_sha256'] and sha(Path(x['output']))==x['output_sha256']
    snapshot=HERE/'reviewed_sources'/op.name;snapshot.parent.mkdir(exist_ok=True);shutil.copyfile(op,snapshot)
    assert sha(snapshot)==sha(op)
    report={
      'status':'COMPLETE_SUPPORTED_SD_ONLY_ACTIVE_SELF_WRITE_NOT_SUPPORTED',
      'created_utc':datetime.now(timezone.utc).isoformat(),
      'scope':'Offline review of pinned public ASUS BMC1.1.57 LuaJIT bytecode, static assembly/decompilation, completed parent captures and actual new operation under mocks. No BMC requests or device actions by reviewer.',
      'observed_sequence':[
        {'evidence':ref(restored),'utc':a['utc'],'after_sd':triple(a['after']),'meaning':'Previous verified flag only establishes SD readback, not the active Self view.'},
        {'evidence':ref(pre),'utc':b['utc'],'active':triple(b['system']['Boot']),'settings':triple(b['settings']['Boot'])},
        {'evidence':ref(post),'utc':c['utc'],'active':triple(c['system']['Boot']),'settings':triple(c['settings']['Boot'])}
      ],
      'observation_conclusion':'Active Self was already Disabled/UEFI/Cd before the second BMC restart and remained so afterward. The observed change was SD becoming equal to the existing active view. The captures do not prove IPMI BootFlags state, exact Redis keys, or which initialization callback executed.',
      'supported_routes':{
        'external_active_self_boot_patch':False,
        'external_settings_boot_patch':True,
        'settings_uri':'/redfish/v1/Systems/Self/SD',
        'body':{'Boot':{'BootSourceOverrideEnabled':'Disabled','BootSourceOverrideTarget':'None','BootSourceOverrideMode':'Legacy'}},
        'active_route_evidence':[
          {'file':'lua/system_access.lua','lines':[36,60],'finding':'BootSourceOverrideEnabled/Mode/Target are read-only r; raw table also in system_access.asm.txt lines73-83.'},
          {'file':'lua/system.lua','lines':[527,540],'finding':'External dispatcher selects patch_sd only for trailing SD; Self selects patch_self.'},
          {'file':'lua/system.lua','lines':[1257,1265],'finding':'patch_self emits Ami.OperationSupportedInFutureStateURI for a Boot table, with request path+/SD. Corresponding raw bytecode instructions351-371 are in system.asm.txt lines4899-4919.'},
          {'file':'lua/system_sd_access.lua','lines':[15,32],'finding':'All three override fields writable on SD; other writable fields exist but new operation never submits them.'}
        ]
      },
      'settings_write_chain':[
        {'file':'lua/system.lua','lines':[686,877],'finding':'Three separately type/enum-validated fields enqueue PATCH:Redfish:Systems:Self:Boot:* and wait on corresponding SD keys. ETag preconditions validated; booting/fixed-BootOptions guards also exist.'},
        {'file':'lua/intermediate_map.lua','lines':[54,66],'finding':'All three PATCH keys map to Systems_Boot.'},
        {'file':'lua/chassis.lua','lines':[391,425],'finding':'patchBootTarget passes Enabled/Target/Mode using PATCH→SD→active fallback to bootOptions:set_bootOptions, then queries readback to populate SD.'},
        {'file':'lua/ipmi_boot.lua','lines':[47,111],'finding':'Standard IPMI System Boot Options parameter5 path, not BIOS image update. Disabled clears valid bit7; Legacy clears bit5; None maps selector0. Actual function/error handling and runtime IPMI state were not executed here.'},
        {'file':'lua/chassis.lua','lines':[113,231],'finding':'get_boot_options publishes SD values and sets SD:BootPropsChangeFlag. This does not directly replace active inventory Boot keys.'}
      ],
      'inventory_refresh_paths':[
        {'file':'lua/system.lua','lines':[112,136],'finding':'GET SD prefers SD keys and falls back to current Boot keys. GET Self separately reads current keys (lines258-261/318-321).'},
        {'file':'lua/hi_inventory.lua','lines':[36,43],'finding':'At module initialization, empty inventory CRC plus existing configured BIOS inventory backup queues unpacked saved inventory. This is an identified conditional source, not evidence the live condition held.'},
        {'file':'lua/hi_helper.lua','lines':[6177,6313],'finding':'init with GroupCrcList runs an SD-key cleanup excluding ResourceExists, among other inventory synchronization. These OEM internal commands were inspected, never executed by reviewer and are not proposed as recovery commands.'},
        {'file':'lua/hi_helper.lua','lines':[4023,4045],'finding':'systems_data writes each supplied Boot field to active current keys and publishes the three override PATCH keys. This can repopulate SD from saved/current inventory through normal synchronization.'},
        {'file':'lua/hi_system.lua','lines':[454,480],'finding':'Trusted host-interface inventory update also writes current Boot and enqueues override changes. It is distinct from external Self PATCH and must not be impersonated to force a change.'}
      ],
      'write_scope_and_limits':[
        'New operation submits only BootSourceOverrideEnabled, BootSourceOverrideTarget and BootSourceOverrideMode through supported SD. No request writes BootOrder, BootNext, BIOS settings, inventory, power or restart.',
        'Mode Legacy here is the mode of a disabled temporary boot override; it is not an instruction to change the persistent BIOS boot configuration.',
        'OEM Chassis readback marks BOOT changes; hi_inventory can send current BootOrder/BootOptions/BootNext alongside changed overrides to the host during later boot synchronization (hi_inventory.lua129-132,869-891). Thus request allowlisting and unchanged readback do not prove the OEM never resubmits unchanged firmware variables.',
        'Both supplied before/after views report Enabled Disabled. Retained UEFI/Cd selector values are not by themselves evidence of an enabled next-boot override.',
        'Rebooting BMC solely to force inactive-field agreement is not part of the new operation. No unsupported Self write, host-interface impersonation, Redis or shell mutation is prepared.'
      ],
      'new_operation':{'source':ref(op),'snapshot':ref(snapshot),'tests':ref(HERE/'restore09_tests.json'),'mock_cases':28,
        'gates':['Pinned baseline and historical BootOptions; exact six/seven identity/order whitelist including known virtual-CD addition/removal.',
                 'BMC1.01.57/BIOS1904, two fresh Self reads, native Off, detached CD/HD, no owned helper.',
                 'Advertised values; fresh SD ETag; exact three-field body; maxRetries0 and at most one PATCH; no mutation retries after transport ambiguity.',
                 'Independent current/future readback and preservation of every other Boot property; mismatched active view is explicitly partial, not verified complete.'],
        'invocation_contract':'Run only through the already owned reviewed session after parent approval/review. Args exactly baseline filename boot-once-<digits>.json and its SHA256. No invocation performed here.',
        'outcomes':['BOTH_VIEWS_MATCH_BASELINE','SD_RESTORED_ACTIVE_VIEW_DIFFERS_NO_EXTRA_MUTATION','READBACK_NOT_FULLY_RESTORED','READBACK_UNAVAILABLE_NO_RETRY']},
      'limitations':['Lua is decompiled analysis output, not original source; critical path and property constants cross-checked in raw bytecode listings. Full server execution/scheduling and live binary readback not proven.',
                     'Mock tests verify new operation safety/reporting, not actual IPMI acceptance or persistence across a BMC reboot.',
                     'No changes to restore08, helper04/05, GEO6, restart reviews, production EFI or firmware artifacts.']
    }
    write(HERE/'boot_override_review.json',report)
    artifacts=sorted(p for p in HERE.rglob('*') if p.is_file() and p.name!='manifest.json' and '__pycache__' not in p.parts)
    external=[op,oldop,restored,pre,post,HW/'boot-options-1793666634014.json',HW/'boot-once-1793701152945.json',BASE/'official_bmc/W7901157.ima',BASE/'bmc_backend_inventory.json',BASE/'bmc_restart_review01/decompile_lua.py',ROOT/'tools/luajit-decompiler/main.py']
    write(HERE/'manifest.json',{'status':'FROZEN','review':ref(HERE/'boot_override_review.json'),'artifacts':[ref(p) for p in artifacts],'external_inputs':[ref(p) for p in external]})
    print(json.dumps({'review':ref(HERE/'boot_override_review.json'),'manifest':ref(HERE/'manifest.json'),'artifact_count':len(artifacts),'external_count':len(external),'operation':ref(op),'mocks':28}))
if __name__=='__main__':main()

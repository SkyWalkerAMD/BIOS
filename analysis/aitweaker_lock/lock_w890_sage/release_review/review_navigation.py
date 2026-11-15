"""Independent frozen navigation-component identities and test-scope review.

This checks original registry bytes, compiled DLLs and reported emulation output.
It does not rerun the agent's behavioral suites or create/install native hooks.
"""
from pathlib import Path
import hashlib, json, re, struct, sys, zlib

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;BOARD=HERE.parent;ROOT=HERE.parents[3];NAV=BOARD/'navigation'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def binding(p):return dict(path=str(p.resolve()),size=p.stat().st_size,sha256=sha(p))

mp=NAV/'navigation_manifest.json';manifest=read(mp)
assert sha(mp)=='73848c9130153084adf9645c1f7c1eb79eb717d701a2492aaeb83623e3bbde3e'
assert manifest['status']=='ROUND_FROZEN_COMPILED_EMULATED_NOT_INSTALLABLE_NOT_FLASHABLE'
checked=[]
for key,base,count in [('owned_artifacts',NAV,135),('external_dependencies_read_only',ROOT,9)]:
    entries=manifest[key];assert len(entries)==count
    for e in entries:
        p=(base/e['file']).resolve();assert p.is_relative_to(base.resolve())
        assert p.stat().st_size==e['bytes'] and sha(p)==e['sha256']
        checked.append(dict(group=key,**binding(p)))
adaptation=read(NAV/'adaptation_report.json')
for key in ['native_owner_bound','installer_implemented','all_entrypoints_covered','pending_write_authority_bound','flashable_image_produced','modified_code_hardware_tested']:
    assert adaptation[key] is False
assert adaptation['hardware_or_firmware_writes_by_this_agent']==0
components=[]
for e in adaptation['components']:
    p=NAV/e['file'];assert sha(p)==e['sha256'] and p.stat().st_size==e['bytes'] and not e['installable']
    pe=pefile.PE(str(p));assert pe.FILE_HEADER.Machine==0x8664 and pe.FILE_HEADER.Characteristics&0x2000
    assert pe.OPTIONAL_HEADER.AddressOfEntryPoint==0 and not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
    components.append(dict(**binding(p),machine='x64 DLL',entry_rva=0,imports=False,
        relocation_directory_bytes=pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size,installable=False))

profile=read(BOARD/'password/profile_0603.json')
original=ROOT/profile['sources']['AMITSE']['path']
assert sha(original)==profile['sources']['AMITSE']['sha256']=='43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
pe=pefile.PE(str(original));assert pe.OPTIONAL_HEADER.ImageBase==0
registry=read(NAV/'control_registry_0603.json')
assert registry['original_amitse_sha256']==sha(original)
assert registry['count']==len(registry['items'])==15 and registry['registry_rva']==0x943f0 and registry['stride']==40
for i,e in enumerate(registry['items']):
    assert e['descriptor_rva']==0x943f0+40*i
    raw=pe.get_data(e['descriptor_rva'],40);assert raw.hex()==e['descriptor_bytes']
    assert struct.unpack_from('<Q',raw,0)[0]==e['type']
    assert struct.unpack_from('<Q',raw,8)[0]==e['vtable_rva']
    assert e['input_slot_rva']==e['vtable_rva']+32
    slot=pe.get_data(e['input_slot_rva'],8)
    assert slot.hex()==e['input_slot_bytes'] and struct.unpack('<Q',slot)[0]==e['input_rva']
assert registry['terminator_rva']==0x943f0+15*40 and pe.get_data(registry['terminator_rva'],8)==bytes(8)
header=(NAV/'input_registry_data.h').read_text()
items=[(int(a),int(b,16),int(c,16)) for a,b,c in re.findall(r'\{(\d+),(0x[0-9a-f]+),(0x[0-9a-f]+)\}',header)]
assert items==[(e['type'],e['vtable_rva'],e['input_rva']) for e in registry['items']]

reported=[]
for suite in adaptation['suites']:
    p=NAV/suite['file'];assert sha(p)==suite['sha256']
    r=read(p);assert r['status']==suite['status']
    cases=r['cases'];assert len(cases)==suite['cases']
    assert all(x.get('status')=='PASS' or x.get('passed') is True for x in cases)
    reported.append(dict(**binding(p),reported_cases=len(cases),scope=suite['scope'],independently_rerun_by_reviewer=False))
assert len(reported)==8 and sum(x['reported_cases'] for x in reported)==156

runtime=BOARD/'password_runtime02/build/W890Runtime02.UNBOUND.TESTONLY.efi'
gate=NAV/'build/W890Navigation.TESTONLY.dll';first=NAV/'build/W890FirstFallback.TESTONLY.dll';inp=NAV/'build/W890InputAdapter.TESTONLY.dll'
input_result=read(NAV/'input_adapter_tests.json')
chain=read(NAV/'integration/native02/runtime02_chain_tests.json')
assert input_result['case_count']==len(input_result['cases'])==21
assert chain['case_count']==len(chain['cases'])==18
for r in [input_result,chain]:
    assert r['runtime02_sha256']==sha(runtime)=='ec718d44fd088b1fb241ced5602bbea8b71ea07798b8226d05e4af5c0c2c15d6'
    assert r['gate_sha256']==sha(gate) and r['original_amitse_sha256']==sha(original) and r['hardware_or_firmware_writes']==0
assert input_result['input_adapter_sha256']==sha(inp)
assert chain['first_component_sha256']==sha(first)
assert input_result['source_sha256']==sha(NAV/'verify_input_adapter.py')
assert chain['source_sha256']==sha(NAV/'integration/native02/verify_runtime_chain.py')
assert chain['runtime_fixture_sha256']==sha(BOARD/'password_runtime02/verify_runtime_pe.py')
assert chain['separate_OVMF_result_sha256']==sha(BOARD/'password_runtime02/lab/runs/20261108_012702/result.json')
assert chain['native_owner_and_HII_modeled'] and chain['UEFI_services_and_GOP_modeled'] and chain['PBKDF_primitive_independent_python_oracle']
assert chain['password_auth_result_modeled'] is False
for n,h in read(NAV/'build/input_build.json')['sources'].items():assert sha(NAV/n)==h
input_cases={x['name']:x for x in input_result['cases']}
for name in ['cancel','wrong','unknown_owner','unknown_ifr','unknown_type']:
    c=input_cases['keyboard_'+name+'_through_original_frame_and_page']
    assert c['page_consumed'] and c['native_control_calls']==0 and c['stop_rva']=='0x23b05'
assert input_cases['keyboard_correct_through_original_frame_and_page']['native_control_calls']==1
assert input_cases['owner_revoked_after_scope_before_original_method']['native_control_calls']==0
for protected in [(True,True),(False,True),(True,False),(False,False)]:
    c=input_cases['kind2_each_control_'+str(protected)]
    assert c['prompt_count']==0 and c['native_control_calls']==sum(not x for x in protected)
observed_shape=input_cases['hardware_observed_nonempty_history_shape_refused_without_owner_or_allocation_proof']
assert observed_shape['result']=='fault' and observed_shape['fault_continuation_modeled']
for e in adaptation['original_hardware_evidence']:
    p=ROOT/e['file'];raw=p.read_bytes()
    assert sha(p)==e['sha256'] and len(raw)==e['bytes'] and f'{zlib.crc32(raw)&0xffffffff:08X}'==e['crc32']
    assert not e['authorization_or_ownership'] and not e['modified_code_tested']

input_source=(NAV/'input_adapter.c').read_text()
stub=(NAV/'first_entry_stub.S').read_text()
assert 'uint64_t result=0;' in input_source and 'b->native_base+0x40094' in input_source
assert 'if(kind==2){if(!silent(b,c,e))goto done;}' in input_source
assert 'if(type==14)' in input_source and 'ptr(c+8)!=b->menu_callback' in input_source
assert 'if(!b->effects(b->opaque,&z)||!eq(&x,&z,sizeof(x)))goto done;' in input_source
assert 'ud2' in stub and 'wf_fail_closed: .quad 0' in stub

out=dict(status='PASS_FROZEN_NAVIGATION_BINDINGS_ORIGINAL_REGISTRY_AND_REPORTED_SCOPE',release_ready=False,
    frozen_manifest=binding(mp),owned_binding_count=135,external_binding_count=9,checked_bindings=checked,
    components=components,original_registry=dict(original=binding(original),rows=15,stride=40,rva='0x943f0',
        exact_descriptors_and_input_slots_independently_checked=True,generated_registry_matches=True),
    reported_suites=reported,overlapping_case_sum_not_coverage=156,
    focused_review=dict(input_cases=21,runtime02_chain_cases=18,
        actual_runtime_password_dialog_and_authorization=True,PBKDF_uses_independent_Python_oracle=True,
        native_owner_HII_scope_effects_and_UEFI_services_modeled=True,
        source_files=[binding(NAV/x) for x in ['input_adapter.c','input_adapter.h','gate_adapter.c','first_entry_stub.S','verify_input_adapter.py','integration/native02/verify_runtime_chain.py']],
        positive_findings=[
            'Input denial is zero, consistent with reported original two-layer cancellation consumption; no ACCESS_DENIED/ABORTED universal-cancel assumption.',
            'Exact type plus original vtable choose original methods; kind 2 performs per-control silent policy checks and no prompt.',
            'Menu type 14 requires guarded factory/object callbacks; owner state is rechecked after scope callbacks.',
            'Pending path checks a distinct producer/effect attestation twice and refuses changed/unknown/protected-without-grant conditions.',
            'Hardware-observed nonempty history is expressly rejected by zero-history fallback; its error branch is modeled, not a working native error UI.'
        ]),
    open_requirements=[
        'No actual native owner, HII provenance, frame/control allocation lifetime, session exclusivity or pending producer/effect proof is implemented.',
        'Original FrameInput reads the vtable before the virtual wrapper; earlier object/frame validation and all direct callers remain required.',
        'No atomic installer/uninstaller, exact patch-overlay validation or complete first/render/input/save/default/profile/SendForm coverage.',
        'Mid-function failure continuation remains zero and deliberately UD2 traps. This must never be installed as a completed BIOS lock.',
        'Original pending helper 0x3fed4 is modeled with no new work for the allowed empty-list case; positive pending-write authority is not established.',
        '156 is the sum of overlapping suites with different assumptions, not a coverage rate, number of distinct features, or hardware acceptance.',
        'Only root original read-only P3/native module observations were exercised on hardware; these compiled adapters have not been installed there.'
    ],reviewer_network_or_device_actions=False)
(HERE/'navigation_component_review.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(status=out['status'],owned=135,external=9,input_cases=21,runtime_chain_cases=18,
    sha256=sha(HERE/'navigation_component_review.json'))))

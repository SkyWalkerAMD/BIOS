"""Independent frozen Runtime02 identities, capacity and original-code decode.

Provider01's packing result is not inherited. Runtime02 is packed separately,
with FALSE DEPEX, entirely in memory. This writes review JSON only.
"""
from pathlib import Path
import hashlib,json
from validate_layout import main as layout_main
from verify_native_lzma import execute,MODULE,IMAGE,GET_INFO,DECODE,unicorn

HERE=Path(__file__).resolve().parent;COMPONENT=HERE.parent/'password_runtime02'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def binding(p):return dict(path=str(p.resolve()),size=p.stat().st_size,sha256=sha(p))

manifest_file=COMPONENT/'component_manifest.json';manifest=read(manifest_file)
assert sha(manifest_file)=='3c949b98f40fcf53b894f61615669c8e8393073a40e4034cad70a2c5c4a578c8'
assert not manifest['release_ready'] and not manifest['native_owner_bound']
checked=[]
for name,info in manifest['bindings'].items():
    p=(COMPONENT/name).resolve();assert p.is_relative_to(COMPONENT.resolve())
    assert sha(p)==info['sha256'] and p.stat().st_size==info['bytes']
    checked.append(binding(p))
assert len(checked)==70
base=(COMPONENT/manifest['frozen_base']['path']).resolve()
assert sha(base)==manifest['frozen_base']['sha256']=='c38abd7f26dab2d885ec5d2b85a3ad2780373aa1038a644cffa1885ec2464544'
efi=COMPONENT/'build/W890Runtime02.UNBOUND.TESTONLY.efi'
assert sha(efi)==manifest['component']['sha256']=='ec718d44fd088b1fb241ced5602bbea8b71ea07798b8226d05e4af5c0c2c15d6'
assert efi.stat().st_size==39936
tests=read(COMPONENT/'build/runtime_pe_test.json')
assert tests['efi_sha256']==sha(efi) and len(tests['cases'])==115 and all(x['status']=='PASS' for x in tests['cases'])
run=COMPONENT/'lab/runs/20261108_012702';ovmf=read(run/'result.json')
assert ovmf['component_sha256']==sha(efi) and ovmf['lab_sha256']==sha(COMPONENT/'build/W890Runtime02.QEMU_ONLY.LAB.efi')
assert len(ovmf['boots'])==3 and sum(x['checks'] for x in ovmf['boots'])==94 and all(x['passed'] for x in ovmf['boots'])
assert ovmf['iso_sha256_before']==ovmf['iso_sha256_after']==sha(run/'runtime02-lab.iso')
for i,b in enumerate(ovmf['boots']):assert b['debug_sha256']==sha(run/f'boot{i}/debug.log')
journal=read(COMPONENT/'journal/runs/20261108_011504/result.json')
assert journal['case_count']==len(journal['cases'])==15 and journal['status']=='PASS_DURABLE_JOURNAL_CURRENT_WINDOWS_USER'
cases=[]
def memory(values):
    wrong=bytearray(values['original_section']);wrong[4]^=1
    for name,section,expected in [('wrong_guid',bytes(wrong),b''),
        ('original_factory_stream',values['original_section'],values['original_output']),
        ('runtime02_disabled_provider_stream',values['proposed_section'],values['proposed_output'])]:
        print(json.dumps(dict(case=name,phase='starting')),flush=True)
        result=execute(section,expected,name);cases.append(result);print(json.dumps(result),flush=True)
layout_main(['--efi',str(efi),'--sha256',sha(efi),'--file-guid','1a643cc0-cc83-45e5-bb2d-c59d02659514',
    '--output',str(HERE/'runtime02_layout_experiment.json')],observe_memory=memory)
report=dict(status='PASS_FROZEN_RUNTIME02_CAPACITY_AND_ORIGINAL_DECODER_ONLY',release_ready=False,
    component_manifest=binding(manifest_file),efi=binding(efi),checked_binding_count=70,bindings=checked,
    separately_verified_new_component=True,
    modeled_behavior_reports=dict(actual_unbound_PE_cases=115,ovmf_LAB_variant_checks=94,ovmf_cold_boots=3,
        dpapi_journal_cases=15,PE_report=binding(COMPONENT/'build/runtime_pe_test.json'),
        OVMF_report=binding(run/'result.json'),journal_report=binding(COMPONENT/'journal/runs/20261108_011504/result.json'),
        behavioral_tests_rerun_by_this_reviewer=False,
        limitations=['OVMF uses a separate QEMU-only LAB artifact with the frozen component sources and modeled native owner/input.',
            'PE UEFI services/RDSEED/page tables/PBKDF2 boundaries are modeled as declared by the component report.',
            'Windows current-user DPAPI fixture is not an installed host firmware recovery controller.']),
    layout=binding(HERE/'runtime02_layout_experiment.json'),
    original_decoder=dict(module=binding(MODULE),image_base=hex(IMAGE),get_info=hex(GET_INFO),decode=hex(DECODE),
        unicorn_version=unicorn.__version__,cases=cases,no_device_services_supplied=True,
        implementation=binding(HERE/'verify_native_lzma.py')),
    script_sha256=sha(Path(__file__)),
    limits=['This is a standalone replacement packing experiment, not two providers installed together.',
        'FALSE/END DEPEX disables dispatch; the actual Runtime02 entry also returns EFI_UNSUPPORTED.',
        'Native owner/hooks, HII publication, automatic every-BIOS-entry dispatch and disabled-record recovery remain unbound.',
        'The original decoder accepts this byte stream in local emulation; whole FFS scanning and hardware FV dispatch remain unproved.',
        'No CAP/ROM emitted, hardware password/OC change or firmware write. This is not a flash candidate.'])
(HERE/'runtime02_component_review.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(status=report['status'],sha256=sha(HERE/'runtime02_component_review.json'))),flush=True)

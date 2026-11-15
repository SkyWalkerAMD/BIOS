"""Verify frozen W890 inputs without installing or running any firmware code."""
from pathlib import Path
import hashlib,json,sys

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];BOARD=HERE.parent
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def binding(p):return dict(path=str(p.resolve()),size=p.stat().st_size,sha256=sha(p))

password=BOARD/'password';manifest_file=password/'component_manifest.json'
assert sha(manifest_file)=='c38abd7f26dab2d885ec5d2b85a3ad2780373aa1038a644cffa1885ec2464544'
manifest=read(manifest_file)
assert manifest['release_ready'] is False
checked=[]
for name,value in manifest['bindings'].items():
    p=(password/name).resolve();assert p.is_relative_to(password.resolve())
    assert sha(p)==value['sha256'] and p.stat().st_size==value['bytes']
    checked.append(binding(p))
assert len(checked)==41
profile=read(password/'profile_0603.json')
assert profile['board']=='ASUS Pro WS W890E-SAGE SE' and profile['bios']=='0603'
original_sources=[]
navigation=read(BOARD/'navigation/native_layout_0603.json')
nav_modules={x['module']:x for x in navigation['modules']}
for name,info in profile['sources'].items():
    p=(ROOT/info['path']).resolve();assert p.is_relative_to(ROOT.resolve())
    assert sha(p)==info['sha256'] and p.stat().st_size==info['bytes']
    pe=pefile.PE(str(p));sections=[x for x in pe.sections if x.Name.rstrip(b'\0')==b'.text']
    assert len(sections)==1
    sec=sections[0];text=pe.get_memory_mapped_image()[sec.VirtualAddress:sec.VirtualAddress+sec.Misc_VirtualSize]
    record=dict(module=name,file=binding(p),text_sha256=hashlib.sha256(text).hexdigest(),
        text_rva=sec.VirtualAddress,text_bytes=sec.Misc_VirtualSize,image_bytes=pe.OPTIONAL_HEADER.SizeOfImage)
    if name in nav_modules:
        nav=nav_modules[name]
        assert record['file']['sha256']==nav['file_sha256']
        assert record['text_sha256']==nav['original_text_sha256']
        assert record['image_bytes']==nav['image_bytes']
        record['independent_navigation_agreement']=True
    original_sources.append(record)
tests=read(password/'provider/build/provider_pe_test.json')
efi=password/'provider/build/W890PasswordProvider01.UNBOUND.TESTONLY.efi'
assert sha(efi)==tests['efi_sha256']=='971ae6208bb75bdbe15a859adf46b1e68ca2e232bb618cca5f476994d6465a9e'
assert len(tests['cases'])==tests['case_count']==57 and all(x['status']=='PASS' for x in tests['cases'])
layout=read(HERE/'provider01_layout_experiment.json')
assert layout['efi']['sha256']==sha(efi) and layout['release_ready'] is False
result=dict(status='PASS_FROZEN_INPUT_IDENTITY_NOT_INTEGRATION_ACCEPTANCE',release_ready=False,
    component_manifest=binding(manifest_file),checked_bindings=len(checked),bindings=checked,
    original_sources=original_sources,navigation_layout_snapshot=binding(BOARD/'navigation/native_layout_0603.json'),
    provider_test_report=dict(file=binding(password/'provider/build/provider_pe_test.json'),cases=57,
        scope=tests['scope'],independently_rerun_here=False),
    layout_experiment=binding(HERE/'provider01_layout_experiment.json'),
    firmware_profile=dict(root_form=profile['root_form'],setup_formset_guid=profile['setup_formset_guid'],
        password_profile=binding(password/'profile_0603.json')),
    limitations=['Only original and frozen component hashes are independently rechecked here.',
        'Reported synthetic host tests are not real AMI entry interception, HII UI, NV persistence or actual boot acceptance.',
        'The tested EFI entry refuses EFI_UNSUPPORTED; no dispatch is enabled in the capacity experiment.',
        'Any changed runtime provider must receive new identity, tests and layout verification.'])
(HERE/'profile_hash_bindings.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(status=result['status'],bindings=len(checked),sha256=sha(HERE/'profile_hash_bindings.json'))))

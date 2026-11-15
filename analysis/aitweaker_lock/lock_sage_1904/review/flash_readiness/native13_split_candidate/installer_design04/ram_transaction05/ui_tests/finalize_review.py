"""Freeze/verify only this owned UI review subtree and its two source outputs."""
from pathlib import Path
import argparse,hashlib,json,re,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;TX=HERE.parent;D04=TX.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/vm-pydeps'))
from pyfatfs.PyFatFS import PyFatFS
REPORT=HERE/'session_ui_review.json';MANIFEST=HERE/'session_ui_manifest.json'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def entry(p,base=None):
    p=Path(p).resolve();return {'path':str(p.relative_to(base))if base else str(p),'bytes':p.stat().st_size,'sha256':sha(p)}
def checked(p,a):
    p=Path(p);assert p.stat().st_size==a['bytes']and sha(p)==a['sha256'],str(p)
def collected():
    external=set()
    tests=read(HERE/'ui_test_result.json');build=read(HERE/'build/build.json')
    assert tests['status'].startswith('PASS')and tests['cases']==len(tests['results'])==105
    assert len(set(a['name']for a in tests['results']))==105 and all(a['status']=='PASS'for a in tests['results'])
    assert tests['fixture_sha256']==build['pe']['sha256']==sha(HERE/'build/UI-EMULATION-FIXTURE-NOT-FOR-BOOT.EFI')
    assert tests['source_bindings']==build['sources']
    for a in tests['source_bindings']:
        p=Path(a['path']);checked(p,a)
        if not p.is_relative_to(HERE):external.add(p)
    assert sha(TX/'source/session_ui.c')=='95d448214c31ad96317e9076240fc0adc99b3e428a0a700e15721575b310991d'
    assert sha(TX/'source/ui_bindings.h')=='b554a0316c4cf4dee6e7d8bed4483908ac3b48de4d68f623995f29f9b3f6fb82'
    frozen=D04/'provider13/local_candidate_manifest.json'
    assert sha(frozen)=='2f7738e0cdfdb75a9557cf8c7bba233d512c17ac63063fea23d8e77975566e8a'
    original=read(frozen);assert len(original['artifacts'])==60
    for a in original['artifacts']:checked(D04/a['path'],a)
    external.add(frozen)
    # Validate that the private record validator/crypto came from frozen P13.
    for name in ['password_core.c','password_core.h','password_crypto.c']:
        source=D04/'provider13/source'/name
        assert sha(source)==sha(TX/'source'/name);external.add(source)
    source_package=D04/'provider13/source/management_package.h';external.add(source_package)
    extract=lambda p:bytes(int(x,16)for x in re.findall(r'0x([0-9a-f]{2})',p.read_text()))
    assert extract(source_package)==extract(TX/'source/ui_bindings.h')
    official=D04/'ram_test05_delivery/BasePeCoff.official.c';external.add(official)
    assert sha(official)=='6ad1e8719ed25c2a44e373f3b458401ab0d906b79a5b16802b49421ce6bab0f1'
    blob=hashlib.sha1(b'blob '+str(official.stat().st_size).encode()+b'\0'+official.read_bytes()).hexdigest()
    assert blob=='80e79243ce147d17d15ff4c4ed25a407721d7df7'
    load_runs=[]
    for run in sorted((HERE/'loadimage_lab/runs').iterdir()):
        result=read(run/'result.json');raw=(run/'debug.log').read_text(encoding='ascii',errors='replace')
        assert result['status'].startswith('PASS')and result['exit_code']==33 and result['loadimage_started_provider']is False
        assert result['raw_observation']==raw[raw.index('LOADIMAGE_IDENTITY_BEGIN'):]
        assert 'LOADIMAGE_IDENTITY_COMPLETE'in raw
        for a in result['source_bindings']:
            p=Path(a['path'])
            if sha(p)!=a['sha256']:p=run/'source_snapshot'/p.name
            checked(p,a)
        with PyFatFS(str(run/'readonly-boot.img'),read_only=True,utc=True)as fs:
            files=set(fs.walk.files());assert files=={'/EFI/BOOT/BOOTX64.EFI'}
            assert hashlib.sha256(fs.readbytes('/EFI/BOOT/BOOTX64.EFI')).hexdigest()==result['app_sha256']
        load_runs.append({'path':str(run.relative_to(HERE)),'result_sha256':sha(run/'result.json'),
                          'observations':result['observations']})
    assert len(load_runs)==2
    classified=load_runs[-1]['observations']
    assert int(classified['DeclaredBytes'],16)==51341
    assert int(classified['DeclaredDifferencesAfterImageBase'],16)==0
    assert int(classified['UnspecifiedPaddingBytes'],16)==int(classified['PaddingAFBytes'],16)==14195
    assert classified['DeclaredLoadedSha256']==classified['DeclaredCanonicalSha256']=='6c7dee707f6e425d4ef461c31305c984d0f76a9961b2f416b077100c57d54a85'
    actual=read(HERE/'provider_validator_ovmf/latest_result.json');run=Path(actual['run']);r=actual['result']
    assert r==read(run/'result.json')and r['status']=='PASS_ACTUAL_LOADED_APP_VALIDATOR_IN_OVMF'
    raw=(run/'debug.log').read_text(encoding='ascii',errors='replace');part=raw[raw.index('ACTUAL_PLATFORM_VALIDATOR_BEGIN'):]
    assert r['raw_observation']==part and len(re.findall(r'^PASS ',part,re.M))==r['checks']==85
    assert 'FAIL 'not in part and r['exit_code']==33 and r['imports_started']is False
    assert len(r['relocations_tested'])==17 and len(r['active_mutations_tested'])==12 and len(r['padding_mutations_tested'])==10
    assert r['actual_app_sha256']=='ba5e0491983f4067001bf00d0de3ad91457fe677c39804d730cc79a76937d108'
    assert r['provider_sha256']=='caa80df1fa6414d635d28a3b65fec1c265968482ddb66268412483eff95deca9'
    for a in r['source_bindings']:checked(a['path'],a)
    with PyFatFS(str(run/'readonly-boot.img'),read_only=True,utc=True)as fs:
        assert set(fs.walk.files())=={'/EFI/BOOT/BOOTX64.EFI'}
        assert hashlib.sha256(fs.readbytes('/EFI/BOOT/BOOTX64.EFI')).hexdigest()==r['fixture_sha256']
    for d in [*(HERE/'loadimage_lab/runs').iterdir(),run]:
        command=read(d/'command.json');assert command[command.index('-nic')+1]=='none'
        assert command[command.index('-accel')+1]=='tcg,thread=single'
        drives=[command[i+1]for i,x in enumerate(command)if x=='-drive'];assert len(drives)==3
        assert sum('readonly=on'in drive for drive in drives)==2
        assert all('file='in drive for drive in drives)
    return {'status':'FROZEN_LOCAL_UI_AND_LOADER_VALIDATION_NOT_PHYSICAL_OR_COMPLETE_INSTALLER_ACCEPTANCE',
            'ui_source':entry(TX/'source/session_ui.c'),'ui_package_binding':entry(TX/'source/ui_bindings.h'),
            'ui_tests':{'cases':105,'result_sha256':sha(HERE/'ui_test_result.json'),'fixture_sha256':tests['fixture_sha256'],
                        'scope':'Actual optimized session_ui and frozen record validator executed by Unicorn; firmware services and SendForm effects explicitly mocked.',
                        'ended_boundary_cases':sum(a['name'].startswith('EBS ')for a in tests['results'])},
            'preserved_revision01':{'note':'105 earlier cases passed but only expected ordinary failure at wrong TPL; independent review required terminal CPU hold so the app cannot resume firmware output. Final corresponding tests require no RestoreTPL and no return.',
                                    'result_sha256':sha(HERE/'revision01/ui_test_result.json')},
            'loadimage_discovery':{'runs':load_runs,'official_loader_sha256':sha(official),'official_git_blob_sha':blob,
                'finding':'Real OVMF updates Header.ImageBase and leaves 14195 undeclared alignment/raw-tail bytes as 0xAF; inverse DIR64 plus ImageBase normalization still cannot justify a full zero-padded mapped-image hash.',
                'strict_declared_bytes':51341,'declared_sha256':classified['DeclaredLoadedSha256'],
                'interpretation':'Recorded OVMF behavior agrees with the pinned official source copy/min-size/zero-BSS logic. This is not ASUS loader implementation evidence.'},
            'actual_loaded_app_validator':{'run':str(run.relative_to(HERE)),'result_sha256':sha(run/'result.json'),
                'debug_sha256':sha(run/'debug.log'),'app_sha256':r['actual_app_sha256'],'assertions':85,
                'actual_functions_rva':r['symbols_rva'],'declared_mutation_sites':12,'dir64_mutation_sites':17,'padding_mutation_sites':10,
                'scope':'Standard LoadImage of the exact compiled app and P13. Invoke the actual internal app validator, real CPU environment reader and memory-map reader. No imported entrypoint StartImage. Only initialization of documented app BSS prerequisites; negative mutations on a separately owned correctly rebased provider copy.',
                'result':'Original loaded P13 accepted and fully unchanged. Declared header/text/rdata/data/BSS/reloc changes rejected, every original DIR64 change rejected, unspecified padding changes accepted. Wrong header ImageBase/size/alignment rejected.',
                'count_note':'85 runtime assertions include positive setup and restoration assertions; they are not 85 independent adversarial cases.'},
            'safety_contract':[
                'Initial private credential must return exact EFI_NOT_FOUND to a size-only query; preexisting/unknown records are never adopted or overwritten.',
                'Only a valid 128-byte attrs=3 record observed after this test UI may become owned. Unexpected pre-UI changes or invalid/backward-generation post-UI records are sticky unknown.',
                'The sole direct setter deletes one fixed private name/GUID, after byte-identical readback; reads back NOT_FOUND and wipes the owned RAM copy. No generic setter or RuntimeServices replacement.',
                'Original OC/MEM stores are compared read-only with full values and attributes; no repair writes.',
                'Wrong TPL, changed RuntimeServices identity, corrupt/dangling owned state or ended boot services lead to CPU hold with no subsequent service call.',
                'M is a separate temporary test form; B is original Setup formset default entry. Neither proves a permanent ASUS Security menu item or direct Del/F2 boot integration.'
            ],
            'remaining_limits':[
                'Full installer allocation/publication/rollback and exact final application boot remain separate validation responsibilities.',
                'OVMF and mocked service tests do not prove ASUS native rendering/KVM/password behavior, multi-core/AP/TLB correctness, or hardware loading of a new app build.',
                'Snapshots cannot prove every OEM internal NVRAM write absent, and exact-read-before-delete is not an atomic comparison against hostile concurrent firmware.',
                'No BMC/device action, flashing, firmware trust/recovery acceptance, or release approval is performed by this work.'
            ],
            'external_inputs':[entry(p)for p in sorted(external)]}
def own():
    return [entry(p,HERE)for p in sorted(HERE.rglob('*'))if p.is_file()and p!=MANIFEST and not any(x in {'zig-local','zig-global','__pycache__'}for x in p.relative_to(HERE).parts)]
def main():
    parser=argparse.ArgumentParser();g=parser.add_mutually_exclusive_group(required=True);g.add_argument('--freeze',action='store_true');g.add_argument('--verify-only',action='store_true');args=parser.parse_args()
    report=collected()
    if args.freeze:
        assert not REPORT.exists()and not MANIFEST.exists()
        REPORT.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
        manifest={'path_base':str(HERE),'status':report['status'],'external_inputs':report['external_inputs'],'artifacts':own(),'excluded':['manifest self-reference','all zig-local/zig-global cache subtrees','__pycache__']}
        MANIFEST.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    else:
        assert read(REPORT)==report;manifest=read(MANIFEST)
        assert manifest['external_inputs']==report['external_inputs']and manifest['artifacts']==own()
    print(json.dumps({'status':'PASS','review_sha256':sha(REPORT),'manifest_sha256':sha(MANIFEST),'external_bindings':len(manifest['external_inputs']),'local_artifacts':len(manifest['artifacts']),'ui_cases':105,'actual_validator_assertions':85,'frozen_P13_bindings_reverified':60}))
if __name__=='__main__':main()

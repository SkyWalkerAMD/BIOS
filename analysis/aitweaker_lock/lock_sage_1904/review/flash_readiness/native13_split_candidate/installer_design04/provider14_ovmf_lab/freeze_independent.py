from pathlib import Path
import argparse,hashlib,json,re,sys

HERE=Path(__file__).resolve().parent;D04=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'))
from PIL import Image
UI=D04/'ram_transaction08/ui_independent_review'
VAL=HERE/'tx08_validator_e0793175'
REVIEW=HERE/'independent_review.json';MANIFEST=HERE/'independent_manifest.json'
APP='e0793175f78b6488c8222b65f0d5321d97e881bd06dca033a314d3fa8d307486'
PROVIDER='495fe43ffa8ebb685c1346501a08c2d2932bc94d62809ab01b3f019d33029630'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda p:json.loads(p.read_text(encoding='utf8'))

def artifact(p):
    return {'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}

def manifest_inputs(path,pin,base,count):
    assert sha(path)==pin,str(path)
    rows=read(path)['artifacts'];assert len(rows)==count
    inputs=[path]
    for row in rows:
        p=base/row['path']
        assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],str(p)
        inputs.append(p)
    return inputs

def verify_qemu(args,run,readonly_boot):
    assert args[args.index('-nic')+1]=='none'
    assert args[args.index('-accel')+1]=='tcg,thread=single'
    assert args[args.index('-smp')+1]=='1'
    assert not any(x in args for x in ['-net','-netdev','-hda','-hdb','-cdrom'])
    drives=[args[i+1] for i,v in enumerate(args) if v=='-drive']
    assert len(drives)==3
    for spec in drives:
        entries=dict(p.split('=',1) for p in spec.split(','))
        path=Path(entries['file']).resolve()
        if entries.get('if')=='pflash' and entries.get('unit')=='0':
            assert entries.get('readonly')=='on'
            assert path==(ROOT/'tools/qemu-11.1.0/share/edk2-x86_64-code.fd').resolve()
        elif entries.get('if')=='pflash' and entries.get('unit')=='1':
            assert path.is_relative_to(run.resolve())
        else:
            assert entries.get('readonly')=='on' and path==readonly_boot.resolve()

def collect():
    external=manifest_inputs(D04/'provider14_chrome07/local_candidate_manifest.json',
       '150ae9aaba738a2c70f3075d741f4875f0c9f26ce8006ca83eafd71c5e9e7019',D04,49)
    external+=manifest_inputs(D04/'ram_transaction08/ram_candidate_manifest.json',
       '7f08d975710179f88f953636b1da72db34ebd0c41ef04447bdf40b296a599e96',D04,81)
    assert sha(D04/'ram_transaction08/app_build/SageNative13RamTest08.efi')==APP
    assert sha(D04/'provider14_chrome07/build/AiTweakerSplitProvider14.UNSIGNED.local.efi')==PROVIDER
    assert sha(UI/'inputs/SageNative13RamTest08.efi')==APP
    assert sha(VAL/'inputs/SageNative13RamTest08.efi')==APP
    assert sha(VAL/'inputs/AiTweakerSplitProvider14.UNSIGNED.local.efi')==PROVIDER
    source_old=D04/'provider13/source';source_new=D04/'provider14_chrome07/source'
    names_old={p.name for p in source_old.iterdir() if p.is_file()}
    names_new={p.name for p in source_new.iterdir() if p.is_file()}
    assert names_new==names_old
    changed=[name for name in sorted(names_new) if sha(source_new/name)!=sha(source_old/name)]
    assert changed==['split_profile.h'],changed
    for name in sorted(names_new):external.extend([source_old/name,source_new/name])
    package=(source_new/'management_package.h').read_bytes()
    assert package==(source_old/'management_package.h').read_bytes()
    old_lab=D04/'provider13_ovmf_lab/provider13_ovmf_manifest.json'
    assert sha(old_lab)=='1cd8efe3fb87636ed0bae8add264d802770fccfa29a56919828025e69ae72fe0'
    old=read(old_lab)
    for key in ['artifacts','external_inputs']:
        for row in old[key]:
            p=Path(row['path'])
            if not p.is_absolute():p=Path(old['path_base'])/p
            assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],str(p)
    external.extend([old_lab,D04/'provider13_ovmf_lab/provider13_ovmf_review.json'])
    run=HERE/'runs/20261103_230022';result=read(run/'result.json')
    assert result==read(HERE/'latest_result.json')
    assert sha(HERE/'latest_result.json')=='786bef6d4dfcd2a35f4d257658fd1305508f8c1f3a33482f9dc928bec0cf98d0'
    assert result['status']=='PASS_TWO_PROCESS_OVMF_REAL_STORAGE_AND_CONSOLE_UI' and result['error'] is None
    assert result['provider_sha256']==PROVIDER and result['readonly_boot_disk_unchanged']
    assert sha(HERE/'build/P14-OVMF-FIXTURE-NOT-FOR-HARDWARE.EFI')==result['fixture_sha256']
    assert sha(HERE/'persist_ui.c')==result['fixture_source_sha256']
    assert sha(HERE/'run_persist_ui.py')==result['runner_sha256']
    for name in ['persist_ui.c','fixture_extra.inc','run_persist_ui.py']:
        assert sha(HERE/name)==sha(run/'fixture-snapshot'/name)
    previous=result['initial_vars_sha256'];screens=0;boots=[]
    for phase,expected_checks in [(1,173),(2,192)]:
        boot=result['boot_reports'][phase-1];directory=run/f'boot{phase}'
        assert boot==read(directory/'result.json')
        assert boot['status']=='PASS' and boot['exit_code']==33 and boot['error'] is None
        assert boot['vars_before_sha256']==previous;previous=boot['vars_after_sha256']
        log=directory/'debug.log';assert sha(log)==boot['debug_sha256']
        raw=log.read_text(encoding='ascii',errors='replace')
        labels=re.findall(r'^PASS (.+)$',raw,re.M)
        assert len(labels)==expected_checks==boot['checks'] and 'FAIL ' not in raw
        assert 'P14_UI_OVMF_PASS\n' in raw
        assert 'PASS real ExitBootServices succeeds\n' in raw
        assert 'PASS real EBS permanently revokes provider\n' in raw
        assert 'PASS actual EBS retires split state to ENDED\n' in raw
        if phase==1:
            assert 'PASS real HII management form exits successfully\n' in raw
        else:
            assert 'PASS credential bytes persist identically across separate QEMU boots\n' in raw
            assert 'PASS full real GOP framebuffer restored byte-for-byte\n' in raw
        verify_qemu(read(directory/'command.json'),run,run/'readonly-boot.img')
        for row in boot['screenshots']:
            png=Path(row['path']);assert sha(png)==row['sha256']
            with Image.open(png) as a,Image.open(png.with_suffix('.ppm')) as b:
                assert a.size==b.size and a.convert('RGB').tobytes()==b.convert('RGB').tobytes()
            screens+=1
        boots.append({'phase':phase,'assertions':expected_checks,'exit_code':33,
                      'debug_log':artifact(log),'keyboard_steps':boot['standard_keyboard_actions']})
    assert previous==result['final_vars_sha256']==sha(run/'shared-vars.fd')
    ui=read(UI/'ui_test_result.json')
    assert sha(UI/'ui_test_result.json')=='66632d9172bd8f30f3ec12d4036b40d122570c6d5ab659d7aa94f3bc237593d5'
    assert ui['actual_app_sha256']==APP and ui['cases']==139
    assert all(row['status']=='PASS' for row in ui['results'])
    for row in ui['source_bindings']:
        p=Path(row['path']);assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256']
    valwrapper=read(VAL/'latest_result.json');val=valwrapper['result'];valrun=Path(valwrapper['run'])
    assert sha(VAL/'latest_result.json')=='6dd26281fd20d3b39ef98173ff850004af48a40d8a0c50e9a9b38eec1286ab4e'
    assert val['status']=='PASS_ACTUAL_LOADED_APP_VALIDATOR_IN_OVMF' and val['exit_code']==33
    assert val['actual_app_sha256']==APP and val['provider_sha256']==PROVIDER and val['checks']==85
    assert not val['imports_started'] and val['readonly_boot_unchanged']
    assert len(val['relocations_tested'])==17
    verify_qemu(read(valrun/'command.json'),valrun,valrun/'readonly-boot.img')
    for row in val['source_bindings']:
        p=Path(row['path']);assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256']
    globals_report=D04/'ram_transaction08/app_build/globals_verification.json'
    external.append(globals_report)
    external.extend([D04/'native_unwind_review08/independent_review.json',D04/'native_unwind_review08/independent_manifest.json',
        ROOT/'tools/qemu-11.1.0/share/edk2-x86_64-code.fd',ROOT/'tools/qemu-11.1.0/share/edk2-i386-vars.fd',
        ROOT/'tools/qemu-11.1.0/qemu-system-x86_64.exe',ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'])
    report={
      'status':'PASS_LOCAL_P14_TX08_BINDING_AND_DECLARED_UEFI_SIMULATION_NOT_NATIVE_ASUS_ACCEPTANCE',
      'actual_app_sha256':APP,'actual_provider_sha256':PROVIDER,
      'candidate_manifest_bindings_reverified':{'P14':49,'TX08':81},
      'provider_production_source_difference_from_P13':changed,
      'old_P13_lab':{'manifest_sha256':sha(old_lab),'local_bindings_preserved':len(old['artifacts']),
                    'external_bindings_preserved':len(old['external_inputs'])},
      'actual_provider_two_process_test':{'leaf':artifact(HERE/'latest_result.json'),'boot_assertions':boots,
          'png_ppm_pairs_equal':screens,'shared_vars_byte_chain_valid':True,
          'features':['Actual pinned P14 LoadImage/StartImage and exact detached guard owner lifecycle.',
           'Real OVMF HII database NewPackageList/Export exact991B equality and ConfigAccess publication.',
           'First enrollment selected by actual OVMF SendForm and standard emulated keyboard. Later verify/change/clear directly invoke the installed ConfigAccess callback.',
           'Wrong password refusal, cooldown, session-only unlock, change, separate second-process identical saved-record observation, previous-password refusal, Escape cancellation, explicit disabled record and next-session state.',
           'Actual ExitBootServices revokes provider and marks split state ENDED; RuntimeServices GetVariable/SetVariable table entries are not replaced.',
           'Selected direct callback restores complete real GOP framebuffer and console/cursor metadata. This is an OVMF checkpoint, not ASUS visual restoration.'],
          'substitutions':['OEM AMITSE and Setup DXE entrypoints and original ASUS browser body do not execute.',
           'Exactly12 detours in VM-loaded original modules, matching FV-file paths and two BootServices globals are fixture setup.',
           'TCG-only execution breakpoint at E1CA restores the original eight pushes and changes saved RIP to the declared browser_body. OEM body bytes are not patched.',
           'Native render/input/static-chrome classification paths are not reached by this body replacement; separate07 classifier tests are not added to this runtime count.',
           'Fixture allocation/protection prepares actual RX guards/RW-NX state; it is not the production transaction installer.',
           'New template exceeds16KiB, so this new fixture computes five guard pages and protects that full owned extent instead of reusing the old four-page allocation.'],
          'scope':'Single-vCPU QEMU TCG; no NIC, physical disk, BMC, actual user credential or flashing. Writable state limited to owned local VAR image.'},
      'actual_full_app_ui':{'leaf':artifact(UI/'ui_test_result.json'),'cases':139,
          'scope':'Actual e079 full-app UI functions and app_require_services; firmware/provider endpoints, platform_native_globals and pure log sink explicitly modeled. No app recompilation or installer entry execution.',
          'new_coverage':['ActionRequest starts NONE and unchanged-on-normal-return succeeds.',
           'Pre-globals ordinary failure prevents SendForm.',
           'Post-globals ordinary failure still observes private record and OC/MEM for exact-owned cleanup, then returns failure.',
           'Private/store/provider/owned-chain/EBS changes after pre-globals are rechecked before SendForm.',
           'Post-SendForm TPL and every modeled EBS boundary prevent subsequent firmware service.'],
          'globals_internal_coverage':'This suite models platform_native_globals. Author actual23 collector cases are separate in globals_verification.json, bound through the frozen81-item candidate manifest; they are not counted as these139.'},
      'actual_loaded_validator':{'leaf':artifact(VAL/'latest_result.json'),'cases':85,'dir64_targets':17,
          'scope':'Standard OVMF LoadImage loads unchanged final app and P14; actual compiled provider_before_start, real CPU environment and MemoryMap execute. Neither imported EFI entrypoint starts in this fixture.',
          'coverage':'Accepts correctly loaded/rebased images and permitted header ImageBase variants; rejects declared header/text/data/BSS/each17DIR64 mutations, wrong size and unaligned base. Undefined alignment/raw-tail padding is ignored. Mutation copies are owned; original loaded provider full hash unchanged.'},
      'visual_review':['20261103_230022/boot1/enroll_a-prompt.png: real OVMF Ai Tweaker Password form with three actions visible.',
                       '20261103_230022/boot1/enroll_a-password-via-form.png: selected Set/change opens real New password prompt.'],
      'count_note':'173 and192 count runtime assertions including repeated setup.139 and85 are separately scoped checks; do not sum these into unique hardware tests.',
      'known_gaps':['No proven safe automatic unwind for an unknown page with no safe redirect; no app+5A/resetflag/RT shortcut is introduced.',
       'No original ASUS renderer/input/static-chrome execution in this OVMF body fixture, no acceptance of the prior black-screen fix on hardware.',
       'No native password-entry hardware test, B/original Setup initial-page and alternative-entry acceptance, direct Del/F2 permanent integration, all12 detour paths or AP/TLB concurrency proof.',
       'No all-OEM-variable-writes-absent claim; no firmware signature/flash trust/SPI backup/recovery validation.'],
      'stage_advice':'Final delivery is separately reviewed by root. A first reviewed physical M display -> native ESC -> Q without password input remains distinct from password/B/automatic-unwind acceptance.',
      'firmware_release_ready':False,'device_actions':0,'frozen_inputs_modified':False,
      'external_inputs':[artifact(p) for p in sorted(set(external))]
    }
    return report

def owned_files():
    out=[]
    for directory in [HERE,UI]:
        for p in directory.rglob('*'):
            if p.is_file() and p!=MANIFEST and not any(x in {'zig-local','zig-global','__pycache__'} for x in p.parts):out.append(p)
    return sorted(set(out))

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--freeze',action='store_true');parser.add_argument('--verify-only',action='store_true')
    args=parser.parse_args();assert args.freeze!=args.verify_only
    report=collect()
    if args.freeze:
        assert not REVIEW.exists() and not MANIFEST.exists(),'Do not overwrite a frozen review'
        REVIEW.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
        artifacts={row['path']:row for row in report['external_inputs']+[artifact(p)for p in owned_files()]}
        MANIFEST.write_text(json.dumps({'path_base':'workspace_root','artifacts':sorted(artifacts.values(),key=lambda x:x['path']),
           'excluded':['manifest self-reference','**/zig-local/**','**/zig-global/**','**/__pycache__/**']},indent=2)+'\n',encoding='utf8')
    else:assert read(REVIEW)==report,'Evidence or review changed'
    manifest=read(MANIFEST)
    for row in manifest['artifacts']:assert artifact(ROOT/row['path'])==row,row['path']
    assert all(artifact(p) in manifest['artifacts'] for p in owned_files())
    print(json.dumps({'status':'PASS','bindings':len(manifest['artifacts']),
          'manifest_sha256':sha(MANIFEST),'review_sha256':sha(REVIEW),'png_ppm_pairs':report['actual_provider_two_process_test']['png_ppm_pairs_equal']}))

if __name__=='__main__':main()

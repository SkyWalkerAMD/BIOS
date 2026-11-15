"""Revalidate existing read-only P3 bytes for W890; never modifies legacy evidence."""
from pathlib import Path
import datetime, hashlib, importlib.util, json, shutil, sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
LEGACY = ROOT / 'analysis/aitweaker_lock/probe_p3_kvm'
for folder in ('pydeps', 'vm-pydeps', 'kvm-pydeps'):
    sys.path.insert(0, str(ROOT / 'tools' / folder))
sys.path.insert(0, str(LEGACY))

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def save(p, v):
    p.write_text(json.dumps(v, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')

def load(name, p):
    spec=importlib.util.spec_from_file_location(name, p)
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module
    spec.loader.exec_module(module)
    return module

def main():
    run=HERE / ('validation-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    run.mkdir(parents=True, exist_ok=False)
    original=json.loads((LEGACY/'build.json').read_text(encoding='utf-8'))
    for name, key in (('BOOTX64.EFI','efi_sha256'),('AiTweaker-P3-KVM.iso','iso_sha256')):
        assert sha(LEGACY/name)==original[key], (name,'legacy identity mismatch')
        shutil.copyfile(LEGACY/name,run/name)
    sources={str(p.relative_to(ROOT)).replace('\\','/'):sha(p) for p in (LEGACY/'source').rglob('*') if p.is_file()}
    tests=[LEGACY/'verify_inventory.py',LEGACY/'verify_vm.py',LEGACY/'decode_captures.py',LEGACY.parent/'probe_p2/verify.py',LEGACY.parent/'inspect_setup.py']
    sources.update({str(p.relative_to(ROOT)).replace('\\','/'):sha(p) for p in tests})
    save(run/'input_manifest.json',{'scope':'Unchanged P3 read-only inventory; not the W890 password lock','efi_sha256':sha(run/'BOOTX64.EFI'),'iso_sha256':sha(run/'AiTweaker-P3-KVM.iso'),'source_bindings':sources})
    report={'target':'W890_SAGE_0603','passed':False,'hardware_run':False,'firmware_write':False,'checks':[]}
    save(run/'result.json',report)
    try:
        fixture=load('w890_probe_inventory_fixture',LEGACY/'verify_inventory.py')
        fixture.OUT=run
        (run/'capture_tests').mkdir()
        for case in ('normal','no_protocols','no_modules','malformed_hii','allocation_failure','unknown_build','watchdog_error','no_keyboard','keyboard_error'):
            value=fixture.Machine('W890_SAGE_0603',case).check()
            report['checks'].append(value)
            print('W890 original module inventory',case,'PASS',flush=True)
        vm=load('w890_probe_vm_fixture',LEGACY/'verify_vm.py')
        vm.OUT=run
        vm.ISO=run/'AiTweaker-P3-KVM.iso'
        report['ovmf']=vm.run('sata',800,600,0)
        assert report['ovmf']['passed']
        assert sha(run/'BOOTX64.EFI')==original['efi_sha256']
        assert sha(run/'AiTweaker-P3-KVM.iso')==original['iso_sha256']
        report['passed']=True
    except Exception as e:
        report['error']=type(e).__name__+': '+str(e)
        raise
    finally:
        report['scope_limits']=['Native inventory service calls are synthetic in the 9 W890 cases.','OVMF proves generic boot, QR recovery and display controls only.','No physical W890 inventory run yet.','No password lock or flash-acceptance behavior is tested.']
        save(run/'result.json',report)
        print(json.dumps({'passed':report['passed'],'result':str(run/'result.json'),'cases':len(report['checks'])}),flush=True)

if __name__=='__main__':
    main()

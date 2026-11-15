"""QEMU-only RuntimeServices fault injection; no fixture in delivery media."""
from pathlib import Path
import datetime,json,os,subprocess,sys
from build_loader import OUT,ROOT,sha
from run_tests import iso_for,run_vm,save
sys.path.insert(0,str(OUT/'tests'))
from inject_fixture_ovmf import inject
def main():
    root=OUT/'tests/seed-runs'/datetime.datetime.now().strftime('%Y%m%d_%H%M%S');root.mkdir(parents=True)
    fixture=OUT/'tests/fixture';files={'/EFI/BOOT/BOOTX64.EFI':(fixture/'loader/BOOTX64.EFI').read_bytes(),'/LINUX/VMLINUX.EFI':(fixture/'VMFIXTURE.EFI').read_bytes(),'/LINUX/CAPACITY01.IMG':(fixture/'NOT-AN-INITRAMFS.fixture').read_bytes()}
    zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(OUT/'cache/global');env['ZIG_LOCAL_CACHE_DIR']=str(OUT/'cache/local')
    report={'scope':'Actual bootstrap under OVMF with a separate TCG-only RuntimeServices fault injection DXE','bootstrap_sha256':sha(fixture/'loader/BOOTX64.EFI'),'cases':[],'all_passed':False}
    for n,name,stage in [(1,'present','seed_preflight'),(2,'read_error','seed_preflight'),(3,'appears_before_handoff','seed_handoff'),(4,'error_before_handoff','seed_handoff'),(5,'inconsistent_not_found','seed_preflight'),(6,'success_zero_size','seed_preflight')]:
        folder=root/name;folder.mkdir();obj=folder/'seed.obj';efi=folder/'SEED-TEST-ONLY.EFI';fd=folder/'OVMF-TEST-ONLY.fd'
        subprocess.run([str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(OUT/'source'),'-std=c11','-Oz','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar',f'-DSEED_CASE={n}','-c',str(OUT/'tests/seed_fixture.c'),'-o',str(obj)],env=env,check=True)
        subprocess.run([str(zig),'lld-link','/subsystem:efi_boot_service_driver','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/timestamp:0','/out:'+str(efi),str(obj)],env=env,check=True)
        inject(efi,fd);iso=iso_for(folder,files)
        result=run_vm(folder,iso,'LC01_BOOT_STOP '+stage,firmware=fd)
        debug=(folder/'debug.log').read_text(encoding='ascii',errors='replace')
        assert result['passed'] and 'LC01_TEST_SEED_FIXTURE_INSTALLED' in debug and 'LC01_FIXTURE_ENTER' not in debug and 'LC01_TEST_FORBIDDEN_SET_VARIABLE' not in debug and 'LC01_TEST_SEED_CONTENT_REQUEST_FORBIDDEN' not in debug
        expected=2 if n in [3,4] else 1;assert debug.count('LC01_TEST_SEED_QUERY')==expected
        result.update({'case':name,'zero_buffer_queries':expected,'seed_contents_requested':False,'bootstrap_set_variable_calls':0,'fixture_efi_sha256':sha(efi),'test_firmware_sha256':sha(fd)})
        report['cases'].append(result);save(root/'summary.json',report);print(name,'PASS',flush=True)
    report['all_passed']=True;save(root/'summary.json',report);save(OUT/'tests/latest_seed_gate_results.json',report)
if __name__=='__main__':main()

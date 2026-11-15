"""Explicitly non-deliverable temporary variants for isolating EFI handoff.
Never changes the production source. Never use these on hardware.
"""
from pathlib import Path
import argparse,json,os,subprocess,sys
OUT=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(OUT))
from build_loader import ROOT,sha
from run_tests import iso_for,save,disk_images
def main():
    p=argparse.ArgumentParser();p.add_argument('variant',choices=['skip_watchdog','path_load','inspect_tpl','silent_lf2']);a=p.parse_args()
    prior=json.loads((OUT/'production_provisional_serial_debug/media_manifest.json').read_text());contract=prior['contract']
    dest=OUT/'tests/debug_variants'/a.variant;dest.mkdir(parents=True,exist_ok=True)
    source=(OUT/'source/bootstrap.c').read_text()
    if a.variant=='skip_watchdog':source=source.replace('ES e=((WATCHDOG)st->bs->set_watchdog)(0,0,0,0);','ES e=0;/* DEBUG ONLY: skip watchdog call */')
    elif a.variant=='path_load':source=source.replace('(0,self,kernel_path,kernel,LC_KERNEL_BYTES,&child)','(0,self,kernel_path,0,0,&child)').replace('uint8_t*kernel=read_verified','uint8_t*kernel __attribute__((unused))=read_verified')
    elif a.variant=='inspect_tpl':
        source=source.replace('UN exit_size=0;', 'typedef UN(EA*RAISE)(UN);typedef void(EA*RESTORE)(UN);UN old_tpl=((RAISE)st->bs->raise_tpl)(31);((RESTORE)st->bs->restore_tpl)(old_tpl);uint64_t flags;__asm__ volatile("pushfq; popq %0":"=r"(flags));message("DEBUG_ONLY_TPL=");number(old_tpl);message(" FLAGS=");number(flags);message("\\r\\n");UN exit_size=0;')
    else:source=source.replace('message("LC01_INITRD_DELIVERED\\r\\n");','/* DEBUG: no ConsoleOut inside LoadFile2 */')
    assert source!=(OUT/'source/bootstrap.c').read_text()
    src=dest/'DEBUG-ONLY-bootstrap.c';src.write_text(source,encoding='utf8')
    zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(OUT/'cache/global');env['ZIG_LOCAL_CACHE_DIR']=str(OUT/'cache/local')
    subprocess.run([str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(OUT/'source'),'-I',str(OUT/'production_provisional_serial_debug/build'),'-std=c11','-Oz','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections','-c',str(src),'-o',str(dest/'bootstrap.obj')],env=env,check=True)
    boot=dest/'BOOTX64.EFI';subprocess.run([str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/timestamp:0','/opt:ref','/out:'+str(boot),str(dest/'bootstrap.obj'),str(OUT/'production_provisional_serial_debug/build/sha256.obj')],env=env,check=True)
    iso=iso_for(dest,{'/EFI/BOOT/BOOTX64.EFI':boot.read_bytes(),'/LINUX/VMLINUX.EFI':Path(contract['kernel']['path']).read_bytes(),'/LINUX/CAPACITY01.IMG':Path(contract['initrd']['path']).read_bytes()})
    manifest={**prior,'status':'DEBUG VARIANT ONLY - NEVER HARDWARE','variant':a.variant,'debug_source_sha256':sha(src),'iso':str(iso),'iso_sha256':sha(iso),'efi_sha256':sha(boot)};save(dest/'media_manifest.json',manifest);print(str(dest/'media_manifest.json'))
if __name__=='__main__':main()

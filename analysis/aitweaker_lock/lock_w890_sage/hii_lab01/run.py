"""Build and boot an isolated TCG-only HII service integration lab."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = BASE.parents[2]
P = BASE / 'password'
R = BASE / 'password_runtime02'
sys.path[:0] = [str(ROOT/'tools/pydeps'), str(ROOT/'tools/kvm-pydeps'), str(ROOT/'analysis/aitweaker_lock'), str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015')]
import pefile
import pycdlib
import disk_images
from inspect_setup import string_packages


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def save(p, value):
    p.write_text(json.dumps(value, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')


def blob(name, data):
    return 'static const uint8_t '+name+'[]={\n'+''.join(','.join(hex(v) for v in data[i:i+32])+',\n' for i in range(0,len(data),32))+'};\n'


def main():
    folder = HERE/'runs'/datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    folder.mkdir(parents=True)
    profile = json.loads((P/'profile_0603.json').read_text())
    setup = ROOT/profile['sources']['Setup']['path']
    assert sha(setup) == profile['sources']['Setup']['sha256']
    raw = setup.read_bytes()
    strings = string_packages(raw)
    assert len(strings) == 1
    s = strings[0]
    english = raw[s['offset']:s['offset']+s['length']]
    forms = (P/'official_forms_0603.pack').read_bytes()
    assert hashlib.sha256(forms).hexdigest() == '0111abd4e9914a32b865fc95af15990687a9d05f984df533c30e028e38cbba2f'
    guid = uuid.UUID('15b535e2-608f-493e-bfea-d3aa1ce7b50c').bytes_le
    package = guid+struct.pack('<I',24+len(forms)+len(english))+forms+english+bytes.fromhex('040000df')
    fixtures = folder/'fixtures.h'
    fixtures.write_text(blob('original_package',package)+blob('original_forms',forms)+f'#define ORIGINAL_MAX_STRING {max(map(int,s["strings"]))}\n',encoding='ascii')
    zig = ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
    env = os.environ.copy()
    env.update(ZIG_LOCAL_CACHE_DIR=str(folder/'zig-local'), ZIG_GLOBAL_CACHE_DIR=str(folder/'zig-global'))
    sources = [HERE/'lab.c',P/'w890_policy.c',P/'core/password_crypto.c']
    commands = []
    objects = []
    for source in sources:
        obj = folder/(source.stem+'.obj')
        cmd = [str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(folder),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(source),'-o',str(obj)]
        commands.append(cmd)
        subprocess.run(cmd,check=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
        objects.append(obj)
    app = folder/'W890-HII-LAB01.TCG-ONLY.efi'
    cmd = [str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/out:'+str(app),*[str(p) for p in objects]]
    commands.append(cmd)
    subprocess.run(cmd,check=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
    pe=pefile.PE(str(app));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();app.write_bytes(pe.write())
    inputs=sources+[HERE/'run.py',R/'source/efi.h',P/'w890_policy.h',P/'w890_policy_data.h',P/'core/password_core.h',P/'management_package.h',P/'official_forms_0603.pack',fixtures,setup]
    manifest={str(p):{'bytes':p.stat().st_size,'sha256':sha(p)} for p in inputs}
    save(folder/'inputs.json',manifest);save(folder/'build_commands.json',commands)
    Q=ROOT/'tools/qemu-11.1.0';share=Q/'share';varsfile=folder/'vars.fd'
    shutil.copyfile(share/'edk2-i386-vars.fd',varsfile)
    disk_images.OUT=folder;disk_images.VOLUME_SIZE=16*1024*1024
    boot=folder/'boot.img';disk_images.create(boot,'superfloppy',16,{'/EFI/BOOT/BOOTX64.EFI':app.read_bytes()})
    iso=folder/'W890-HII-LAB01.TCG-ONLY.iso'
    cd=pycdlib.PyCdlib();cd.new(interchange_level=3,vol_ident='W890_HII_LAB01',joliet=3)
    cd.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG');cd.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul');cd.write(str(iso));cd.close()
    debug=folder/'debug.log'
    cmd=[str(Q/'qemu-system-x86_64.exe'),'-L',str(share),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-serial','file:'+str(folder/'serial.log'),'-debugcon','file:'+str(debug),'-global','isa-debugcon.iobase=0x402','-device','isa-debug-exit,iobase=0xf4,iosize=0x4','-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),'-drive','if=none,id=boot,format=raw,media=cdrom,readonly=on,file='+str(iso),'-device','ide-cd,drive=boot,bus=ide.0,bootindex=1']
    save(folder/'qemu_command.json',cmd)
    report={'status':'RUNNING','scope':'Real OVMF HII Database/String services; isolated lab-owned packages. No ASUS native browser, ConfigAccess dispatch or password/OC writes tested.','efi_sha256':sha(app),'iso_sha256_before':sha(iso),'original_forms_sha256':sha(P/'official_forms_0603.pack'),'ovmf_sha256':sha(share/'edk2-x86_64-code.fd'),'source_bindings':manifest}
    print('START',str(folder),flush=True)
    try:
        start=time.monotonic()
        with (folder/'stderr.log').open('wb') as err,(folder/'stdout.log').open('wb') as out:
            process=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=out,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW)
            try:code=process.wait(timeout=120)
            except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=10);raise RuntimeError('HII lab timed out; evidence preserved')
        text=debug.read_text(encoding='ascii',errors='replace')
        report.update({'exit_code':code,'seconds':round(time.monotonic()-start,3),'checks':text.count('PASS '),'debug_sha256':sha(debug),'iso_sha256_after':sha(iso)})
        assert code==33 and 'W890_HII_LAB01_PASS' in text and 'FAIL ' not in text, text[-2500:]
        assert report['iso_sha256_before']==report['iso_sha256_after']
        report['status']='PASS_REAL_OVMF_HII_PUBLICATION_UPDATE_ROLLBACK_REMOVAL'
    except Exception as e:
        report['status']='FAILED_RETAINED_EVIDENCE';report['error']=str(e)
        raise
    finally:
        report['finished_utc']=datetime.now(timezone.utc).isoformat();save(folder/'result.json',report)
        print(json.dumps({k:report[k] for k in ['status','checks','efi_sha256'] if k in report}),flush=True)
        print('REPORT',str(folder/'result.json'),flush=True)


if __name__=='__main__':main()

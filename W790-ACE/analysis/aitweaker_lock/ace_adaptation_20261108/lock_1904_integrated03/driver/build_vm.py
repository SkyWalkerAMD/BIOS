from pathlib import Path
import hashlib,json,os,subprocess,sys,struct,uuid
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'tools/zig-x86_64-windows-0.14.1/zig.exe').is_file());OUT=HERE/'build'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock'))
from inspect_setup import string_packages
case=ROOT/'analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF'
original=(case/'modules/Setup.efi').read_bytes()
ifr=json.loads((case/'modules/Setup_IFR.json').read_text(encoding='utf8'))[0]
strings=string_packages(original);assert len(strings)==1
sections=[original[x['offset']:x['offset']+x['length']] for x in [ifr,strings[0]]]
package=uuid.UUID('899407d7-99fe-43d8-9a21-79ec328cac21').bytes_le+struct.pack('<I',24+sum(map(len,sections)))+b''.join(sections)+b'\x04\0\0\xdf'
(OUT/'vm_hii_data.h').write_text('/* VM-only original 1904 IFR and English HII resources. */\nstatic const unsigned char vm_hii_data[]={\n'+''.join(','.join(hex(x) for x in package[i:i+24])+',\n' for i in range(0,len(package),24))+'};\n',encoding='ascii')
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(HERE),'-I',str(OUT),'-I',str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source'),'-std=c11','-Oz','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(HERE/'vm_fixture.c'),'-o',str(OUT/'vm_fixture.obj')]
subprocess.run(cmd,check=True,env=env)
efi=OUT/'VM-INTEGRATION-ONLY.EFI'
subprocess.run([str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(OUT/'vm_fixture.map'),'/out:'+str(efi)]+[str(OUT/(n+'.obj')) for n in ['vm_fixture','services','cpu_entropy','ui','hii','policy','password_core','password_crypto','probe_core']],check=True,env=env)
p=pefile.PE(str(efi));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();efi.write_bytes(p.write())
print(json.dumps({'bytes':efi.stat().st_size,'sha256':hashlib.sha256(efi.read_bytes()).hexdigest(),'scope':'Actual services/UI/HII/policy/crypto compiled objects; QEMU-TCG-only fixture entry, OEM navigation adapter excluded'}))

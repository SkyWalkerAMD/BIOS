from pathlib import Path
import hashlib,importlib.util,json,os,re,shutil,struct,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];BASE=ROOT/'analysis/aitweaker_lock'
OUT=HERE/'preflight';SRC=OUT/'source';SRC.mkdir(parents=True,exist_ok=True)
for name in ['pydeps','vm-pydeps','kvm-pydeps']:sys.path.insert(0,str(ROOT/'tools'/name))
import pefile,pycdlib
from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS
original=BASE/'probe_p3_kvm/source'
for p in original.rglob('*'):
 if p.is_file():dest=SRC/p.relative_to(original);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
driver=BASE/'lock_1904/driver'
services=(driver/'services.c').read_text(encoding='utf8');entry=(driver/'entry.c').read_text(encoding='utf8')
walk=services[services.index('int memory_present('):services.index('int patch_memory(')]
board=entry[entry.index('static int equal_ascii('):entry.index('static int image_guid(')]
guids='\n'.join(line for line in entry.splitlines() if line.startswith(('static GUID smbios3_guid','static GUID smbios_guid')))
extra=walk+'\n'+guids+'\n#define system_table st\n#define memcmp(a,b,n) (!equal((a),(b),(n)))\n'+board+'\n#undef memcmp\n#undef system_table\n'+(HERE/'preflight_extra.c').read_text(encoding='utf8')
probe=(SRC/'probe.c').read_text(encoding='utf8')
probe=probe.replace('/* No SimpleFileSystem or RuntimeServices are called. Display-only log export. */',extra+'\n/* P4 adds read-only RuntimeServices metadata queries. */')
probe=probe.replace('inspect_images();inspect_protocols();inspect_hii();','inspect_images();inspect_protocols();inspect_hii();inspect_preflight();')
probe=probe.replace('Ai Tweaker P3 KVM - collecting read-only inventory...','Ai Tweaker P4 - read-only lock preflight...')
(SRC/'probe.c').write_text(probe,encoding='utf8')
kvm=(SRC/'kvm.c').read_text(encoding='utf8').replace('AI TWEAKER P3 - KVM LOG','AI TWEAKER P4 - PREFLIGHT')
(SRC/'kvm.c').write_text(kvm,encoding='utf8')
profiles=(SRC/'profiles.h').read_text(encoding='utf8');new=[]
for module,guid,crc in [('AMITSE','{0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}}',0x760c4005),('Setup','{0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}}',0x9e141291)]:
 p=pefile.PE(str(BASE/f'hardware_20261102_W790_ACE_E9B906DF/modules/{module}.efi'))
 t=next(s for s in p.sections if s.Name.rstrip(b'\0')==b'.text')
 new.append('{'+guid+f',{crc}U,{t.VirtualAddress}U,{t.Misc_VirtualSize}U,{p.OPTIONAL_HEADER.AddressOfEntryPoint}U,{p.OPTIONAL_HEADER.SizeOfImage}U,"W790_ACE_1904/{module}"'+'}')
profiles=profiles.replace('\n};',',\n'+',\n'.join(new)+'\n};');(SRC/'profiles.h').write_text(profiles,encoding='utf8')
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
objects=[]
for name in ['probe','probe_core','kvm','vendor/qrcodegen']:
 obj=OUT/(Path(name).name+'.obj');objects.append(str(obj))
 subprocess.run([str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(SRC),'-I',str(SRC/'compat'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-DNDEBUG','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(SRC/(name+'.c')),'-o',str(obj)],check=True,env=env)
efi=OUT/'BOOTX64.EFI';subprocess.run([str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(OUT/'preflight.map'),'/out:'+str(efi)]+objects,check=True,env=env)
p=pefile.PE(str(efi));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();efi.write_bytes(p.write());assert not hasattr(p,'DIRECTORY_ENTRY_IMPORT')
boot=OUT/'eltorito.img';boot.write_bytes(b'');fat=PyFat();fat.mkfs(str(boot),fat_type=16,size=16*1024*1024,label='AITWK_P4');fat.close()
with PyFatFS(str(boot),utc=True) as fs:fs.makedirs('/EFI/BOOT',recreate=True);fs.writebytes('/EFI/BOOT/BOOTX64.EFI',efi.read_bytes())
iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='AITWK_P4_RO',joliet=3)
iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG');iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul',bootable=True)
target=OUT/'AiTweaker-P4-Preflight.iso';iso.write(str(target));iso.close()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
result={'purpose':'Read-only hardware preflight; no hooks or password changes','efi_sha256':sha(efi),'efi_bytes':efi.stat().st_size,'iso_sha256':sha(target),'iso_bytes':target.stat().st_size,'production_memory_walk_and_board_match_reused':True,'source_hashes':{p.relative_to(SRC).as_posix():sha(p) for p in SRC.rglob('*') if p.is_file()},'status':'BUILT_AWAITING_VM_VALIDATION'}
(OUT/'build.json').write_text(json.dumps(result,indent=2),encoding='utf8');print(json.dumps({k:v for k,v in result.items() if k!='source_hashes'},indent=2))

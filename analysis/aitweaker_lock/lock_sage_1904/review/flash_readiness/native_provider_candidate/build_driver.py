"""Build isolated optional static-gate provider; no CAP/FFS or hardware access."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=CASE.parents[2]
OUT=HERE/'build';SRC=HERE/'source';OUT.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
state=json.loads((OUT/'state_build.json').read_text());binding=json.loads((HERE/'guard_binding.json').read_text())
for name,digest in state['objects'].items():assert sha(OUT/name)==digest
for module in binding['modules'].values():assert sha(Path(module['module_file']))==module['module_sha256']
assert sha(SRC/'guard_binding.h')==binding['header_sha256']
objects=[OUT/name for name in ['provider.obj','password_core.obj','password_crypto.obj']];commands=[]
for name in ['services','owner','entry','ui','cpu_entropy','hii','policy']:
    obj=OUT/(name+'.obj');cmd=[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),
     '-I',str(SRC),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone',
     '-mno-stack-arg-probe','-fshort-wchar','-c',str(SRC/(name+'.c')),'-o',str(obj)]
    subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd);objects.append(obj)
efi=OUT/'AiTweakerNativeProvider1904.UNSIGNED.review.efi'
cmd=[str(ZIG),'lld-link','/subsystem:efi_boot_service_driver','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0',
 '/map:'+str(OUT/'provider.map'),'/out:'+str(efi)]+[str(o)for o in objects]
subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
p=pefile.PE(str(efi));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();efi.write_bytes(p.write())
assert not p.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size
for s in p.sections:assert not(s.Characteristics&0x20000000 and s.Characteristics&0x80000000)
report={'status':'BUILT_INTERNAL_UNSIGNED_PROVIDER_NOT_FIRMWARE_ACCEPTANCE','efi_sha256':sha(efi),'efi_bytes':efi.stat().st_size,
        'sources':{s.name:sha(s)for s in SRC.glob('*')if s.is_file()},'objects':{o.name:sha(o)for o in objects},
        'state_object_identical_to_native_tests':state['objects']['provider.obj']==sha(OUT/'provider.obj'),
        'guard_binding_sha256':sha(HERE/'guard_binding.json'),'commands':commands,
        'unresolved':['Actual modified OEM modules plus provider must be replayed together.','UI/HII/storage adapter fault matrix and standard UEFI load remain incomplete.',
                      'No whole-firmware container or physical cold-boot/flash/recovery acceptance.'],
        'hardware_access':False,'CAP_or_FFS_written':False}
(OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k]for k in ['status','efi_sha256','efi_bytes','state_object_identical_to_native_tests']}))

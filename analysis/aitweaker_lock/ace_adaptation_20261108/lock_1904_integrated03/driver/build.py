from pathlib import Path
import hashlib,json,os,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'tools/zig-x86_64-windows-0.14.1/zig.exe').is_file());OUT=HERE/'build';OUT.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
subprocess.run([sys.executable,str(HERE/'generate_policy.py')],check=True)
sources=[HERE/n for n in ('entry.c','services.c','cpu_entropy.c','ui.c','policy.c','hii.c','platform.c')]
sources += [HERE.parent/'core'/n for n in ('password_core.c','password_crypto.c')]
sources += [ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source/probe_core.c']
objects=[];commands=[]
for src in sources:
 obj=OUT/(src.stem+'.obj');objects.append(str(obj))
 cmd=[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-I',str(HERE),'-I',str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source'),'-std=c11','-O2' if src.name=='password_crypto.c' else '-Oz','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(src),'-o',str(obj)]
 subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
efi=OUT/'AiTweakerLock1904.efi'
cmd=[str(ZIG),'lld-link','/subsystem:efi_boot_service_driver','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(OUT/'driver.map'),'/out:'+str(efi)]+objects
subprocess.run(cmd,check=True,env=env);commands.append(cmd)
p=pefile.PE(str(efi));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();efi.write_bytes(p.write());p=pefile.PE(str(efi))
assert p.OPTIONAL_HEADER.Subsystem==11 and p.verify_checksum() and not hasattr(p,'DIRECTORY_ENTRY_IMPORT')
assert p.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size and not p.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
fingerprinted=sorted(set(p for p in sources if p.is_relative_to(HERE.parent))|set(HERE.glob('*.h'))|set((HERE.parent/'core').glob('*.h')))
result={'status':'BUILT_EXPERIMENTAL_NOT_FLASH_VALIDATED','revision':'ACE1904_INTEGRATED03','board':'Pro WS W790-ACE','bios':'1904','efi_bytes':efi.stat().st_size,'efi_sha256':hashlib.sha256(efi.read_bytes()).hexdigest(),'subsystem':11,'unsigned':True,'imports':False,'sources':{str(p.relative_to(HERE.parent)):hashlib.sha256(p.read_bytes()).hexdigest() for p in fingerprinted},'external_sources':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source').glob('probe_core.*') if p.suffix in {'.c','.h'}},'commands':commands}
(OUT/'build.json').write_text(json.dumps(result,indent=2),encoding='utf8')
print(json.dumps({k:result[k] for k in ['status','efi_bytes','efi_sha256','subsystem']}))

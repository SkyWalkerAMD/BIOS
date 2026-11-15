"""Compile only the independent read-only browser baseline; no packaging/device access."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;ROOT=next(p for p in HERE.parents if(p/'tools/pydeps').is_dir());SRC=HERE/'source';BUILD=HERE/'build';BUILD.mkdir(exist_ok=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(SRC/'management_package.h')==sha(D04/'provider13/source/management_package.h')
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(BUILD/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(BUILD/'zig-global'));(BUILD/'tmp').mkdir(exist_ok=True);env.update(TEMP=str(BUILD/'tmp'),TMP=str(BUILD/'tmp'))
names=['app.c','browser.c','inventory.c','sha256.c','transport/kvm.c','transport/probe_core.c','transport/vendor/qrcodegen.c','entry.S'];commands=[];objects=[]
for name in names:
 obj=BUILD/(Path(name).stem+'.obj');objects.append(obj)
 cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(SRC),'-I',str(SRC/'transport'),'-I',str(SRC/'transport/compat'),'-DNDEBUG','-std=c11','-O2','-Wall','-Wextra','-Werror','-Wno-unused-const-variable','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(SRC/name),'-o',str(obj)]
 subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
efi=BUILD/'SageNative13BrowserBaseline06.efi'
cmd=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(BUILD/'app.map'),'/out:'+str(efi),*map(str,objects)]
subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
p=pefile.PE(str(efi));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();efi.write_bytes(p.write());assert not p.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size
assert all((s.Characteristics&0xa0000000)!=0xa0000000 for s in p.sections)
r={'status':'COMPILED_BASELINE_PENDING_INDEPENDENT_TEST_REVIEW_NOT_RELEASE','efi_sha256':sha(efi),'efi_bytes':efi.stat().st_size,'image_bytes':p.OPTIONAL_HEADER.SizeOfImage,'sources':[{'path':str(p.relative_to(HERE)),'sha256':sha(p)}for p in SRC.rglob('*')if p.is_file()],'commands':commands,'objects':{p.name:sha(p)for p in objects},'scope':['Only one original SendForm call after explicit B key.','No native detours, P13 provider or credential implementation linked.','No direct variable, disk, flash or runtime-table write in app; standard volatile events/HII publication and native browser can have effects.','Unsupported OVMF must refuse production identity; separate UI fixture must be explicitly marked.']}
(BUILD/'build.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:r[k]for k in ['status','efi_sha256','efi_bytes','image_bytes']}))

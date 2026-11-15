"""Build resident RAM test app; all exact dependencies are local and frozen.
Packaging is separately owned by root in ram_test05_delivery.
"""
from pathlib import Path
import hashlib,json,os,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;ROOT=D04.parents[6];SRC=HERE/'source';BUILD=HERE/'app_build';BUILD.mkdir(exist_ok=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
frozen=json.loads((D04/'provider13/local_candidate_manifest.json').read_text())
for row in frozen['artifacts']:assert sha(D04/row['path'])==row['sha256']
assets=json.loads((HERE/'platform_assets.json').read_text())
for name,hash in assets['generated'].items():assert sha(SRC/name)==hash
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(BUILD/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(BUILD/'zig-global'))
(BUILD/'tmp').mkdir(exist_ok=True);env.update(TEMP=str(BUILD/'tmp'),TMP=str(BUILD/'tmp'))
names=['app.c','platform.c','transaction.c','session_ui.c','password_core.c','password_crypto.c','transport/kvm.c','transport/probe_core.c','transport/vendor/qrcodegen.c','entry.S']
if '--platform-only' in sys.argv:names=['platform.c']
commands=[];objects=[]
for name in names:
 obj=BUILD/(Path(name).stem+'.obj');objects.append(obj)
 cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(SRC),'-I',str(SRC/'transport'),'-I',str(SRC/'transport/compat'),'-DNDEBUG','-std=c11','-O2','-Wall','-Wextra','-Werror','-Wno-unused-const-variable','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(SRC/name),'-o',str(obj)]
 subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
if '--platform-only' in sys.argv:print('PLATFORM_OBJECT_COMPILED');sys.exit(0)
efi=BUILD/'SageNative13RamTest05.efi'
cmd=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(BUILD/'app.map'),'/out:'+str(efi),*map(str,objects)]
subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
p=pefile.PE(str(efi));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();efi.write_bytes(p.write());assert not p.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size
assert all((s.Characteristics&0xa0000000)!=0xa0000000 for s in p.sections)
r={'status':'COMPILED_RAM_TEST_APP_PENDING_EXACT_TESTS_REVIEW_NOT_RELEASE','efi_sha256':sha(efi),'efi_bytes':efi.stat().st_size,'image_bytes':p.OPTIONAL_HEADER.SizeOfImage,'sources':[{'path':str(p.relative_to(HERE)),'sha256':sha(p)}for p in SRC.rglob('*')if p.is_file()], 'commands':commands,'objects':{p.name:sha(p)for p in objects},'p13_manifest_sha256':sha(D04/'provider13/local_candidate_manifest.json'),'assets_sha256':sha(HERE/'platform_assets.json'),'scope':['Resident RAM-only original module detours; no BIOS image flashing.','Temporary private credential writes only in explicitly selected mode2; no OC variable setter in controller.','No foreign page-attribute changes; all own published resources remain until BMC power off.','Not ASUS native GUI or physical acceptance until exact artifact run/review.']}
(BUILD/'app_build.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:r[k]for k in ['status','efi_sha256','efi_bytes','image_bytes']}))

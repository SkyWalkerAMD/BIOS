"""Compile separate P13; no installer, firmware container or hardware access."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;N13=HERE.parent.parent;ROOT=N13.parents[5]
BUILD=HERE/'build';SRC=HERE/'source';BUILD.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(BUILD/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(BUILD/'zig-global'))
profile=json.loads((HERE/'split_profile.json').read_text());assert sha(SRC/'split_profile.h')==profile['profile_header_sha256']
assert sha(HERE.parent/'split_core/build/split_build.json')==profile['split_build_sha256']
copies=json.loads((HERE/'copied_p12_sources.json').read_text())
for name,digest in copies['files'].items():assert sha(SRC/name)==digest,name
objects=[];commands=[]
for name in ['provider','password_core','password_crypto','services','ui','cpu_entropy','owner','hii','entry']:
 obj=BUILD/(name+'.obj');cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(SRC),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(SRC/(name+'.c')),'-o',str(obj)]
 subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd);objects.append(obj)
efi=BUILD/'AiTweakerSplitProvider13.UNSIGNED.local.efi'
cmd=[str(zig),'lld-link','/subsystem:efi_boot_service_driver','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(BUILD/'provider.map'),'/out:'+str(efi)]+list(map(str,objects))
subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
p=pefile.PE(str(efi));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();efi.write_bytes(p.write());assert not p.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size
assert all(not(s.Characteristics&0x20000000 and s.Characteristics&0x80000000)for s in p.sections)
r={'status':'BUILT_P13_LOCAL_CANDIDATE_NOT_NATIVE_INSTALLER_OR_GUI_ACCEPTANCE','efi_sha256':sha(efi),'efi_bytes':efi.stat().st_size,'sources':{p.name:sha(p)for p in SRC.iterdir()if p.is_file()},'objects':{p.name:sha(p)for p in objects},'copied_p12_sources_identical':copies['files'],'profile_sha256':sha(HERE/'split_profile.json'),'management_package_sha256':sha(BUILD/'management.pack'),'commands':commands,'limits':['No installer/publication transaction yet; load requires validated exact96B split context and already installed12 gates.','Independent management formset has not yet been exercised in OEM GUI.','Real original module code and detached code identities are pinned, not weakened for bind.','No firmware integration or signature acceptance, no device operations.']}
(BUILD/'build.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'status':r['status'],'efi_sha256':r['efi_sha256'],'efi_bytes':r['efi_bytes']}))

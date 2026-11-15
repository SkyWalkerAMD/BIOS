"""Compile service-layer EBS fixture independently of in-progress navigation."""
from pathlib import Path
import difflib
import hashlib
import json
import os
import subprocess
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
CASE=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/zig-x86_64-windows-0.14.1/zig.exe').is_file())
DRIVER=CASE/'driver';OUT=HERE/'build';OUT.mkdir(exist_ok=True)
BASELINE=CASE.parent/'lock_1904_history02'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(BASELINE/'driver/build/AiTweakerLock1904.efi')=='598daaa53564f9b4610e300946fd588c2108a9842cb5f15cf67ee8e8d0a2fd84'
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(OUT/'.zig-global'),ZIG_LOCAL_CACHE_DIR=str(OUT/'.zig-local'),PYTHONDONTWRITEBYTECODE='1')
sources=[HERE/'fixture.c',DRIVER/'services.c',DRIVER/'cpu_entropy.c',CASE/'core/password_core.c',CASE/'core/password_crypto.c',ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source/probe_core.c']
objects=[];commands=[]
for source in sources:
 obj=OUT/(source.stem+'.obj');objects.append(obj)
 cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(DRIVER),'-I',str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source'),'-std=c11','-O2' if source.name=='password_crypto.c' else '-Oz','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(source),'-o',str(obj)]
 subprocess.run(cmd,check=True,env=env,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0));commands.append(cmd)
efi=OUT/'EBS-SERVICES-ONLY.EFI'
cmd=[str(zig),'lld-link','/subsystem:efi_application','/entry:test_entry','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/opt:noref','/timestamp:0','/map:'+str(OUT/'fixture.map'),'/out:'+str(efi)]+[str(p) for p in objects]
subprocess.run(cmd,check=True,env=env,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0));commands.append(cmd)
pe=pefile.PE(str(efi));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();efi.write_bytes(pe.write());pe.close()
inputs=sorted(set(sources)|set(DRIVER.glob('*.h'))|set((CASE/'core').glob('*.h'))|{ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source/probe_core.h'})
report={'scope':'EBS service machine code + explicit local browser-ownership stub; not production driver or hardware medium','efi_sha256':sha(efi),'services_obj_sha256':sha(OUT/'services.obj'),'sources':{str(p.relative_to(ROOT)):sha(p) for p in inputs},'objects':{p.name:sha(p) for p in objects},'commands':commands}
(OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
diff=''.join(difflib.unified_diff((BASELINE/'driver/services.c').read_text(encoding='utf8').splitlines(True),(DRIVER/'services.c').read_text(encoding='utf8').splitlines(True),fromfile='HISTORY02/driver/services.c',tofile='INTEGRATED04/driver/services.c'))
diff+=''.join(difflib.unified_diff((BASELINE/'driver/efi.h').read_text(encoding='utf8').splitlines(True),(DRIVER/'efi.h').read_text(encoding='utf8').splitlines(True),fromfile='HISTORY02/driver/efi.h',tofile='INTEGRATED04/driver/efi.h'))
(HERE/'services-and-efi.diff').write_text(diff,encoding='utf8')
print(json.dumps({'status':'BUILT_EBS_ONLY_FIXTURE','efi_sha256':report['efi_sha256'],'services_obj_sha256':report['services_obj_sha256']},indent=2))

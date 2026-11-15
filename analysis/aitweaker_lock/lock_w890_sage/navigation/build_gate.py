"""Build test-only freestanding x64 gate component; no EFI install entrypoint."""
from map_w890 import *
import os,subprocess
OUT=HERE/'build';OUT.mkdir(exist_ok=True)
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(OUT/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(OUT/'zig-global'))
sources=[HERE/'gate_adapter.c',HERE.parent/'password/w890_policy.c',HERE.parent/'password/core/password_crypto.c']
objects=[];commands=[]
for p in sources:
 obj=OUT/(p.stem+'.obj');cmd=[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-std=c11','-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-Wall','-Wextra','-Werror','-DAITWK_TEST_EXPORT','-c',str(p),'-o',str(obj)]
 subprocess.run(cmd,check=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW);objects.append(obj);commands.append(cmd)
out=OUT/'W890Navigation.TESTONLY.dll'
cmd=[str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/out:'+str(out),*[str(p)for p in objects]]
subprocess.run(cmd,check=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW);commands.append(cmd)
p=pefile.PE(str(out));assert not p.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size and not p.OPTIONAL_HEADER.AddressOfEntryPoint
result={'status':'COMPILED_NOT_INSTALLABLE','dll_sha256':sha(out.read_bytes()),'sources':{str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources+[HERE/'gate_adapter.h',HERE.parent/'password/w890_policy.h',HERE.parent/'password/w890_policy_data.h']},'commands':commands,'exports':{e.name.decode():e.address for e in p.DIRECTORY_ENTRY_EXPORT.symbols},'limitations':['Trusted native observer and lifecycle/provider binding are not implemented by this component.','No bootable entrypoint or hook installation; tests must not be interpreted as hardware acceptance.']}
(OUT/'build.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps({'status':result['status'],'sha256':result['dll_sha256'],'exports':{k:v for k,v in result['exports'].items()if k.startswith('wg_')}},indent=2))

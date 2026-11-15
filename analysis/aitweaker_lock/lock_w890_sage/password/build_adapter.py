"""Build pure policy and management backend objects; no bootable EFI produced."""
from pathlib import Path
import hashlib
import json
import os
import struct
import subprocess

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];OUT=HERE/'build'
OUT.mkdir(exist_ok=True)
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def build():
    env=os.environ.copy()
    env.update(ZIG_GLOBAL_CACHE_DIR=str(HERE/'.zig-global'),ZIG_LOCAL_CACHE_DIR=str(HERE/'.zig-local'))
    flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),
           '-std=c11','-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone',
           '-Wall','-Wextra','-Werror','-DAITWK_TEST_EXPORT']
    commands=[];objects=[]
    sources=[HERE/'w890_policy.c',HERE/'w890_management.c',HERE/'core/password_core.c',HERE/'core/password_crypto.c']
    for src in sources:
        obj=OUT/(src.stem+'.obj');cmd=[str(ZIG),'clang',*flags,'-c',str(src),'-o',str(obj)]
        subprocess.run(cmd,check=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
        objects.append(obj);commands.append(cmd)
    dll=OUT/'w890_password_pure_test.dll'
    cmd=[str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/out:'+str(dll),*[str(p)for p in objects]]
    subprocess.run(cmd,check=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW);commands.append(cmd)
    data=dll.read_bytes();pe=struct.unpack_from('<I',data,60)[0]
    assert data[pe:pe+4]==b'PE\0\0' and struct.unpack_from('<H',data,pe+24)[0]==0x20b
    assert struct.unpack_from('<II',data,pe+24+120)==(0,0)
    files=sources+[HERE/'w890_policy.h',HERE/'w890_policy_data.h',HERE/'w890_management.h',HERE/'core/password_core.h']
    result={'status':'COMPILED_PURE_X64_BACKEND_NO_EFI_ENTRYPOINT','sources':{str(p.relative_to(HERE)):sha(p)for p in files},
            'artifacts':{p.name:{'bytes':p.stat().st_size,'sha256':sha(p)}for p in objects+[dll]},
            'commands':commands,'compiler_sha256':sha(ZIG),'imports':False,'hardware_writes':0}
    (OUT/'adapter_build.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    return result
if __name__=='__main__':
    r=build();print(json.dumps({'status':r['status'],'dll':r['artifacts']['w890_password_pure_test.dll']}))

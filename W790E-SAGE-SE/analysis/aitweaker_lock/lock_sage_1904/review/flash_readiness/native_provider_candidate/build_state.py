"""Compile real provider/core machine code, with injectable I/O solely at ABI boundaries."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=CASE.parents[2]
OUT=HERE/'build';OUT.mkdir(exist_ok=True);SRC=HERE/'source'
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
commands=[];objects=[]
for name in ['provider','password_core','password_crypto']:
    obj=OUT/(name+'.obj')
    cmd=[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),
         '-I',str(SRC),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector',
         '-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(SRC/(name+'.c')),'-o',str(obj)]
    subprocess.run(cmd,env=env,check=True,cwd=ROOT);commands.append(cmd);objects.append(obj)
exports=['provider_initialize','provider_end_boot','provider_fault','provider_begin','provider_end','provider_query','provider_request','provider_manage',
         'platform_session_owned','platform_can_enter','native_provider','password_core','boot_services_ended',
         'ap_unlock','ap_set_password','ap_clear_password','ap_session_end','ap_can_enter','ap_record_valid','ap_pbkdf2_sha256']
cmd=[str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0',
     '/map:'+str(OUT/'provider_state.map'),'/out:'+str(OUT/'provider_state.dll')]+['/export:'+x for x in exports]+[str(x) for x in objects]
subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
report={'status':'COMPILED_STATE_CORE_NOT_HARDWARE_ACCEPTANCE','dll_sha256':sha(OUT/'provider_state.dll'),
 'objects':{p.name:sha(p)for p in objects},'sources':{(name+'.c'):sha(SRC/(name+'.c'))for name in ['provider','password_core','password_crypto']},
 'commands':commands,'scope':'Production state object compiled with actual password core/crypto. Environment hooks are injected by the host test, not a deployable driver yet.'}
(OUT/'state_build.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'dll_sha256':report['dll_sha256']}))

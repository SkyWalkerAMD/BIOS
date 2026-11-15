from pathlib import Path
import os,sys,subprocess,hashlib,json
H=Path(__file__).resolve().parent;R=H.parents[3];O=H/'build';O.mkdir(exist_ok=True)
Z=R/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(O/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(O/'zig-global'))
sources=[H/'observer.c',H/'provider_calls.S',H/'test_support.c',H.parent/'installer04/source/memory.c',H.parent/'password/w890_policy.c',H.parent/'password/core/password_crypto.c']
objects=[];cmds=[]
for p in sources:
    o=O/(p.stem+'.obj')
    cmd=[str(Z),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(Z.parent/'lib/include'),'-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-omit-frame-pointer','-mno-red-zone','-Wall','-Wextra','-Werror']
    cmd+=['-x','assembler','-Wno-unused-command-line-argument'] if p.suffix=='.S' else ['-std=c11']
    cmd+=['-c',str(p),'-o',str(o)]
    result=subprocess.run(cmd,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:print(result.stdout+result.stderr);raise SystemExit(result.returncode)
    objects.append(o);cmds.append(cmd)
exports=['no_initialize','no_prepare','no_identity','no_shutdown','no_end_boot','no_native_loop','no_native_send_form','no_native_entry','no_host','no_observe','no_publication_validate','no_publication_finished','no_restoration_finished','no_management_enter','no_management_valid','no_management_leave','no_scope_enter','no_scope_validate','no_scope_validate_cached','no_scope_leave','no_copy','no_read_variable','no_lease_begin','no_lease_validate_cached','no_lease_end','no_range']
cmd=[str(Z),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/base:0x180000000','/out:'+str(O/'W890NativeObserver04.TESTONLY.dll'),'/map:'+str(O/'observer.map'),*[str(o)for o in objects],*['/export:'+x for x in exports]]
result=subprocess.run(cmd,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
if result.returncode:print(result.stdout+result.stderr);raise SystemExit(result.returncode)
cmds.append(cmd)
report={'status':'COMPILED_DEFAULT_DENY_NO_INSTALLER','sha256':hashlib.sha256((O/'W890NativeObserver04.TESTONLY.dll').read_bytes()).hexdigest(),'sources':{str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sources+[H/'observer.h',H/'profile_windows.h']},'commands':cmds}
(O/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k!='commands'},indent=2))

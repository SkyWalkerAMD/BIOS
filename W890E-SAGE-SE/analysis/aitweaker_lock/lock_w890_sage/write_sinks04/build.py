from pathlib import Path
import os,sys,subprocess,hashlib,json
H=Path(__file__).resolve().parent;R=H.parents[3];O=H/'build';O.mkdir(exist_ok=True)
Z=R/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(O/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(O/'zig-global'))
common=[H/'policy04.c',H.parent/'password/w890_policy.c',H.parent/'password/core/password_crypto.c',H.parent/'native_observer04/test_support.c']
native=[H/'native_bridge04.c',H.parent/'native_observer04/observer.c',H.parent/'native_observer04/provider_calls.S',H.parent/'installer04/source/memory.c']
commands=[];objects={}
for p in common+native:
 o=O/(p.stem+'.obj');cmd=[str(Z),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(Z.parent/'lib/include'),'-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-omit-frame-pointer','-mno-red-zone','-Wall','-Wextra','-Werror']
 cmd+=['-x','assembler','-Wno-unused-command-line-argument'] if p.suffix=='.S' else ['-std=c11']
 cmd+=['-c',str(p),'-o',str(o)]
 v=subprocess.run(cmd,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW);commands.append(cmd)
 if v.returncode:print(v.stdout+v.stderr);raise SystemExit(v.returncode)
 objects[p]=o
policy=['ws04_preflight','ws04_known','ws04_descriptor','ws04_route_header','ws04_route_apply','ws04_intent_bytes']
bridge=['ws04_prepare','ws04_end_boot','ws04_check_commit','ws04_check_route','ws04_check_save','ws04_native_commit','ws04_setup_route','ws04_native_save','ws04_last_report']
products=[]
for label,src,exports in [('W890WritePolicy04.TESTONLY',common,policy),('W890WriteBridge04.DENYONLY',common+native,policy+bridge)]:
 out=O/(label+'.dll');cmd=[str(Z),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/base:0x180000000','/out:'+str(out),'/map:'+str(O/(label+'.map')),*[str(objects[p])for p in src],*['/export:'+x for x in exports]]
 v=subprocess.run(cmd,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW);commands.append(cmd)
 if v.returncode:print(v.stdout+v.stderr);raise SystemExit(v.returncode)
 products.append({'path':str(out.relative_to(H)),'bytes':out.stat().st_size,'sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'exports':exports})
bound=common+native+[H/'policy04.h',H/'native_bridge04.h',H/'catalog04.inc',H.parent/'native_observer04/observer.h',H.parent/'native_observer04/profile_windows.h',H.parent/'password/w890_policy_data.h']
report={'status':'COMPILED_REAL_OBSERVER_LINK_NO_NATIVE_WRITE_DISPATCH','products':products,'sources':{str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest()for p in bound},'commands':commands}
(O/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k!='commands'},indent=2))

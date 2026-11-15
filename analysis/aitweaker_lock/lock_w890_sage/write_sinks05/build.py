from pathlib import Path
import os,sys,subprocess,hashlib,json
H=Path(__file__).resolve().parent;R=H.parents[3];O=H/'build';O.mkdir(exist_ok=True)
Z=R/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(O/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(O/'zig-global'))
common=[H/'save_guard05.c',H/'save_thunk05.S',H.parent/'password/w890_policy.c',H.parent/'password/core/password_crypto.c',H.parent/'native_observer04/test_support.c']
native=[H.parent/'native_observer04/observer.c',H.parent/'native_observer04/provider_calls.S',H.parent/'installer04/source/memory.c',H.parent/'password/provider/provider.c',H.parent/'password/core/password_core.c',H.parent/'password/w890_management.c']
fixture=[H/'fixture05.c',H/'profile_gate_fixture.S'];commands=[];objects={}
for p in common+native+fixture:
 o=O/(p.stem+'.obj');cmd=[str(Z),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(Z.parent/'lib/include'),'-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-omit-frame-pointer','-mno-red-zone','-Wall','-Wextra','-Werror']
 cmd+=['-x','assembler','-Wno-unused-command-line-argument']if p.suffix=='.S' else ['-std=c11'];cmd+=['-c',str(p),'-o',str(o)]
 v=subprocess.run(cmd,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW);commands.append(cmd)
 if v.returncode:print(v.stdout+v.stderr);raise SystemExit(v.returncode)
 objects[p]=o
exports=['ws05_prepare','ws05_end_boot','ws05_before_save','ws05_before_protected_action','ws05_profile_callback_gate','ws05_last_report','ws05_save_mid_thunk','ws05_provider_request_call','ws05_provider_request_return','ws05_native_dispatch','ws05_native_defaults','ws05_native_load_defaults_save','ws05_native_profile','ws05_native_profile_policy']
products=[]
for label,src,ex in [('W890SaveGuard05.UNBOUND',common+native,exports),('W890SaveGuard05.MODEL',common+fixture,exports+['ws05_fixture_init','ws05_fixture_mode','ws05_fixture_requests','ws05_fixture_profile_call'])]:
 out=O/(label+'.dll');cmd=[str(Z),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/base:0x50000000','/out:'+str(out),'/map:'+str(O/(label+'.map')),*[str(objects[p])for p in src],*['/export:'+x for x in ex]]
 v=subprocess.run(cmd,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW);commands.append(cmd)
 if v.returncode:print(v.stdout+v.stderr);raise SystemExit(v.returncode)
 products.append({'path':str(out.relative_to(H)),'bytes':out.stat().st_size,'sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'exports':ex})
bound=common+native+fixture+[H/'save_guard05.h',H/'catalog05.inc',H.parent/'native_observer04/observer.h',H.parent/'native_observer04/profile_windows.h',H.parent/'password/w890_policy_data.h',H.parent/'password/provider/provider.h']
report={'status':'COMPILED_UNBOUND_CANDIDATE_NOT_DEPLOYABLE','products':products,'sources':{str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest()for p in bound},'commands':commands,'boundaries':['Model product replaces owner/services explicitly; real-observer product does not.','Both products use the same compiled save_guard05.obj and save_thunk05.obj.','Save gate candidate is unarmed: derived OC effects of notifications/defaults/imports not yet fully closed.','No firmware entry, CAP, installed hook or real variable write.']}
(O/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k not in ['commands','sources']},indent=2))

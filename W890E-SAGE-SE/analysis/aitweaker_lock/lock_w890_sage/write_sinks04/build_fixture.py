from pathlib import Path
import os,sys,subprocess,json,hashlib
H=Path(__file__).resolve().parent;R=H.parents[3];O=H/'build';Z=R/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(O/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(O/'zig-global'))
cmd=[str(Z),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(Z.parent/'lib/include'),'-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-Wall','-Wextra','-Werror','-std=c11','-c',str(H/'fixture.c'),'-o',str(O/'fixture.obj')]
p=subprocess.run(cmd,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
if p.returncode:print(p.stdout+p.stderr);raise SystemExit(p.returncode)
base=json.loads((O/'build.json').read_text());exports=base['products'][1]['exports'];out=O/'W890WriteBridge04.OBSERVER-FIXTURE.dll'
cmd2=[str(Z),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/base:0x180000000','/out:'+str(out),*[str(O/(s+'.obj'))for s in ['policy04','w890_policy','password_crypto','test_support','native_bridge04','fixture']],*['/export:'+x for x in exports]]
p=subprocess.run(cmd2,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
if p.returncode:print(p.stdout+p.stderr);raise SystemExit(p.returncode)
r={'status':'TEST_FIXTURE_OBSERVER_AND_GETVARIABLE_MODELED','sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'bytes':out.stat().st_size,'commands':[cmd,cmd2],'native_bridge_object_sha256':hashlib.sha256((O/'native_bridge04.obj').read_bytes()).hexdigest(),'note':'The exact same native_bridge04.obj is linked into production-deny and fixture products; authority and variables are modeled only in the fixture.'}
(O/'fixture_build.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items()if k!='commands'}))

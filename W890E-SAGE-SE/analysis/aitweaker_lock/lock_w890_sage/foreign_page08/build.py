from pathlib import Path
import os,subprocess,json,hashlib,sys
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3];O=H/'build';O.mkdir(exist_ok=True)
Z=R/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(O/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(O/'zig-global'))
src=[H/'foreign_page.c',H/'test_host.c',B/'password/w890_policy.c',B/'password/core/password_crypto.c'];objects=[];commands=[]
for p in src:
 obj=O/(p.stem+'.obj');cmd=[str(Z),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(Z.parent/'lib/include'),'-O2','-std=c11','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-mno-red-zone','-mno-stack-arg-probe','-c',str(p),'-o',str(obj)]
 commands.append(cmd);r=subprocess.run(cmd,env=env,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
 if r.returncode:print((r.stdout+r.stderr).decode('utf8','replace'));r.check_returncode()
 objects.append(obj)
dll=O/'W890ForeignPage08.TESTONLY.dll';exports=['fp08_describe_page','fp08_describe_control','fp08_view_bytes','fp08_test_bind','fp08_test_mode','fp08_test_exports','fp08_test_nested','fp08_test_identity_bytes']
cmd=[str(Z),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/dynamicbase','/timestamp:0','/out:'+str(dll),'/map:'+str(O/'foreign_page.map'),*[str(p)for p in objects],*['/export:'+x for x in exports]]
commands.append(cmd);r=subprocess.run(cmd,env=env,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
if r.returncode:print((r.stdout+r.stderr).decode('utf8','replace'));r.check_returncode()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
(O/'build.json').write_text(json.dumps({'status':'NATIVE_PE_WITH_EXPLICIT_TEST_HOST_NOT_FIRMWARE','component_sha256':sha(dll),
 'production_source':'foreign_page.c','test_only_source':'test_host.c','production_external_apis':['no_identity','no_native_visit_identity','no_range','no_catalog_generation'],
 'sources':{p.relative_to(R).as_posix():sha(p)for p in src+[H/'foreign_page.h',H/'scope_data.h',Path(__file__)]},'commands':commands},indent=2)+'\n')
print(sha(dll))

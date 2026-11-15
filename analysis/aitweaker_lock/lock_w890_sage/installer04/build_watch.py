from pathlib import Path
import hashlib,json,os,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];BASE=HERE.parent
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
out=HERE/'watch_build';out.mkdir(exist_ok=True)
profile=json.loads((BASE/'password/profile_0603.json').read_text());source=ROOT/profile['sources']['AMITSE']['path'];raw=source.read_bytes()
assert hashlib.sha256(raw).hexdigest()==profile['sources']['AMITSE']['sha256']
(out/'watch_fixture.h').write_text('static const uint8_t original_amitse_file[]={'+','.join(hex(x) for x in raw)+'};\n',encoding='ascii')
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(out/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(out/'zig-global'))
sources=[HERE/'source/memory.c',HERE/'source/cold_watch.c',BASE/'password/core/password_crypto.c'];objects=[];commands=[]
def compile(p,o,defs=[]):
 cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(out),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-omit-frame-pointer','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar',*defs,'-c',str(p),'-o',str(o)]
 r=subprocess.run(cmd,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW);commands.append(cmd)
 if r.returncode:print(r.stdout+r.stderr);r.check_returncode()
for p in sources:
 o=out/(p.stem+'.obj');compile(p,o);objects.append(o)
outputs={}
for preexist in [0,1,2,3]:
 # The reentry carrier adds only a labeled test-call shim; core logic is the
 # same source. Never embed this shim into a deployable driver.
 if preexist==2:
  extra=out/'cold_watch_reentry.obj';compile(HERE/'source/cold_watch.c',extra,['-DCW_LAB_REENTRY=1'])
  selected=[extra if x.name=='cold_watch.obj' else x for x in objects]
 else:selected=objects
 obj=out/f'lab_watch_{preexist}.obj';compile(HERE/'lab_watch.c',obj,[f'-DCW_PREEXIST={preexist}'])
 efi=out/f'W890-ColdWatch04-{preexist}.TCG-ONLY.efi'
 cmd=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/out:'+str(efi),*[str(p) for p in selected],str(obj)]
 r=subprocess.run(cmd,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW);commands.append(cmd)
 if r.returncode:print(r.stdout+r.stderr);r.check_returncode()
 pe=pefile.PE(str(efi));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();efi.write_bytes(pe.write())
 outputs[str(preexist)]={'path':str(efi),'sha256':hashlib.sha256(efi.read_bytes()).hexdigest(),'bytes':efi.stat().st_size}
inputs=sources+[HERE/'build_watch.py',HERE/'lab_watch.c',HERE/'source/cold_watch.h',HERE/'source/memory.h',BASE/'password_runtime02/source/efi.h',BASE/'password/core/password_core.h',source,out/'watch_fixture.h']
report={'status':'READ_ONLY_EARLY_LOADER_WATCHER_TCG_LAB','inputs':{str(p):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in inputs},'outputs':outputs,'commands':commands,'scope':'Actual UEFI loaded-image timing; no hook installer, original entry execution or physical cold-start proof.'}
(out/'build_manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(outputs))

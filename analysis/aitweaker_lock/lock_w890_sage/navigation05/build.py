from pathlib import Path
import os,sys,subprocess,json,hashlib,re
H=Path(__file__).resolve().parent;R=H.parents[3];B=H.parent;O=H/'build';O.mkdir(exist_ok=True)
sys.path.insert(0,str(R/'tools/pydeps'));import pefile,capstone
Z=R/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(O/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(O/'zig-global'))
src=[H/'navigation.c',H/'free_stubs.S',B/'native_observer04/observer.c',B/'native_observer04/provider_calls.S',B/'installer04/source/memory.c']
src +=[B/'password_runtime02/source'/(n+'.c')for n in ['services','ui','cpu_entropy','recovery']]
src +=[B/'password/provider/provider.c',B/'password/w890_policy.c',B/'password/w890_management.c',B/'password/core/password_core.c',B/'password/core/password_crypto.c']
objects=[];commands=[]
for i,p in enumerate(src):
 obj=O/(str(i)+'_'+p.stem+'.obj');cmd=[str(Z),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(Z.parent/'lib/include'),'-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-omit-frame-pointer','-mno-red-zone','-mno-stack-arg-probe','-Wall','-Wextra','-Werror']
 cmd+=['-x','assembler','-Wno-unused-command-line-argument']if p.suffix=='.S'else['-std=c11']
 cmd+=['-c',str(p),'-o',str(obj)];r=subprocess.run(cmd,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
 if r.returncode:print(r.stdout+r.stderr);raise SystemExit(r.returncode)
 objects.append(obj);commands.append(cmd)
old=pefile.PE(str(B/'native_observer04/build/W890NativeObserver04.TESTONLY.dll'))
exports=[x.name.decode()for x in old.DIRECTORY_ENTRY_EXPORT.symbols]+['n05_bind','n05_history_allocate','n05_history_reallocate','n05_forget_history','n05_fallback_main','n05_check','n05_first','n05_menu','n05_menu_free_stub','n05_loop_free_stub']
out=O/'W890Navigation05.TESTONLY.dll'
cmd=[str(Z),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/opt:noref','/base:0x180000000','/out:'+str(out),'/map:'+str(O/'navigation.map'),*[str(x)for x in objects],*['/export:'+x for x in exports]]
r=subprocess.run(cmd,capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
if r.returncode:print(r.stdout+r.stderr);raise SystemExit(r.returncode)
commands.append(cmd);p=pefile.PE(str(out));base=p.OPTIONAL_HEADER.ImageBase;im=p.get_memory_mapped_image();sy={n:int(a,16)for n,a in re.findall(r'^\s*\w+:\w+\s+(\w+)\s+([0-9a-fA-F]{16})\s',(O/'navigation.map').read_text(),re.M)}
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True;md.skipdata=True;calls=[]
for sec in p.sections:
 if sec.Name.rstrip(b'\0')!=b'.text':continue
 for x in md.disasm(im[sec.VirtualAddress:sec.VirtualAddress+sec.Misc_VirtualSize],base+sec.VirtualAddress):
  if x.mnemonic!='call':continue
  effect=x.bytes[0]==0xe8 and x.address+5+int.from_bytes(x.bytes[1:],'little',signed=True)==sy['no_scope_enter']
  request=any(o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP and x.address+x.size+o.mem.disp==sy['w890_provider']+40 for o in x.operands)
  if effect or request:
   ret=x.address+x.size;calls.append({'kind':1 if effect else 3,'return_rva':ret-base,'window':im[ret-base-16:ret-base+16].hex(),'purpose':'main fallback authority'if effect else'password request'})
assert len(calls)==2,calls
(O/'consumer_windows.json').write_text(json.dumps(calls,indent=2)+'\n')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
report={'status':'COMPILED_NO_INSTALLER','component_sha256':sha(out),'sources':{str(p.relative_to(R)):sha(p)for p in src+[H/'navigation.h']},'commands':commands,'consumer_windows':calls,'exports':{e.name.decode():e.address for e in p.DIRECTORY_ENTRY_EXPORT.symbols}}
(O/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'sha256':sha(out),'calls':calls},indent=2))

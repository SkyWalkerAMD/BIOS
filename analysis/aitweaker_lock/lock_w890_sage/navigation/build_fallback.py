from pathlib import Path
import hashlib,json,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];OUT=HERE/'build';OUT.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
source=HERE/'first_fallback.c';obj=OUT/'first_fallback.obj';asm=HERE/'first_entry_stub.S';asmobj=OUT/'first_entry_stub.obj';dll=OUT/'W890FirstFallback.TESTONLY.dll'
commands=[[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-std=c11','-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-Wall','-Wextra','-Werror','-DAITWK_TEST_EXPORT','-c',str(source),'-o',str(obj)],
 [str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-x','assembler','-c',str(asm),'-o',str(asmobj)],
 [str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/out:'+str(dll),'/export:wf_native_first_entry','/export:wf_binding_pointer,DATA','/export:wf_first_function,DATA','/export:wf_native_resume,DATA','/export:wf_fail_closed,DATA',str(obj),str(asmobj),str(OUT/'w890_policy.obj'),str(OUT/'password_crypto.obj')]]
for cmd in commands:subprocess.run(cmd,cwd=ROOT,check=True,capture_output=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=pefile.PE(str(dll));report={'status':'COMPILED_FIRST_ENTRY_FALLBACK_COMPONENT_NOT_INSTALLABLE','sha256':sha(dll),'exports':{e.name.decode():e.address for e in p.DIRECTORY_ENTRY_EXPORT.symbols},'commands':commands,'sources':{str(p.relative_to(ROOT)):sha(p)for p in [source,asm,HERE/'first_fallback.h',HERE/'gate_adapter.h',HERE.parent/'password/w890_policy.c',HERE.parent/'password/w890_policy.h']},'objects':{p.name:sha(p)for p in [obj,asmobj,OUT/'w890_policy.obj',OUT/'password_crypto.obj']},'limits':['External identity/session/HII/UEFI-range callbacks require real native binding.','No hook installer. Unsupported first-entry recovery states return WF_CANNOT_RECOVER; caller must not resume the protected page.','Mid-function stub has no safe failure UI bound; its zero fail-closed continuation traps intentionally. This is not hardware installable.','Main fallback requires a unique Setup Main root and zero history pointer/used/root. No forced exit, reset or save path.']}
(OUT/'fallback_build.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':report['status'],'sha256':report['sha256']}))

"""Compile the unchanged patch source and original encoder to a native test DLL."""
from pathlib import Path
import os,sys,json,hashlib,subprocess
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(OUT/'zig-cache-global');env['ZIG_LOCAL_CACHE_DIR']=str(OUT/'zig-cache-local')
flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-I',str(OUT/'source/compat'),'-DNDEBUG','-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections']
commands=[];objects=[]
for name in ('kvm','memory','vendor/qrcodegen'):
 obj=OUT/(Path(name).name+'.obj');objects.append(str(obj))
 commands.append([str(ZIG),'clang',*flags,'-c',str(OUT/'source'/(name+'.c')),'-o',str(obj)])
commands.append([str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/export:kvm_present','/export:kvm_make_frame','/export:kvm_encode_frame','/export:probe_crc32','/export:qrcodegen_getSize','/export:qrcodegen_getModule','/out:'+str(OUT/'kvm_test.dll'),*objects])
for cmd in commands:subprocess.run(cmd,check=True,cwd=OUT,env=env)
analyzer=subprocess.run([str(ZIG),'clang',*flags,'--analyze','-Xanalyzer','-analyzer-output=text',str(OUT/'source/kvm.c')],check=True,capture_output=True,text=True,cwd=OUT,env=env)
assert not analyzer.stdout and not analyzer.stderr,analyzer.stdout+analyzer.stderr
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
report=dict(commands=commands,dll_sha256=sha(OUT/'kvm_test.dll'),kvm_static_analysis='no diagnostics',sources={p.relative_to(OUT/'source').as_posix():sha(p) for p in (OUT/'source').rglob('*') if p.is_file()})
(OUT/'build-test.json').write_text(json.dumps(report,indent=2)+'\n')
print('Built',report['dll_sha256'])

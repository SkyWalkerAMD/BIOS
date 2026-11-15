from pathlib import Path
import os,subprocess,hashlib,json,sys
P=Path(__file__).resolve().parent;ROOT=P.parents[2];SRC=ROOT/'analysis/hero_inventory_collect_20261108/source'
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(P/'zig-global');env['ZIG_LOCAL_CACHE_DIR']=str(P/'zig-local')
flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-I',str(SRC),'-DNDEBUG','-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections']
commands=[]
for name,path in [('dxe_state_probe',P/'dxe_state_probe.c'),('common',SRC/'common.c')]:
 c=[str(ZIG),'clang',*flags,'-c',str(path),'-o',str(P/(name+'.obj'))];subprocess.run(c,check=True,env=env);commands.append(c)
c=[str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/timestamp:0','/export:dxe_state_probe','/export:dx_state_snapshot','/export:dx_range','/out:'+str(P/'dxe_state_probe_test.dll'),str(P/'dxe_state_probe.obj'),str(P/'common.obj')]
subprocess.run(c,check=True,env=env);commands.append(c)
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
pe=pefile.PE(str(P/'dxe_state_probe_test.dll'));assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
(P/'probe-build.json').write_text(json.dumps(dict(commands=commands,inputs={str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in [P/'dxe_state_probe.c',P/'dxe_state_probe.h',P/'dxe_core_anchors.h',SRC/'efi_min.h',SRC/'common.c']}),indent=2)+'\n')
print('compiled, no imports')

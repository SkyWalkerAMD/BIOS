"""Only build the local diagnostic codec DLL; no firmware/device artifact yet."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];SRC=HERE/'source';OUT=HERE/'build';H6=HERE.parent/'diagnostic_hii06'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 SRC.mkdir(exist_ok=True);OUT.mkdir(exist_ok=True)
 frozen=json.loads((H6/'component_manifest.json').read_text());assert sha(H6/'component_manifest.json')=='0af72ade1c3e0b8dfa1350216cf5db37dbd4935e86f1aa005e85558657dcfe97'
 for record in frozen['files']:assert sha(ROOT/record['path'])==record['sha256']
 inputs=[]
 for name in ('delta_core.c','delta_core.h'):shutil.copyfile(HERE/name,SRC/name)
 for name in ('password_crypto.c','password_core.h','probe_core.c','probe_core.h'):
  p=H6/'source'/name;shutil.copyfile(p,SRC/name);inputs.append({'path':str(p),'sha256':sha(p)})
 zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-global');env['ZIG_LOCAL_CACHE_DIR']=str(HERE/'zig-cache')
 common=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(SRC),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-DD7_EXPORT'];commands=[];objects=[]
 for name in ('delta_core','password_crypto','probe_core'):
  obj=OUT/(name+'.obj');cmd=common+['-c',str(SRC/(name+'.c')),'-o',str(obj)];subprocess.run(cmd,check=True,env=env);commands.append(cmd);objects.append(str(obj))
 dll=OUT/'delta_core_test.dll';cmd=[str(zig),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/out:'+str(dll)]+objects;subprocess.run(cmd,check=True,env=env);commands.append(cmd)
 report={'status':'LOCAL_CODEC_COMPONENT','dll_sha256':sha(dll),'inputs':inputs,'sources':{p.name:sha(p) for p in SRC.iterdir() if p.is_file()},'commands':commands};(OUT/'core_build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'dll_sha256':report['dll_sha256']},indent=2))
if __name__=='__main__':main()

"""Build a local diagnostic component; never creates a bootable carrier."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];H6=HERE.parent/'diagnostic_hii06';SRC=HERE/'source';OUT=HERE/'build'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 SRC.mkdir(exist_ok=True);OUT.mkdir(exist_ok=True)
 manifest=H6/'component_manifest.json'
 assert sha(manifest)=='0af72ade1c3e0b8dfa1350216cf5db37dbd4935e86f1aa005e85558657dcfe97'
 for x in json.loads(manifest.read_text())['files']:assert sha(ROOT/x['path'])==x['sha256']
 inputs=[]
 for name in ('sampler.c','sampler.h'):shutil.copyfile(HERE/name,SRC/name)
 for name in ('core.c','core.h','known_profiles.h','password_core.h','password_crypto.c'):
  p=H6/'source'/name;shutil.copyfile(p,SRC/name);inputs.append({'path':str(p),'sha256':sha(p)})
 zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-global');env['ZIG_LOCAL_CACHE_DIR']=str(HERE/'zig-cache')
 common=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(SRC),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-DS7_EXPORT']
 commands=[];objects=[]
 for name in ('sampler','core','password_crypto'):
  obj=OUT/(name+'.obj');cmd=common+['-c',str(SRC/(name+'.c')),'-o',str(obj)];subprocess.run(cmd,check=True,env=env);commands.append(cmd);objects.append(str(obj))
 dll=OUT/'spf_sampler_test.dll';cmd=[str(zig),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/out:'+str(dll)]+objects
 subprocess.run(cmd,check=True,env=env);commands.append(cmd)
 report={'status':'LOCAL_READ_ONLY_COMPONENT_NO_EFI_CARRIER','dll_sha256':sha(dll),'inputs':inputs,'sources':{p.name:sha(p) for p in SRC.iterdir() if p.is_file()},'commands':commands}
 (OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'dll_sha256':report['dll_sha256']},indent=2))
if __name__=='__main__':main()

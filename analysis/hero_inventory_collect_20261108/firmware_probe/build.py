"""Build identity probe object plus host-test DLL; no installed firmware changes."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
HERE=Path(__file__).resolve().parent;COL=HERE.parent;ROOT=COL.parents[1]
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(HERE/'zig-global');env['ZIG_LOCAL_CACHE_DIR']=str(HERE/'zig-local')
 flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-I',str(COL/'source'),'-I',str(COL/'source/compat'),'-DNDEBUG','-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections']
 commands=[]
 for name,path in [('firmware_probe',HERE/'firmware_probe.c'),('common',COL/'source/common.c'),('kvm',COL/'source/kvm.c'),('qrcodegen',COL/'source/vendor/qrcodegen.c')]:
  cmd=[str(ZIG),'clang',*flags,'-c',str(path),'-o',str(HERE/(name+'.obj'))]
  subprocess.run(cmd,check=True,cwd=ROOT,env=env);commands.append(cmd)
 cmd=[str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/timestamp:0','/export:firmware_probe','/export:fp_path_targets','/export:fp_range_readable','/out:'+str(HERE/'firmware_probe_test.dll')]+[str(HERE/(n+'.obj')) for n in ['firmware_probe','common','kvm','qrcodegen']]
 subprocess.run(cmd,check=True,cwd=ROOT,env=env);commands.append(cmd)
 pe=pefile.PE(str(HERE/'firmware_probe_test.dll'));assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
 refs={str(p.relative_to(ROOT)):sha(p) for p in (HERE/'reference').glob('*.h')}
 for p in [ROOT/'analysis/hero_ipmi_r2/reference/edk2/LoadedImage.h',ROOT/'analysis/hero_ipmi_r2/reference/edk2/UefiSpec.h',COL/'source/efi_min.h',COL/'source/collector.h',COL/'source/common.c']:
  refs[str(p.relative_to(ROOT))]=sha(p)
 report={'scope':'Offline object and host DLL build; no device operations','commands':commands,'source_sha256':{p.name:sha(p) for p in [HERE/'firmware_probe.c',HERE/'firmware_probe.h']},'dll_sha256':sha(HERE/'firmware_probe_test.dll'),'references':refs}
 (HERE/'build.json').write_text(json.dumps(report,indent=2)+'\n');print('Firmware probe compiled, no imports.')
if __name__=='__main__':main()

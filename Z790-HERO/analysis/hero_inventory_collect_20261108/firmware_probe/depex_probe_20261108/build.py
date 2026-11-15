from pathlib import Path
import hashlib,json,os,subprocess,sys
P=Path(__file__).resolve().parent;ROOT=P.parents[3];HOST=ROOT/'analysis/hero_inventory_publish_i3a_20261108/source'
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(P/'zig-global');env['ZIG_LOCAL_CACHE_DIR']=str(P/'zig-local')
 commands=[
  [str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-I',str(HOST),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections','-c',str(P/'depex_probe.c'),'-o',str(P/'depex_probe.obj')],
  [str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/timestamp:0','/export:depex_probe','/out:'+str(P/'depex_probe_test.dll'),str(P/'depex_probe.obj')]]
 for cmd in commands:subprocess.run(cmd,check=True,env=env,cwd=ROOT)
 pe=pefile.PE(str(P/'depex_probe_test.dll'));assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
 report={'commands':commands,'sources':{n:sha(P/n) for n in ['depex_probe.c','depex_probe.h']},'efi_min_sha256':sha(HOST/'efi_min.h'),'dll_sha256':sha(P/'depex_probe_test.dll'),'scope':'Offline compile; only source and output in this standalone module directory.'}
 (P/'build.json').write_text(json.dumps(report,indent=2)+'\n');print('Standalone DEPEX probe compiled, no imports.')
if __name__=='__main__':main()

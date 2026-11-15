from pathlib import Path
import os,subprocess,json,hashlib,sys
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(OUT/'zig-global');env['ZIG_LOCAL_CACHE_DIR']=str(OUT/'zig-local')
flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-ffunction-sections','-fdata-sections','-fstack-usage']
cmds=[[str(ZIG),'clang',*flags,'-c',str(OUT/'source/hero_pcie_catalog.c'),'-o',str(OUT/'hero_pcie_catalog.obj')],
 [str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/map:'+str(OUT/'catalog.map'),'/out:'+str(OUT/'catalog.dll'),str(OUT/'hero_pcie_catalog.obj')]+['/export:'+s for s in ('HeroPcieCatalogBuild','HeroPcieCrc32','HeroPcieCatalogSize','HeroPcieScratchSize','HeroPcieRecordSize')]]
for cmd in cmds:subprocess.run(cmd,check=True,env=env,cwd=OUT)
p=pefile.PE(str(OUT/'catalog.dll'));assert not hasattr(p,'DIRECTORY_ENTRY_IMPORT')
manifest={'dll_sha256':hashlib.sha256((OUT/'catalog.dll').read_bytes()).hexdigest(),'no_imports':True,'commands':cmds,'sources':{x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in (OUT/'source').glob('*')}}
(OUT/'build.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps({k:v for k,v in manifest.items() if k!='commands'},indent=2))

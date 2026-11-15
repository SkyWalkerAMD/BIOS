from pathlib import Path
import hashlib,json,os,subprocess
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[2]
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(BASE/'build/zig-global'),ZIG_LOCAL_CACHE_DIR=str(BASE/'build/zig-local'))
flags=[zig,'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',zig.parent/'lib/include','-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone']
for inc in ('analysis/hero_inventory_i5_20261108/capture_fix/source','analysis/hero_pcie_catalog_20261108/source','analysis/hero_pcie_catalog_20261108/sata/source','analysis/hero_hardware_source_20261108/source'):flags+=['-I',ROOT/inc]
objects=[]
for name in ('publish','plan'):
 obj=BASE/'build'/(name+'.obj');cmd=flags+['-c',BASE/'source'/('hero_inventory_'+name+'.c'),'-o',obj];subprocess.run([str(x) for x in cmd],check=True,env=env);objects.append(obj)
cmd=[zig,'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/timestamp:0','/out:'+str(BASE/'build/publish.dll'),*objects]
cmd+=['/export:'+s for s in ('HeroInventoryPublishContextSize','HeroInventoryPublishInit','HeroInventoryPublishState','HeroInventoryPublishNext','HeroInventoryPublishAccept','HeroInventoryPublishAuthorize','HeroInventoryPlanBuild')]
subprocess.run([str(x) for x in cmd],check=True,env=env)
print(json.dumps({'dll_sha256':hashlib.sha256((BASE/'build/publish.dll').read_bytes()).hexdigest(),'bytes':(BASE/'build/publish.dll').stat().st_size}))

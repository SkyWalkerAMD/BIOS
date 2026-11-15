"""Build only the EBS candidate, replacing services.obj; EXP02 remains intact."""
from pathlib import Path
import difflib,hashlib,json,os,subprocess,sys
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=CASE.parents[2]
DRIVER=CASE/'driver';OUT=HERE/'build';OUT.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
baseline='da52a08f0e477867f4f08e3d1514b156be1ac67fa3bc9c47d09272a869aaf2e2'
assert sha(DRIVER/'build/AiTweakerLock1904.efi')==baseline
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
cmd=[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-I',str(DRIVER),'-I',str(CASE.parent/'probe_p3_kvm/source'),'-std=c11','-Oz','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(HERE/'services.c'),'-o',str(OUT/'services.obj')]
subprocess.run(cmd,check=True,env=env,cwd=ROOT)
objects=[(OUT if n=='services' else DRIVER/'build')/(n+'.obj') for n in ['entry','services','cpu_entropy','ui','policy','hii','platform','password_core','password_crypto','probe_core']]
efi=OUT/'AiTweakerLock1904.efi'
link=[str(ZIG),'lld-link','/subsystem:efi_boot_service_driver','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(OUT/'driver.map'),'/out:'+str(efi)]+[str(p) for p in objects]
subprocess.run(link,check=True,env=env)
p=pefile.PE(str(efi));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();efi.write_bytes(p.write())
diff=''.join(difflib.unified_diff((DRIVER/'services.c').read_text().splitlines(True),(HERE/'services.c').read_text().splitlines(True),fromfile='driver/services.c',tofile='ebs_candidate/services.c'))
(HERE/'services.patch').write_text(diff,encoding='utf8')
report={'status':'LOCAL_CANDIDATE_NOT_DEPLOYED','baseline_driver_sha256':baseline,'candidate_driver_sha256':sha(efi),'candidate_source_sha256':sha(HERE/'services.c'),'object_sha256':{str(p.relative_to(CASE)):sha(p) for p in objects},'commands':[cmd,link]}
(OUT/'build.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps({k:report[k] for k in ['status','baseline_driver_sha256','candidate_driver_sha256','candidate_source_sha256']},indent=2))

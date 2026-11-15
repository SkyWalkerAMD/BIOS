"""Build a local candidate by replacing only platform.obj in the pinned driver.

No existing driver source, binary, CAP, ISO, or production report is modified.
"""
from pathlib import Path
import difflib,hashlib,json,os,subprocess,sys
HERE=Path(__file__).resolve().parent
CASE=HERE.parent.parent
ROOT=CASE.parents[2]
DRIVER=CASE/'driver'
OUT=HERE/'build';OUT.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
SHA='61e01e74c1605121aab4573707e870ae6ecc2d3c5a198b09e4ea4886ce9b6f26'
assert hashlib.sha256((DRIVER/'build/AiTweakerLock1904.efi').read_bytes()).hexdigest()==SHA
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
cmd=[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-I',str(DRIVER),'-I',str(CASE.parent/'probe_p3_kvm/source'),'-std=c11','-Oz','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(HERE/'platform.c'),'-o',str(OUT/'platform.obj')]
subprocess.run(cmd,check=True,env=env,cwd=ROOT)
objects=[(OUT if n=='platform' else DRIVER/'build')/(n+'.obj') for n in ['entry','services','cpu_entropy','ui','policy','hii','platform','password_core','password_crypto','probe_core']]
efi=OUT/'AiTweakerLock1904.efi'
link=[str(ZIG),'lld-link','/subsystem:efi_boot_service_driver','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(OUT/'driver.map'),'/out:'+str(efi)]+[str(p) for p in objects]
subprocess.run(link,check=True,env=env)
p=pefile.PE(str(efi));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();efi.write_bytes(p.write())
diff=''.join(difflib.unified_diff((DRIVER/'platform.c').read_text().splitlines(True),(HERE/'platform.c').read_text().splitlines(True),fromfile='driver/platform.c',tofile='history_candidate/platform.c'))
(HERE/'platform.patch').write_text(diff,encoding='utf8')
report={'status':'CANDIDATE_BUILT_NOT_DEPLOYED','original_driver_sha256':SHA,'candidate_driver_sha256':hashlib.sha256(efi.read_bytes()).hexdigest(),'candidate_platform_sha256':hashlib.sha256((HERE/'platform.c').read_bytes()).hexdigest(),'object_sha256':{str(p.relative_to(CASE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in objects},'commands':[cmd,link]}
(OUT/'build.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps({k:report[k] for k in ['status','original_driver_sha256','candidate_driver_sha256','candidate_platform_sha256']},indent=2))

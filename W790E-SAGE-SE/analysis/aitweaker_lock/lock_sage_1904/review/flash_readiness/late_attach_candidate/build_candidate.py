"""Link isolated late-attach/session-owner changes with the preserved EBS fix."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=CASE.parents[2]
DRIVER=CASE/'driver';OUT=HERE/'build';OUT.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
baseline='da52a08f0e477867f4f08e3d1514b156be1ac67fa3bc9c47d09272a869aaf2e2'
ebs='93237af8b9b59437f0135524d8283c4685f6f454e3050c0ed6dc5a6495387c80'
assert sha(DRIVER/'build/AiTweakerLock1904.efi')==baseline
assert sha(HERE.parent/'ebs_candidate/build/AiTweakerLock1904.efi')==ebs
manifest=json.loads((HERE/'source_manifest.json').read_text(encoding='utf8'))
assert all(sha(CASE/p)==h for p,h in manifest['baseline_sources'].items())
assert all(sha(HERE/p)==h for p,h in manifest['candidate_sources'].items())
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
commands=[];changed=['platform','hii','ui','services']
for name in changed:
    cmd=[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-I',str(HERE),'-I',str(DRIVER),'-I',str(CASE.parent/'probe_p3_kvm/source'),'-std=c11','-Oz','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(HERE/(name+'.c')),'-o',str(OUT/(name+'.obj'))]
    subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
objects=[(OUT if n in changed else DRIVER/'build')/(n+'.obj') for n in ['entry','services','cpu_entropy','ui','policy','hii','platform','password_core','password_crypto','probe_core']]
efi=OUT/'AiTweakerLock1904.efi'
link=[str(ZIG),'lld-link','/subsystem:efi_boot_service_driver','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(OUT/'driver.map'),'/out:'+str(efi)]+[str(p) for p in objects]
subprocess.run(link,check=True,env=env);commands.append(link)
p=pefile.PE(str(efi));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();efi.write_bytes(p.write())
report={'status':'LOCAL_CANDIDATE_NOT_DEPLOYED','baseline_driver_sha256':baseline,'ebs_candidate_driver_sha256':ebs,'candidate_driver_sha256':sha(efi),'candidate_source_sha256':sha(HERE/'services.c'),'candidate_sources':manifest['candidate_sources'],'object_sha256':{str(p.relative_to(CASE)):sha(p) for p in objects},'commands':commands,'hardware_acceptance_inherited':False,'ebs_cleanup_source_unchanged':True}
(OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({k:report[k] for k in ['status','candidate_driver_sha256','candidate_sources']},indent=2))

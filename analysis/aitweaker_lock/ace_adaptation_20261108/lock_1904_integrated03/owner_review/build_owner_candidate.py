"""Freeze and build a local owner-review candidate, never execute EFI on host."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess,sys

HERE=Path(__file__).resolve().parent
CASE=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/zig-x86_64-windows-0.14.1/zig.exe').is_file())
BASE=CASE.parent/'lock_1904_history02'
SNAP=HERE/'snapshot';OUT=HERE/'build'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile

def main():
 OUT.mkdir(parents=True,exist_ok=True)
 if not (HERE/'source_snapshot.json').exists():
  files=[]
  for sub,names in [('driver',['entry.c','services.c','cpu_entropy.c','ui.c','policy.c','hii.c','platform.c','efi.h','lock.h','status.h','policy_data.h','policy.json']),('core',['password_core.c','password_crypto.c','password_core.h'])]:
   for name in names:
    # Entry scheduling is being changed independently by the parent. Freeze the
    # previous entry here; owner tests attach directly and do not validate it.
    source=(BASE if name in {'entry.c','policy.json'} else CASE)/sub/name
    target=SNAP/sub/name;target.parent.mkdir(parents=True,exist_ok=True)
    before=sha(source);shutil.copyfile(source,target);assert sha(source)==sha(target)==before
    files.append({'source':str(source.relative_to(ROOT)),'snapshot':str(target.relative_to(HERE)),'sha256':before})
  (HERE/'source_snapshot.json').write_text(json.dumps({'scope':'Owner-only candidate; previous entry.c; contemporaneous stable EBS service interface; not the final integrated build.','files':files},indent=2)+'\n')
 for item in json.loads((HERE/'source_snapshot.json').read_text())['files']:
  assert sha(HERE/item['snapshot'])==item['sha256']
 zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
 env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(HERE/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(HERE/'zig-local'))
 sources=[SNAP/'driver'/n for n in ['entry.c','services.c','cpu_entropy.c','ui.c','policy.c','hii.c','platform.c']]
 sources += [SNAP/'core'/n for n in ['password_core.c','password_crypto.c']]
 sources += [ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source/probe_core.c']
 commands=[];objects=[]
 for source in sources:
  obj=OUT/(source.stem+'.obj');objects.append(str(obj))
  cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(SNAP/'driver'),'-I',str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source'),'-std=c11','-O2' if source.name=='password_crypto.c' else '-Oz','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(source),'-o',str(obj)]
  subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
 output=OUT/'AiTweakerLock1904.efi'
 cmd=[str(zig),'lld-link','/subsystem:efi_boot_service_driver','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(OUT/'driver.map'),'/out:'+str(output),*objects]
 subprocess.run(cmd,check=True,env=env);commands.append(cmd)
 p=pefile.PE(str(output));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();output.write_bytes(p.write())
 p=pefile.PE(str(output));assert p.verify_checksum() and p.OPTIONAL_HEADER.Subsystem==11 and not hasattr(p,'DIRECTORY_ENTRY_IMPORT')
 result={'status':'BUILT_ISOLATED_OWNER_REVIEW_NOT_HARDWARE_TESTED','efi_sha256':sha(output),'bytes':output.stat().st_size,'source_snapshot_sha256':sha(HERE/'source_snapshot.json'),'sources':{str(p.relative_to(SNAP)):sha(p) for p in SNAP.rglob('*') if p.is_file()},'commands':commands}
 (OUT/'build.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({k:result[k] for k in ['status','efi_sha256','bytes']}))

if __name__=='__main__':main()

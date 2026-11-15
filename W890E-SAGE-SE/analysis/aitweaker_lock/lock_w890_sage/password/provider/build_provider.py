"""Link actual EFI component bytes. Entry deliberately refuses installation."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;PASSWORD=HERE.parent;ROOT=PASSWORD.parents[3]
OUT=HERE/'build';OUT.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(OUT/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(OUT/'zig-global'))
sources=[HERE/'provider.c',HERE/'entry.c',PASSWORD/'w890_policy.c',PASSWORD/'w890_management.c',PASSWORD/'core/password_core.c',PASSWORD/'core/password_crypto.c']
commands=[];objects=[]
for src in sources:
    obj=OUT/(src.stem+'.obj');objects.append(obj)
    cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),
         '-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector',
         '-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(src),'-o',str(obj)]
    subprocess.run(cmd,check=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW);commands.append(cmd)
exports=['w890_provider_initialize','w890_provider_fault','w890_provider_end_boot','w890_session_owned','w890_session_can_enter',
         'w890_provider_begin','w890_provider_end','w890_provider_query','w890_provider_request','w890_provider_manage',
         'w890_config_callback','w890_management_action','w890_profile_matches','w890_classify_form','w890_classify_control',
         'w890_security_insert','ap_session_begin','ap_session_end','ap_record_valid']
efi=OUT/'W890PasswordProvider01.UNBOUND.TESTONLY.efi'
cmd=[str(zig),'lld-link','/subsystem:efi_boot_service_driver','/entry:efi_main','/nodefaultlib','/machine:x64',
     '/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/opt:noref','/map:'+str(OUT/'provider.map'),'/out:'+str(efi),
     *['/export:'+s for s in exports],'/export:w890_provider,DATA','/export:w890_password_core,DATA','/export:w890_management_config,DATA',*[str(p)for p in objects]]
subprocess.run(cmd,check=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW);commands.append(cmd)
p=pefile.PE(str(efi));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();efi.write_bytes(p.write());p=pefile.PE(str(efi))
assert p.OPTIONAL_HEADER.Subsystem==11 and p.verify_checksum() and p.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
assert not p.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size and not p.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
assert all(not(s.Characteristics&0x20000000 and s.Characteristics&0x80000000)for s in p.sections)
symbols={s.name.decode():s.address for s in p.DIRECTORY_ENTRY_EXPORT.symbols}
headers=[HERE/'provider.h',PASSWORD/'w890_policy.h',PASSWORD/'w890_policy_data.h',PASSWORD/'w890_management.h',PASSWORD/'core/password_core.h']
r={'status':'LINKED_UNBOUND_EFI_COMPONENT_ENTRY_RETURNS_UNSUPPORTED','file':efi.name,'bytes':efi.stat().st_size,'sha256':sha(efi),
   'image_base':hex(p.OPTIONAL_HEADER.ImageBase),'entry_rva':p.OPTIONAL_HEADER.AddressOfEntryPoint,'symbols':symbols,
   'sources':{str(s.relative_to(PASSWORD)):sha(s)for s in sources+headers},'objects':{s.name:sha(s)for s in objects},
   'commands':commands,'signatures':False,'imports':False,'native_binding_complete':False,'hardware_installable':False,
   'limits':['Entry unconditionally returns EFI_UNSUPPORTED, calls no hardware or EFI services, and publishes nothing.',
             'W890 native owner, UI prompt, NVRAM adapter, initial-page gate and HII publication are required external integration.',
             'Host callback simulations establish component behavior only, not ownership of real native frames.',
             'No password hardware writes or firmware flashing performed.']}
(OUT/'build.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8');print(json.dumps({k:r[k]for k in ['status','bytes','sha256']}))

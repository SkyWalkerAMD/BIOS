from pathlib import Path
import hashlib,json,os,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];P=HERE.parent/'password';S=HERE/'source';OUT=HERE/'build';OUT.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(OUT/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(OUT/'zig-global'))
sources=[S/(n+'.c')for n in ['services','ui','cpu_entropy','recovery']]+[P/'provider/provider.c',P/'w890_policy.c',P/'w890_management.c',P/'core/password_core.c',P/'core/password_crypto.c']
commands=[];objects=[]
def compile(src,obj):
    cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(S),
         '-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar',
         '-c',str(src),'-o',str(obj)]
    run=subprocess.run(cmd,env=env,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
    if run.returncode:
        (OUT/(src.stem+'.compile-error.txt')).write_bytes(run.stdout+run.stderr)
        print((run.stdout+run.stderr).decode('utf8','replace'));run.check_returncode()
    commands.append(cmd)
def link(entry,efi,subsystem,exports=[]):
    obj=OUT/(entry.stem+'.obj');compile(entry,obj)
    cmd=[str(zig),'lld-link','/subsystem:'+subsystem,'/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/opt:noref',
         '/map:'+str(efi.with_suffix('.map')),'/out:'+str(efi),*['/export:'+x for x in exports],*[str(p)for p in objects],str(obj)]
    subprocess.run(cmd,check=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW);commands.append(cmd)
    pe=pefile.PE(str(efi));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();efi.write_bytes(pe.write());pe=pefile.PE(str(efi))
    assert pe.verify_checksum() and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
    assert all(not(s.Characteristics&0x20000000 and s.Characteristics&0x80000000)for s in pe.sections)
    return {'bytes':efi.stat().st_size,'sha256':sha(efi),'entry_rva':pe.OPTIONAL_HEADER.AddressOfEntryPoint,'image_base':hex(pe.OPTIONAL_HEADER.ImageBase),
            'symbols':{x.name.decode():x.address for x in pe.DIRECTORY_ENTRY_EXPORT.symbols}if hasattr(pe,'DIRECTORY_ENTRY_EXPORT')else{}}
for src in sources:
    obj=OUT/(src.stem+'.obj');compile(src,obj);objects.append(obj)
exports=['w890_runtime_bind','w890_runtime_end_boot','w890_runtime_alive','w890_read_record','w890_persist_record','w890_entropy','w890_now_ms','w890_console_prompt',
         'w890_recover_known_record','w890_provider_begin','w890_provider_end','w890_provider_query','w890_provider_request','w890_provider_manage','w890_provider_fault',
         'w890_provider,DATA','w890_password_core,DATA','w890_system_table,DATA','w890_runtime_ended,DATA','w890_credential_name,DATA','w890_credential_guid,DATA']
component=OUT/'W890Runtime02.UNBOUND.TESTONLY.efi';components=link(S/'entry.c',component,'efi_boot_service_driver',exports)
report={'status':'RUNTIME_COMPONENT_LINKED_ENTRY_CLOSED','component':components,'component_file':component.name,
        'sources':{str(p.relative_to(ROOT)):sha(p)for p in sources+[S/'runtime.h',S/'efi.h',S/'entry.c']},
        'shared_objects':{p.name:sha(p)for p in objects},'commands':commands,'physical_hardware_writes':0,'native_owner_bound':False}
if (HERE/'lab/lab_fixture.c').exists():
    lab=OUT/'W890Runtime02.QEMU_ONLY.LAB.efi';report['lab']=link(HERE/'lab/lab_fixture.c',lab,'efi_application');report['lab_file']=lab.name
    report['lab_source_sha256']=sha(HERE/'lab/lab_fixture.c')
report['commands']=commands
(OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k in ['status','component','lab']}))

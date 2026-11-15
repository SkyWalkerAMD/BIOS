from pathlib import Path
import hashlib,json,os,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;BASE=HERE.parent;ROOT=HERE.parents[3];P=BASE/'password';R=BASE/'password_runtime02';OUT=HERE/'build';OUT.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(OUT/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(OUT/'zig-global'))
sources=[HERE/(n+'.c')for n in ['identity','package','publisher','bridge']]+[R/'source'/(n+'.c')for n in ['services','ui','cpu_entropy','recovery']]+[P/'provider/provider.c',P/'w890_policy.c',P/'w890_management.c',P/'core/password_core.c',P/'core/password_crypto.c']
commands=[];objects=[]
def compile(src,obj):
    cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(HERE/'lab'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(src),'-o',str(obj)]
    commands.append(cmd);result=subprocess.run(cmd,env=env,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:print((result.stdout+result.stderr).decode('utf8','replace'));result.check_returncode()
def link(entry,efi,subsystem,exports=[]):
    obj=OUT/(entry.stem+'.obj');compile(entry,obj)
    cmd=[str(zig),'lld-link','/subsystem:'+subsystem,'/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/opt:noref','/map:'+str(efi.with_suffix('.map')),'/out:'+str(efi),*['/export:'+x for x in exports],*[str(p)for p in objects],str(obj)]
    commands.append(cmd);subprocess.run(cmd,check=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
    pe=pefile.PE(str(efi));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();efi.write_bytes(pe.write());pe=pefile.PE(str(efi))
    assert pe.verify_checksum() and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
    return {'bytes':efi.stat().st_size,'sha256':sha(efi),'entry_rva':pe.OPTIONAL_HEADER.AddressOfEntryPoint,'image_base':hex(pe.OPTIONAL_HEADER.ImageBase),'symbols':{x.name.decode():x.address for x in pe.DIRECTORY_ENTRY_EXPORT.symbols}if hasattr(pe,'DIRECTORY_ENTRY_EXPORT')else{}}
def main():
    for i,src in enumerate(sources):
        obj=OUT/(str(i)+'_'+src.stem+'.obj');compile(src,obj);objects.append(obj)
    exports=['mp_bind','mp_publish','mp_native_publish','mp_rollback','mp_dispose','mp_end_boot','mp_callback','mp_management_scope','mp_provider_caller','mp_current,DATA','w890_runtime_bind','w890_runtime_end_boot','w890_provider_begin','w890_provider_end','w890_provider_query','w890_provider_request','w890_provider_manage','w890_provider,DATA','w890_management_config,DATA','w890_config_callback','w890_system_table,DATA','w890_runtime_ended,DATA','w890_password_core,DATA']
    report={'status':'LINKED_UNBOUND_CLOSED_ENTRY','component':link(HERE/'entry.c',OUT/'W890Management04.UNBOUND.TESTONLY.efi','efi_boot_service_driver',exports),'sources':{str(p.relative_to(ROOT)):sha(p)for p in sources+[HERE/'management.h',HERE/'internal.h',HERE/'entry.c']}}
    if (HERE/'lab/lab.c').exists():report['lab']=link(HERE/'lab/lab.c',OUT/'W890Management04.QEMU_ONLY.LAB.efi','efi_application')
    report['commands']=commands;(OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k in ['status','component','lab']}))
if __name__=='__main__':main()

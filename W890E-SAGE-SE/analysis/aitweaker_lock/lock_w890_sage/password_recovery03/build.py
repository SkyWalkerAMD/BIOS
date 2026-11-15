from pathlib import Path
import hashlib,importlib.util,json,os,subprocess,sys,struct
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];S=HERE/'source';OUT=HERE/'build';LAB=HERE/'lab'
OUT.mkdir(exist_ok=True);LAB.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
environment=os.environ.copy();environment.update(ZIG_LOCAL_CACHE_DIR=str(OUT/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(OUT/'zig-global'))
commands=[]
def compile(source,obj):
    cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(S),
         '-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(source),'-o',str(obj)]
    p=subprocess.run(cmd,env=environment,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW);commands.append(cmd)
    if p.returncode:(OUT/(source.stem+'.error.txt')).write_bytes(p.stdout+p.stderr);print(p.stderr.decode('utf8','replace'));p.check_returncode()
def link(entry,file,exports=[]):
    obj=OUT/(entry.stem+'.obj');compile(entry,obj)
    cmd=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/opt:noref',
         '/map:'+str(file.with_suffix('.map')),'/out:'+str(file),*['/export:'+x for x in exports],*[str(x)for x in objects],str(obj)]
    subprocess.run(cmd,env=environment,check=True,creationflags=subprocess.CREATE_NO_WINDOW);commands.append(cmd)
    pe=pefile.PE(str(file));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();file.write_bytes(pe.write());pe=pefile.PE(str(file))
    assert pe.verify_checksum()and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
    assert all(not(s.Characteristics&0x20000000 and s.Characteristics&0x80000000)for s in pe.sections)
    return {'file':file.name,'bytes':file.stat().st_size,'sha256':sha(file),'entry_rva':pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'symbols':{x.name.decode():x.address for x in pe.DIRECTORY_ENTRY_EXPORT.symbols}if hasattr(pe,'DIRECTORY_ENTRY_EXPORT')else{}}
sources=[S/(n+'.c')for n in ['services','identity','ui','password_core','password_crypto']];objects=[]
for source in sources:
    obj=OUT/(source.stem+'.obj');compile(source,obj);objects.append(obj)
exports=['rc_initialize','rc_shutdown','rc_hold_resident','rc_alive','rc_identity','rc_authorized','rc_delete_known','rc_read','rc_ui_attempt','rc_parse_smbios','rc_module_matches',
         'rc_st,DATA','rc_ended,DATA','rc_guid,DATA','rc_name,DATA']
component=link(S/'entry.c',OUT/'W890Recovery03.IDENTITY_READONLY.efi',exports)
profile=json.loads((HERE.parent/'password/profile_0603.json').read_text());module_rows=[];parts=['/* Test-only loaded-image fixtures. Original code is hashed, never executed. */']
def array(name,data):return 'static const uint8_t '+name+'['+str(len(data))+']={'+','.join(str(x)for x in data)+'};\n'
for index,name in enumerate(['Setup','AMITSE']):
    item=profile['sources'][name];source=ROOT/item['path'];assert sha(source)==item['sha256']
    pe=pefile.PE(str(source));text=next(x for x in pe.sections if x.Name.rstrip(b'\0')==b'.text');mapped=pe.get_memory_mapped_image()
    parts.append(array('fixture_header_'+str(index),mapped[:4096]));parts.append(array('fixture_text_'+str(index),mapped[text.VirtualAddress:text.VirtualAddress+text.Misc_VirtualSize]))
    module_rows.append({'source':item['path'],'original_sha256':item['sha256'],'text_sha256':hashlib.sha256(mapped[text.VirtualAddress:text.VirtualAddress+text.Misc_VirtualSize]).hexdigest()})
(LAB/'module_data.inc').write_text('\n'.join(parts),encoding='ascii')
journal_source=HERE.parent/'password_runtime02/journal/durable_fixture.py'
spec=importlib.util.spec_from_file_location('durable_fixture',journal_source);journal=importlib.util.module_from_spec(spec);spec.loader.exec_module(journal)
journal_path=LAB/'handoff-fixture.dpapi';target='QEMU-W890-RECOVERY03-ISOLATED'
if not journal_path.exists():journal.prepare(journal_path,target)
fixture=journal.open_fixture(journal_path,target)
salt=hashlib.sha256(b'PUBLIC-RECOVERY03-LAB-SALT').digest()
prefix=struct.pack('<8sHHIIIQ',b'AITWKP01',1,128,1,1,600000,1)
record=prefix+salt+hashlib.pbkdf2_hmac('sha256',fixture['before'].encode(),salt,600000,32);record+=hashlib.sha256(record).digest()
(LAB/'credential_data.inc').write_text('/* Test verifier only. No plaintext password. */\n'+array('fixture_record',record),encoding='ascii')
report={'status':'RECOVERY_CARRIER_READONLY_UNPROVEN_ORIGINAL_BOOT','component':component,'release_ready':False,
        'physical_operations':0,'sources':{str(p.relative_to(HERE)):sha(p)for p in sources+[S/'entry.c']+list(S.glob('*.h'))+list(S.glob('*.inc'))},
        'module_source_binding':module_rows,'runtime02_manifest_sha256':sha(HERE.parent/'password_runtime02/component_manifest.json')}
if (LAB/'lab.c').exists():report['lab']=link(LAB/'lab.c',OUT/'W890Recovery03.QEMU_ONLY.LAB.efi');report['lab_sources']={str(p.relative_to(HERE)):sha(p)for p in LAB.glob('*')if p.suffix in ['.c','.inc']}
report['journal_source_sha256']=sha(journal_source);report['fixture_ciphertext_sha256']=sha(journal_path);report['commands']=commands
(OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k]for k in ['status','component','lab']if k in report}))

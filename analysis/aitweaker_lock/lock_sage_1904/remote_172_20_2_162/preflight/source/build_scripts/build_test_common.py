"""Local-only source/object binding and ISO construction for SAGE maintenance probes."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess,sys,zipfile
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
DRIVER=HERE.parent/'driver'
BASE=HERE.parents[1]
PIN='61e01e74c1605121aab4573707e870ae6ecc2d3c5a198b09e4ea4886ce9b6f26'
for n in ['pydeps','vm-pydeps','kvm-pydeps']:sys.path.insert(0,str(ROOT/'tools'/n))
import pefile,pycdlib
from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
ENV=os.environ.copy();ENV.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
OBJECTS=['entry','services','cpu_entropy','ui','policy','hii','platform','password_core','password_crypto','probe_core']
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(p,o):Path(p).write_text(json.dumps(o,indent=2)+'\n',encoding='utf8')
def copy(src,dst):dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst)
def compile(file,obj,includes,commands):
    cmd=[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include')]
    for inc in includes:cmd+=['-I',str(inc)]
    cmd+=['-std=c11','-O2','-Wall','-Wextra','-Werror','-DNDEBUG','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(file),'-o',str(obj)]
    subprocess.run(cmd,check=True,env=ENV);commands.append(cmd)
def link(objects,efi,mapfile,commands,subsystem='efi_application'):
    cmd=[str(ZIG),'lld-link','/subsystem:'+subsystem,'/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(mapfile),'/out:'+str(efi)]+list(map(str,objects))
    subprocess.run(cmd,check=True,env=ENV);commands.append(cmd)
    p=pefile.PE(str(efi));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();efi.write_bytes(p.write());p=pefile.PE(str(efi))
    assert p.verify_checksum() and not hasattr(p,'DIRECTORY_ENTRY_IMPORT') and p.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
def snapshot(out):
    src=out/'source';src.mkdir(parents=True,exist_ok=True)
    build=json.loads((DRIVER/'build/build.json').read_text(encoding='utf8'))
    assert build['board']=='Pro WS W790E-SAGE SE' and build['efi_sha256']==sha(DRIVER/'build/AiTweakerLock1904.efi')==PIN
    for name,digest in build['sources'].items():
        path=HERE.parent/name;assert sha(path)==digest,name;copy(path,src/'production'/name)
    for name,digest in build['external_sources'].items():assert sha(ROOT/name)==digest,name
    p3=BASE/'probe_p3_kvm/source'
    for p in p3.rglob('*'):
        if p.is_file():copy(p,src/'p3'/p.relative_to(p3))
    copied=out/'production_objects';copied.mkdir(exist_ok=True)
    for name in OBJECTS:copy(DRIVER/'build'/(name+'.obj'),copied/(name+'.obj'))
    commands=[]
    relinked=out/'production-relinked.efi'
    link([copied/(name+'.obj') for name in OBJECTS],relinked,out/'production-relinked.map',commands,'efi_boot_service_driver')
    assert sha(relinked)==PIN,'Copied production objects must reconstruct the exact tested driver'
    copy(DRIVER/'build/build.json',out/'production-build.json')
    binding={'production_driver_sha256':PIN,'production_build_sha256':sha(DRIVER/'build/build.json'),'production_relinked_sha256':sha(relinked),'production_objects':{name:sha(copied/(name+'.obj')) for name in OBJECTS},'production_source_hashes':build['sources'],'external_source_hashes':build['external_sources'],'source_archival_scope':'Copied production C/header source and complete P3 transport source; linked production objects copied separately. Reconstructed DXE matches pinned production EFI exactly.'}
    return src,copied,commands,binding
def iso(efi,out,name,label):
    boot=out/'eltorito.img';boot.write_bytes(b'');fat=PyFat();fat.mkfs(str(boot),fat_type=16,size=16*1024*1024,label=label);fat.close()
    with PyFatFS(str(boot),utc=True) as fs:fs.makedirs('/EFI/BOOT',recreate=True);fs.writebytes('/EFI/BOOT/BOOTX64.EFI',efi.read_bytes())
    target=out/name;disc=pycdlib.PyCdlib();disc.new(interchange_level=3,vol_ident=label,joliet=3)
    disc.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG');disc.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul',bootable=True)
    disc.write(str(target));disc.close();return target
def finish(out,src,efi,target,result,commands,script):
    for p in [Path(__file__),script]:copy(p,src/'build_scripts'/p.name)
    result.update(efi_sha256=sha(efi),efi_bytes=efi.stat().st_size,iso_sha256=sha(target),iso_bytes=target.stat().st_size,source_hashes={p.relative_to(src).as_posix():sha(p) for p in src.rglob('*') if p.is_file()},commands=commands,status='BUILT_AWAITING_VM_VALIDATION')
    archive=out/'source-snapshot.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for p in src.rglob('*'):
            if p.is_file():z.write(p,p.relative_to(src).as_posix())
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        assert all(hashlib.sha256(z.read(name)).hexdigest()==digest for name,digest in result['source_hashes'].items())
    result['source_archive_sha256']=sha(archive)
    save(out/'build.json',result)
    print(json.dumps({k:v for k,v in result.items() if k not in ('source_hashes','commands','production_source_hashes','external_source_hashes','production_objects')},indent=2))

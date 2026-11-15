"""Local test ISOs only. Production CAP02 source/EFI/ISO are read, not changed."""
from pathlib import Path
import hashlib,json,os,subprocess,sys,warnings
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir());F=HERE/'test_only_fixtures';OUT=F/'build';OUT.mkdir(exist_ok=True)
for n in ['pydeps','vm-pydeps','kvm-pydeps']:sys.path.insert(0,str(ROOT/'tools'/n))
warnings.filterwarnings('ignore',message='pkg_resources is deprecated.*')
import pefile,pycdlib
from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
data=(HERE/'build/BOOTX64.EFI').read_bytes()
(F/'candidate_blob.h').write_text('static const unsigned char candidate_blob[]={\n'+','.join(str(x) for x in data)+'\n};\n',encoding='ascii')
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
rows=[]
for mode,name in [(0,'success'),(1,'timeout')]:
    obj=OUT/(name+'.obj');efi=OUT/(name+'.EFI');boot=OUT/(name+'.img');iso_path=OUT/('TEST-ONLY-SYNTHETIC-'+name+'.iso')
    cc=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(HERE/'source'),'-I',str(HERE/'source/p3'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-DFIXTURE_MODE='+str(mode),'-c',str(F/'provider.c'),'-o',str(obj)]
    subprocess.run(cc,check=True,env=env)
    link=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/out:'+str(efi),str(obj)]
    subprocess.run(link,check=True,env=env);pe=pefile.PE(str(efi));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();efi.write_bytes(pe.write())
    assert data in efi.read_bytes()
    boot.write_bytes(b'');fat=PyFat();fat.mkfs(str(boot),fat_type=16,size=16*1024*1024,label='TESTONLY');fat.close()
    with PyFatFS(str(boot),utc=True) as fs:fs.makedirs('/EFI/BOOT',recreate=True);fs.writebytes('/EFI/BOOT/BOOTX64.EFI',efi.read_bytes())
    iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='TEST_ONLY',joliet=3);iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG');iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul',bootable=True);iso.write(str(iso_path));iso.close()
    rows.append({'case':name,'efi_sha256':sha(efi),'iso_sha256':sha(iso_path),'embedded_candidate_sha256':hashlib.sha256(data).hexdigest(),'synthetic_provider':True,'commands':[cc,link]})
report={'status':'BUILT_LOCAL_TEST_ONLY','not_for_hardware_use':True,'production_efi_unchanged':sha(HERE/'build/BOOTX64.EFI')==hashlib.sha256(data).hexdigest(),'cases':rows}
(F/'build.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps({'built_test_only_fixtures':len(rows)}))

"""Build the host-interface network probe; do not touch any CAP."""
from pathlib import Path
import hashlib, io, json, os, subprocess, sys
OUT=Path(__file__).resolve().parent; ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
for name in ('tools/pydeps','tools/kvm-pydeps','tools/vm-pydeps','analysis/aitweaker_lock/uefi_vm_20261015'):
    sys.path.insert(0,str(ROOT/name))
import pefile, pycdlib, disk_images
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(OUT/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(OUT/'zig-local'))
flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(OUT/'source/compat'),'-DNDEBUG','-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections']
commands=[]
for name in ('common','crc','app','network','tcp','tls_client','gzip','publish','loader','kvm','vendor/qrcodegen'):
    cmd=[str(zig),'clang',*flags,'-c',str(OUT/'source'/f'{name}.c'),'-o',str(OUT/(Path(name).name+'.obj'))]
    subprocess.run(cmd,env=env,cwd=ROOT,check=True);commands.append(cmd)
artifacts={}
for name,subsystem,objects in [('BOOTX64.EFI','efi_application',('common','crc','app','network','tcp','tls_client','gzip','publish','loader','kvm','qrcodegen'))]:
    p=OUT/'USB/EFI/BOOT'/name;p.parent.mkdir(parents=True,exist_ok=True)
    cmd=[str(zig),'lld-link','/subsystem:'+subsystem,'/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/opt:ref','/opt:noicf','/timestamp:0','/map:'+str(OUT/(name+'.map')),'/out:'+str(p),*[str(OUT/(s+'.obj')) for s in objects]]
    subprocess.run(cmd,check=True,env=env);commands.append(cmd)
    pe=pefile.PE(str(p));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();p.write_bytes(pe.write());pe=pefile.PE(str(p))
    assert pe.verify_checksum() and pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==(10 if name.startswith('BOOT') else 11)
    assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
    artifacts[name]={'sha256':sha(p),'bytes':p.stat().st_size,'subsystem':pe.OPTIONAL_HEADER.Subsystem}
for driver in json.loads((OUT/'staged-drivers/manifest.json').read_text()):
    source=OUT/'staged-drivers'/driver['name'];assert sha(source)==driver['sha256']
    target=OUT/'USB/EFI/BOOT'/driver['name'];target.write_bytes(source.read_bytes())
    artifacts[driver['name']]={k:driver[k] for k in ('bytes','sha256','patches')}
(OUT/'USB/HERO_R8.TAG').write_bytes(b'HERO-REMOTE-R8\n')
files={'/'+p.relative_to(OUT/'USB').as_posix():p.read_bytes() for p in (OUT/'USB').rglob('*') if p.is_file()}
disk_images.OUT=OUT;disk_images.VOLUME_SIZE=8*1024*1024;boot=OUT/'efi-boot.img';disk_images.create(boot,layout='superfloppy',fat_type=16,files=files)
iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='HERO_REMOTE_R8')
iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1');iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',platform_id=0xef,efi=True,media_name='noemul')
iso.add_directory('/EFI');iso.add_directory('/EFI/BOOT')
for name,data in files.items():iso.add_fp(io.BytesIO(data),len(data),iso_path=name.upper()+';1')
output=OUT/'HERO-REMOTE-BIOS-R8.iso';iso.write(str(output));iso.close()
iso=pycdlib.PyCdlib();iso.open(str(output));assert iso.eltorito_boot_catalog.validation_entry.platform_id==0xef
for name,data in files.items():
    fp=io.BytesIO();iso.get_file_from_iso_fp(fp,iso_path=name.upper()+';1');assert fp.getvalue()==data
iso.close()
with disk_images.PyFatFS(str(boot),read_only=True) as fs:
    for name,data in files.items():assert fs.readbytes(name)==data
report={'version':'R8c','mode':'R8c: explicit RAM USB drivers and pinned internal TLS; publish three observed HERO3107 current settings, read-only registry and native AMI layout to BMC only when current BIOS is missing; owned R8b layout update with current/registry/layout preflight; no UEFI settings write or pending queue read','target':'HERO 3107, verified 046B:FFB0 USB control/data pair, physical SNP path only; no persistent IP configuration','artifacts':artifacts,'iso_sha256':sha(output),'iso_bytes':output.stat().st_size,'sources':{p.relative_to(OUT/'source').as_posix():sha(p) for p in (OUT/'source').rglob('*') if p.is_file()},'commands':commands}
(OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ('sources','commands')},indent=2))

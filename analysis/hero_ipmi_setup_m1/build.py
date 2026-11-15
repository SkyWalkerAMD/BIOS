"""Build reviewable USB HII driver and DXE FFS. Never runs hardware code."""
from pathlib import Path
import hashlib,json,os,struct,subprocess,sys,uuid
from generate_forms import generate,DRIVER
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def section(kind,data):return (len(data)+4).to_bytes(3,'little')+bytes([kind])+data
def build():
    generate();(OUT/'USB/EFI/BOOT').mkdir(parents=True,exist_ok=True);(OUT/'USB/EFI/HERO').mkdir(parents=True,exist_ok=True)
    env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-global');env['ZIG_LOCAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-local')
    commands=[]
    for name in ('common','probe_core','engine','driver','launcher'):
        cmd=[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections','-c',str(OUT/'source'/f'{name}.c'),'-o',str(OUT/f'{name}.obj')]
        subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
    outputs=[]
    for name,subsystem,parts,path in [('driver','efi_boot_service_driver',['driver','engine','common','probe_core'],OUT/'USB/EFI/HERO/HeroIpmiM1.efi'),('launcher','efi_application',['launcher','common'],OUT/'USB/EFI/BOOT/BOOTX64.EFI')]:
        cmd=[str(ZIG),'lld-link','/subsystem:'+subsystem,'/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/opt:ref','/opt:noicf','/timestamp:0','/map:'+str(OUT/f'{name}.map'),'/out:'+str(path)]+[str(OUT/f'{p}.obj') for p in parts]
        subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
        pe=pefile.PE(str(path));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();path.write_bytes(pe.write());pe=pefile.PE(str(path))
        assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==(11 if name=='driver' else 10)
        assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size==0 and pe.verify_checksum()
        assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size or name=='launcher' # launcher is entirely RIP-relative
        outputs.append(dict(path=str(path.relative_to(OUT)),bytes=path.stat().st_size,sha256=sha(path),subsystem=pe.OPTIONAL_HEADER.Subsystem))
    # Standard PCI enumeration complete, HII services, writable variables.
    deps=['30cfe3e7-3de1-4586-be20-deaba1b3b793','ef9fc172-a1b2-4693-b327-6d32fc416042','0fd96974-23aa-4cdc-b9cb-98d17750322a','587e72d7-cc50-4f79-8209-ca291fc1a10f','6441f818-6362-4e44-b570-7dba31dd2453']
    depex=b''
    for i,guid in enumerate(deps):depex+=b'\x02'+uuid.UUID(guid).bytes_le+(b'\x03' if i else b'')
    depex+=b'\x08';data=b''
    for kind,body in [(0x13,depex),(0x10,(OUT/'USB/EFI/HERO/HeroIpmiM1.efi').read_bytes()),(0x15,'HeroIpmiSetupM1\0'.encode('utf-16-le'))]:
        data+=section(kind,body);data+=bytes((-len(data))%4)
    hdr=bytearray(uuid.UUID(DRIVER).bytes_le+b'\0\xaa\x07\x00'+(24+len(data)).to_bytes(3,'little')+b'\xf8')
    hdr[16]=(-sum(hdr[:16]+b'\0\0'+hdr[18:23]+b'\0'))&255
    ffs=OUT/'HeroIpmiSetupM1.ffs';ffs.write_bytes(hdr+data)
    marker=b'HERO-IPMI-SETUP-M1\r\n';assert len(marker)==20
    (OUT/'USB/HERO-IPMI-M1.TAG').write_bytes(marker)
    report=dict(version='M1',target='ROG MAXIMUS Z790 HERO BIOS 3107 / exact observed 1.3.13 Device ID',default_auto_init=False,ffs_guid=DRIVER,depex=deps,outputs=outputs,ffs_sha256=sha(ffs),commands=commands,sources={str(p.relative_to(OUT)):sha(p) for p in sorted((OUT/'source').glob('*')) if p.is_file()},status='BUILT; see verification.json and vm/results.json for actual evidence')
    (OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(outputs,indent=2))
if __name__=='__main__':build()

"""Build the USB-only M1a diagnostic. Does not produce a flashable capsule."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
from generate_forms import generate
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def build():
    generate()
    for p in ('USB/EFI/BOOT','USB/EFI/HERO'):(OUT/p).mkdir(parents=True,exist_ok=True)
    env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-global');env['ZIG_LOCAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-local')
    commands=[]
    for name in ('common','probe_core','engine','trace','driver','launcher'):
        cmd=[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections','-c',str(OUT/'source'/f'{name}.c'),'-o',str(OUT/f'{name}.obj')]
        subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
    outputs=[]
    for name,subsystem,parts,path in [('driver','efi_boot_service_driver',['driver','engine','common','probe_core','trace'],OUT/'USB/EFI/HERO/HeroIpmiM1a.efi'),('launcher','efi_application',['launcher','common'],OUT/'USB/EFI/BOOT/BOOTX64.EFI')]:
        cmd=[str(ZIG),'lld-link','/subsystem:'+subsystem,'/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/opt:ref','/opt:noicf','/timestamp:0','/map:'+str(OUT/f'{name}.map'),'/out:'+str(path)]+[str(OUT/f'{p}.obj') for p in parts]
        subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
        pe=pefile.PE(str(path));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();path.write_bytes(pe.write());pe=pefile.PE(str(path))
        assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==(11 if name=='driver' else 10)
        assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size==0 and pe.verify_checksum()
        assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
        outputs.append(dict(path=str(path.relative_to(OUT)),bytes=path.stat().st_size,sha256=sha(path),subsystem=pe.OPTIONAL_HEADER.Subsystem))
    marker=b'HERO-IPMI-SETUP-M1A\r\n';assert len(marker)==21
    (OUT/'USB/HERO-IPMI-M1A.TAG').write_bytes(marker)
    unchanged=['common.c','engine.c','probe_core.c','probe_core.h']
    assert all(sha(OUT/'source'/n)==sha(OUT.parent/'hero_ipmi_setup_m1/source'/n) for n in unchanged)
    report=dict(version='M1a',purpose='USB black-screen diagnosis; target root cause unconfirmed',automatic_initialization=False,firmware_capsule=False,
        unchanged_m1_core=unchanged,outputs=outputs,commands=commands,sources={str(p.relative_to(OUT)):sha(p) for p in sorted((OUT/'source').glob('*')) if p.is_file()})
    (OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(outputs,indent=2))
if __name__=='__main__':build()

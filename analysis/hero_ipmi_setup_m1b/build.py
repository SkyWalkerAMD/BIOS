"""Build only repaired M1b launcher; preserve the tested M1a driver bytes."""
from pathlib import Path
import sys,os,subprocess,json,hashlib
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-global');env['ZIG_LOCAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-local')
    commands=[]
    for name in ('common','launcher'):
        cmd=[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections','-c',str(OUT/'source'/f'{name}.c'),'-o',str(OUT/f'{name}.obj')]
        subprocess.run(cmd,check=True,cwd=ROOT,env=env);commands.append(cmd)
    dest=OUT/'USB/EFI/BOOT/BOOTX64.EFI'
    cmd=[str(ZIG),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/opt:ref','/opt:noicf','/timestamp:0','/map:'+str(OUT/'launcher.map'),'/out:'+str(dest),str(OUT/'launcher.obj'),str(OUT/'common.obj')]
    subprocess.run(cmd,check=True,cwd=ROOT,env=env);commands.append(cmd)
    pe=pefile.PE(str(dest));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();dest.write_bytes(pe.write());pe=pefile.PE(str(dest))
    assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==10 and pe.verify_checksum()
    assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size==0 and pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
    driver=OUT/'USB/EFI/HERO/HeroIpmiM1a.efi'
    assert sha(driver)==sha(OUT.parent/'hero_ipmi_setup_m1a/USB/EFI/HERO/HeroIpmiM1a.efi')=='0b0849c20032b5fee9babdbf49ddb15b3d064ac03aa5642d1551ac475351b184'
    for name in ('efi_min.h','m1.h','probe_core.h','common.c'):assert sha(OUT/'source'/name)==sha(OUT.parent/'hero_ipmi_setup_m1a/source'/name)
    (OUT/'USB/HERO-IPMI-M1B.TAG').write_bytes(b'HERO-IPMI-SETUP-M1B\r\n')
    report=dict(version='M1b',launcher_sha256=sha(dest),launcher_bytes=dest.stat().st_size,driver_sha256=sha(driver),driver_unchanged=True,commands=commands,sources={p.name:sha(p) for p in (OUT/'source').iterdir() if p.is_file()},capsule=False)
    (OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('commands','sources')},indent=2))
if __name__=='__main__':main()

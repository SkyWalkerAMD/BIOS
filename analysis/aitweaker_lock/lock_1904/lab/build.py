"""Build VM-only UEFI fixtures; never executes EFI on the host."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[3]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
    env=os.environ.copy()
    env['ZIG_GLOBAL_CACHE_DIR']=str(OUT/'cache-global');env['ZIG_LOCAL_CACHE_DIR']=str(OUT/'cache-local')
    out=OUT/'build';out.mkdir(exist_ok=True)
    cc=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),
        '-I',str(OUT.parent.parent/'probe_p2/source'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-Wno-unused-variable',
        '-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar']
    for source,extra,obj in [('common',[],'common'),('resident',[],'resident'),('loader',[],'loader'),('checker',[],'checker'),('boot',[],'boot'),('boot',['-DEXPECT_AUTO=1'],'auto')]:
        subprocess.run(cc+extra+['-c',str(OUT/(source+'.c')),'-o',str(out/(obj+'.obj'))],env=env,check=True)
    report={'purpose':'QEMU TCG-only lifecycle fixtures. No password locking behavior claimed.','binaries':{}}
    for obj,name,kind in [('resident','RESIDENT.EFI','efi_boot_service_driver'),('loader','LOADER.EFI','efi_application'),('checker','CHECKER.EFI','efi_application'),('boot','BOOTX64.EFI','efi_application'),('auto','AUTOBOOT.EFI','efi_application')]:
        p=out/name
        subprocess.run([str(zig),'lld-link','/subsystem:'+kind,'/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/out:'+str(p),str(out/(obj+'.obj')),str(out/'common.obj')],env=env,check=True)
        pe=pefile.PE(str(p));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();p.write_bytes(pe.write())
        assert pe.OPTIONAL_HEADER.Subsystem==(11 if obj=='resident' else 10)
        assert not pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress
        assert not pe.FILE_HEADER.Characteristics&1,'IMAGE_FILE_RELOCS_STRIPPED'
        report['binaries'][name]={'sha256':sha(p),'bytes':p.stat().st_size,'subsystem':pe.OPTIONAL_HEADER.Subsystem,'imports':0,'relocations':pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size}
    (out/'manifest.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()

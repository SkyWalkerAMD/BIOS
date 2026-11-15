"""Build standalone S0; no firmware image modification or hardware execution."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def build():
    boot=OUT/'USB/EFI/BOOT';boot.mkdir(parents=True,exist_ok=True)
    env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-global');env['ZIG_LOCAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-local')
    commands=[
        [str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(OUT/'source/probe.c'),'-o',str(OUT/'probe.obj')],
        [str(ZIG),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(OUT/'probe.map'),'/out:'+str(boot/'BOOTX64.EFI'),str(OUT/'probe.obj')]
    ]
    for cmd in commands:subprocess.run(cmd,check=True,env=env,cwd=ROOT)
    p=boot/'BOOTX64.EFI';pe=pefile.PE(str(p));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();p.write_bytes(pe.write());pe=pefile.PE(str(p))
    assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==10 and pe.verify_checksum()
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size and not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
    (OUT/'USB/HERO-BOOT-S0.TAG').write_bytes(b'HERO-BOOT-S0\r\n')
    report=dict(version='S0',status='BUILT; target black-screen cause unconfirmed',date='2026-10-23',purpose='Isolate EFI entry, console output, and explicit USB file access before any IPMI adaptation code',
        startup='First firmware service is direct OutputString; no filesystem or HII before key input',manual_actions=dict(L='Only marked boot-volume log file',G='GOP VideoFill on existing modes, maximum 8 handles',T='SimpleTextOutput mode 0',Q='Return to firmware'),
        excluded=['IPMI','BMC commands','PCI protocol access','NVRAM','SMBIOS','HII','LoadImage','BIOS/BMC flashing'],image='USB/EFI/BOOT/BOOTX64.EFI',sha256=sha(p),bytes=p.stat().st_size,
        pe=dict(machine='x64',subsystem=10,relocations=pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size,no_imports=True,unsigned=True,checksum=True),commands=commands,sources={p.name:sha(p) for p in sorted((OUT/'source').glob('*')) if p.is_file()})
    (OUT/'build.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps({k:report[k] for k in ('version','image','bytes','sha256')},indent=2))
if __name__=='__main__':build()

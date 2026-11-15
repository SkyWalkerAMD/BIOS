"""Build the standalone USB UEFI probe; never installs or runs it on hardware."""
from pathlib import Path
import hashlib, json, os, subprocess, sys
ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'analysis/hero_ipmi_probe'
SRC=OUT/'source'
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile

def build():
    boot=OUT/'USB/EFI/BOOT'
    boot.mkdir(parents=True,exist_ok=True)
    env=os.environ.copy()
    env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-global')
    env['ZIG_LOCAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-local')
    # Invoke Zig's bundled Clang/LLD directly; no Windows SDK or subprocess
    # compiler discovery is needed for this freestanding EFI image.
    commands=[]
    for name in ('probe','probe_core'):
        args=[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc',
              '-nostdinc','-isystem',str(ZIG.parent/'lib/include'),
              '-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding',
              '-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar',
              '-c',str(SRC/(name+'.c')),'-o',str(OUT/(name+'.obj'))]
        subprocess.run(args,check=True,env=env,cwd=ROOT)
        commands.append(args)
    args=[str(ZIG),'lld-link','/subsystem:efi_application','/entry:efi_main',
          '/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat',
          '/timestamp:0','/map:'+str(OUT/'probe.map'),
          '/out:'+str(boot/'BOOTX64.EFI'),str(OUT/'probe.obj'),str(OUT/'probe_core.obj')]
    subprocess.run(args,check=True,env=env,cwd=ROOT)
    commands.append(args)
    exe=boot/'BOOTX64.EFI'
    pe=pefile.PE(str(exe))
    pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum()
    exe.write_bytes(pe.write())
    pe=pefile.PE(str(exe))
    assert pe.FILE_HEADER.Machine==0x8664
    assert pe.OPTIONAL_HEADER.Subsystem==10
    assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size>0
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size==0
    assert pe.verify_checksum()
    (OUT/'USB/HERO-PROBE-USB.TAG').write_bytes(b'HERO-IPMI-PROBE-A1\r\n')
    report=dict(status='BUILT_NOT_TESTED_ON_TARGET',purpose='Standard read-command hardware baseline; NOT a transplant loader.',
                image='USB/EFI/BOOT/BOOTX64.EFI',sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
                bytes=exe.stat().st_size,machine='x64',subsystem=10,
                no_imports=True,relocations_present=True,checksum_valid=True,unsigned=True,
                source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in SRC.glob('*') if p.is_file()},
                compiler='Zig 0.14.1 portable; clang C frontend, LLVM linker',
                commands=commands)
    (OUT/'build.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:report[k] for k in ['image','sha256','bytes','subsystem','unsigned']},indent=2))

if __name__=='__main__': build()

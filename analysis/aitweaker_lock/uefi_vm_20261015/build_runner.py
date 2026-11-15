from pathlib import Path
import sys,subprocess,os,hashlib,json
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
P2=OUT.parent/'probe_p2'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-global');env['ZIG_LOCAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-local')
cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),
     '-I',str(P2/'source'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin',
     '-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(OUT/'vm_runner.c'),'-o',str(OUT/'vm_runner.obj')]
subprocess.run(cmd,check=True,env=env)
cmd=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64',
     '/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/out:'+str(OUT/'VMRUNNER.EFI'),
     str(OUT/'vm_runner.obj'),str(P2/'probe_core.obj')]
subprocess.run(cmd,check=True,env=env)
p=OUT/'VMRUNNER.EFI';pe=pefile.PE(str(p));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();p.write_bytes(pe.write())
report={'purpose':'QEMU TCG-only harness; NOT for physical boards. P2 bytes unchanged.',
        'runner_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
        'source_sha256':hashlib.sha256((OUT/'vm_runner.c').read_bytes()).hexdigest(),
        'p2_sha256':hashlib.sha256((P2/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest()}
(OUT/'runner_build.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps(report,indent=2))

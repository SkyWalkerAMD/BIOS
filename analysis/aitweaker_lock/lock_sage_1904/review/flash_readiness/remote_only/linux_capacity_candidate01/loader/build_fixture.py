"""Build isolated protocol-consumer fixture; never a hardware candidate."""
from pathlib import Path
import hashlib,json,os,subprocess
from build_loader import OUT,ROOT,build,sha
def main():
    dest=OUT/'tests/fixture';dest.mkdir(parents=True,exist_ok=True);zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
    env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(OUT/'cache/global');env['ZIG_LOCAL_CACHE_DIR']=str(OUT/'cache/local')
    for name in ['handshake_fixture','sha256']:
        subprocess.run([str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(OUT/'source'),'-std=c11','-Oz','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(OUT/'source'/f'{name}.c'),'-o',str(dest/f'{name}.obj')],env=env,check=True)
    kernel=dest/'VMFIXTURE.EFI';subprocess.run([str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/timestamp:0','/out:'+str(kernel),str(dest/'handshake_fixture.obj'),str(dest/'sha256.obj')],env=env,check=True)
    initrd=dest/'NOT-AN-INITRAMFS.fixture';initrd.write_bytes(bytes((i*17+3)%256 for i in range(4096)))
    contract={'status':'VM FIXTURE ONLY - NOT LINUX OR HARDWARE','cmdline':'fixture_exact_commandline=LC01 no_fallback=1'}
    for label,p in [('kernel',kernel),('initrd',initrd)]:contract[label]={'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}
    p=dest/'contract.json';p.write_text(json.dumps(contract,indent=2),encoding='utf8');result=build(p,dest/'loader');print(json.dumps({'binary':result['binary'],'sha256':result['binary_sha256'],'contract':str(p)},indent=2))
if __name__=='__main__':main()

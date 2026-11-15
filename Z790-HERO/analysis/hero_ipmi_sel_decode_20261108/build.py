"""Build a pure freestanding decoder as a host test DLL; no hardware/network."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
def main():
    env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(HERE/'zig-global');env['ZIG_LOCAL_CACHE_DIR']=str(HERE/'zig-local')
    commands=[
        [str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-c',str(HERE/'sel_decode.c'),'-o',str(HERE/'sel_decode.obj')],
        [str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/timestamp:0','/export:sel_format_record','/out:'+str(HERE/'sel_decode_test.dll'),str(HERE/'sel_decode.obj')]
    ]
    for command in commands:subprocess.run(command,check=True,cwd=ROOT,env=env)
    pe=pefile.PE(str(HERE/'sel_decode_test.dll'));assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
    report={'scope':'Freestanding C object and import-free host DLL. No target firmware changes.','commands':commands,
        'sha256':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in ['sel_decode.c','sel_decode.h','sel_decode.obj','sel_decode_test.dll']}}
    (HERE/'build.json').write_text(json.dumps(report,indent=2)+'\n')
    print('Decoder compiled; no imported functions.')
if __name__=='__main__':main()

"""Deterministic freestanding object + host-only DLL. Does not touch hardware."""
from pathlib import Path
import hashlib,json,os,subprocess

OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
EXPORTS=('p6_validate_ipv4','p6_lan_apply','p6_watchdog_configure','p6_watchdog_start','p6_watchdog_recover_stop',
         'p6_sel_get_info','p6_sel_clear','p6_sel_delete_oldest','p6_sel_logging','p1_read_allowed','p6_write_armed,DATA')

def main():
    env=os.environ.copy()
    env['ZIG_GLOBAL_CACHE_DIR']=str(OUT/'.zig-cache')
    env['ZIG_LOCAL_CACHE_DIR']=str(OUT/'.zig-local')
    flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),
           '-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin',
           '-fno-stack-protector','-mno-red-zone','-ffunction-sections','-fdata-sections']
    commands=[
        [str(ZIG),'clang',*flags,'-c',str(OUT/'p6_backend.c'),'-o',str(OUT/'p6_backend.obj')],
        [str(ZIG),'clang',*flags,'-I',str(OUT.parent/'source/compat'),'-c',str(OUT.parent/'source/command_policy.c'),'-o',str(OUT/'policy.obj')],
        [str(ZIG),'clang',*flags,'-c',str(OUT/'policy_fixture.c'),'-o',str(OUT/'policy_fixture.obj')],
        [str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/timestamp:0',
         *['/export:'+s for s in EXPORTS],'/out:'+str(OUT/'p6_backend_test.dll'),
         str(OUT/'p6_backend.obj'),str(OUT/'policy.obj'),str(OUT/'policy_fixture.obj')]
    ]
    for cmd in commands: subprocess.run(cmd,check=True,env=env,cwd=ROOT)
    files=['p6_backend.c','p6_backend.h','p6_backend.obj','p6_backend_test.dll']
    report={'scope':'host-only compiled transaction simulation; no hardware access',
            'commands':commands,'sha256':{s:hashlib.sha256((OUT/s).read_bytes()).hexdigest() for s in files},
            'production_policy_sha256':hashlib.sha256((OUT.parent/'source/command_policy.c').read_bytes()).hexdigest()}
    (OUT/'build_report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('Freestanding C object and host test DLL built without libc imports.')

if __name__=='__main__': main()

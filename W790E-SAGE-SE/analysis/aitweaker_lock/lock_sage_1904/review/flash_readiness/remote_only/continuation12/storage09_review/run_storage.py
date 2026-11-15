"""Snapshot and run the actual pure-storage header; never edit author inputs."""
from pathlib import Path
import hashlib,json,subprocess,datetime,os
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[7]
D04=HERE.parents[2]/'native13_split_candidate/installer_design04'
SOURCE=D04/'diagnostic_guard09/source'
run=HERE/datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
run.mkdir()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
for name in ['diagnostic_store.h','diagnostic09.h']:
    (run/name).write_bytes((SOURCE/name).read_bytes())
(run/'test_storage.c').write_bytes((HERE/'test_storage.c').read_bytes())
exe=run/'storage-test.exe'
command=[str(ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'),'cc','-std=c11','-O2','-I',str(run),str(run/'test_storage.c'),'-o',str(exe)]
env=os.environ.copy()
(HERE/'compiler-temp').mkdir(exist_ok=True)
env.update(ZIG_LOCAL_CACHE_DIR=str(HERE/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),
           TEMP=str(HERE/'compiler-temp'),TMP=str(HERE/'compiler-temp'))
build=subprocess.run(command,capture_output=True,text=True,timeout=180,creationflags=subprocess.CREATE_NO_WINDOW,env=env)
(run/'build.log').write_text(build.stdout+build.stderr,encoding='utf-8')
(run/'build_status.json').write_text(json.dumps({'returncode':build.returncode,'command':command,'global_cache':env['ZIG_GLOBAL_CACHE_DIR']},indent=2)+'\n')
assert build.returncode==0,(build.returncode,build.stdout,build.stderr)
process=subprocess.run([str(exe)],capture_output=True,text=True,timeout=45,creationflags=subprocess.CREATE_NO_WINDOW)
(run/'output.log').write_text(process.stdout+process.stderr,encoding='utf-8')
assert process.returncode==0,process.stdout+process.stderr
result=json.loads(process.stdout)
result.update(source_snapshot_unchanged=all((SOURCE/n).read_bytes()==(run/n).read_bytes() for n in ['diagnostic_store.h','diagnostic09.h']),
              bindings={n:sha(run/n) for n in ['diagnostic_store.h','diagnostic09.h','test_storage.c','storage-test.exe','build.log','output.log']},
              limits=['Pure helpers compiled for Windows host; not full UEFI guard, provider, firmware or physical AP test.',
                      'Bounded concurrent stress does not establish exhaustive race freedom or AP/SMM quiescence.',
                      'No native frame, password, EFI service or authorization function is exercised here.'])
(run/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'run':str(run),**result}))

"""Compile only revised entry.c; link against frozen INTEGRATED03 objects.

This isolated review build never writes the unified driver/build directory.
It is not the final INTEGRATED04 production binary.
"""
from pathlib import Path
import difflib
import hashlib
import json
import os
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
CASE = HERE.parent
ROOT = next(p for p in HERE.parents if (p/'tools/zig-x86_64-windows-0.14.1/zig.exe').is_file())
OLD = CASE.parent/'lock_1904_integrated03'
OUT = HERE/'build'
SRC = HERE/'source'
OUT.mkdir(parents=True, exist_ok=True)
(SRC/'driver').mkdir(parents=True, exist_ok=True)
(SRC/'core').mkdir(parents=True, exist_ok=True)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(OLD/'driver/build/AiTweakerLock1904.efi') == 'efd421fb1fd7239e352eb20528c5f7836301ee3289986fc31474a6ba53959395'
inputs = [CASE/'driver/entry.c']+list((CASE/'driver').glob('*.h'))+[CASE/'core/password_core.h']
bindings = {str(p.relative_to(ROOT)): sha(p) for p in inputs}
for p in inputs:
    shutil.copyfile(p, SRC/p.relative_to(CASE))
shutil.copyfile(OLD/'driver/policy.json', HERE/'policy.json')
build = json.loads((OLD/'driver/build/build.json').read_text(encoding='utf8'))
compile_command = next(c for c in build['commands'] if any(a.endswith('entry.c') for a in c))
compile_command = [str(SRC/'driver/entry.c') if a.endswith('entry.c') else
                   str(OUT/'entry.obj') if a.endswith('entry.obj') else
                   str(SRC/'driver') if a == str(OLD/'driver') else a for a in compile_command]
link_command = [('/out:'+str(OUT/'AiTweakerLock1904.efi')) if a.startswith('/out:') else
                ('/map:'+str(OUT/'driver.map')) if a.startswith('/map:') else
                str(OUT/'entry.obj') if a.endswith('entry.obj') else a for a in build['commands'][-1]]
frozen_objects = {a: sha(Path(a)) for a in link_command if a.endswith('.obj') and a != str(OUT/'entry.obj')}
env = os.environ.copy()
env.update(ZIG_GLOBAL_CACHE_DIR=str(OUT/'.zig-global'), ZIG_LOCAL_CACHE_DIR=str(OUT/'.zig-local'))
for command in [compile_command, link_command]:
    subprocess.run(command, check=True, env=env, cwd=HERE,
                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
sys.path.insert(0, str(ROOT/'tools/pydeps'))
import pefile
efi = OUT/'AiTweakerLock1904.efi'
p = pefile.PE(str(efi)); p.OPTIONAL_HEADER.CheckSum = p.generate_checksum(); efi.write_bytes(p.write()); p.close()
assert all(sha(ROOT/p) == digest for p, digest in bindings.items()), 'snapshot input changed while compiling'
assert all(sha(Path(p)) == digest for p, digest in frozen_objects.items())
diff = ''.join(difflib.unified_diff((OLD/'driver/entry.c').read_text(encoding='utf8').splitlines(True),
                                   (CASE/'driver/entry.c').read_text(encoding='utf8').splitlines(True),
                                   fromfile='INTEGRATED03/driver/entry.c', tofile='INTEGRATED04/driver/entry.c'))
(HERE/'entry.diff').write_text(diff, encoding='utf8')
report = {'scope': __doc__, 'efi_sha256': sha(efi), 'entry_obj_sha256': sha(OUT/'entry.obj'),
          'entry_source_sha256': sha(CASE/'driver/entry.c'), 'source_sha256': bindings,
          'frozen_integrated03_objects': {str(Path(p).relative_to(ROOT)): h for p, h in frozen_objects.items()},
          'policy_sha256': sha(HERE/'policy.json'), 'commands': [compile_command, link_command]}
(OUT/'build.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
print(json.dumps({k: report[k] for k in ['efi_sha256', 'entry_obj_sha256', 'entry_source_sha256']}, indent=2))

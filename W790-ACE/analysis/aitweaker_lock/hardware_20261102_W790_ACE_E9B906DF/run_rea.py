"""Run pinned, project-local REA against static firmware files; retain evidence."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
RUNTIME = ROOT / 'tools/rea-runtime'
NODE = RUNTIME / 'node-v26.13.0-win-x64/node.exe'
REA = RUNTIME / 'node_modules/rea-agents/scripts/rea.mjs'


def environment():
    env = os.environ.copy()
    temp = RUNTIME / 'tmp'
    temp.mkdir(exist_ok=True)
    env.update({
        'GHIDRA_INSTALL_DIR': str(RUNTIME / 'ghidra_12.1.4_PUBLIC'),
        'JAVA_HOME': r'D:\JAVA\graalvm-jdk-21.0.9+7.1',
        'REA_ANALYSIS_PROVIDER': 'ghidra',
        'REA_GHIDRA_STARTUP_TIMEOUT_MS': '600000',
        'REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS': '120',
        'GHIDRA_HEADLESS_MAXMEM': '2048M',
        'NODE_TLS_REJECT_UNAUTHORIZED': '1',
        'TEMP': str(temp),
        'TMP': str(temp),
        'PATH': str(NODE.parent) + os.pathsep + env.get('PATH', ''),
    })
    return env


def main():
    label, *args = sys.argv[1:]
    assert label and all(c.isalnum() or c in '-_' for c in label)
    out = HERE / 'rea'
    out.mkdir(exist_ok=True)
    start = time.monotonic()
    completed = subprocess.run([str(NODE), str(REA), *args], env=environment(),
                               cwd=RUNTIME, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               creationflags=subprocess.CREATE_NO_WINDOW, timeout=900)
    (out / f'{label}.json').write_bytes(completed.stdout)
    (out / f'{label}.stderr.txt').write_bytes(completed.stderr)
    record = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'command': [str(NODE), str(REA), *args], 'exit_code': completed.returncode,
              'elapsed_seconds': round(time.monotonic() - start, 3),
              'stdout_bytes': len(completed.stdout),
              'stdout_sha256': hashlib.sha256(completed.stdout).hexdigest(),
              'stderr_bytes': len(completed.stderr)}
    (out / f'{label}.run.json').write_text(json.dumps(record, indent=2), encoding='utf-8')
    print(json.dumps(record, indent=2))
    if len(completed.stdout) < 4000:
        print(completed.stdout.decode('utf-8', errors='replace'))
    if completed.stderr:
        print(completed.stderr.decode('utf-8', errors='replace')[-2500:])
    sys.exit(completed.returncode)


if __name__ == '__main__':
    main()

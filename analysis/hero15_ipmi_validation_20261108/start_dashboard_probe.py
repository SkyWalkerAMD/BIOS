"""Fixed .15 one-shot Dashboard/Sensors capture; credentials via private pipe."""
from pathlib import Path
import argparse
import getpass
import importlib.util
import json
import os
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out-label', required=True)
    parser.add_argument('--credentials-stdin', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,45}', args.out_label) or (HERE / args.out_label).exists():
        raise ValueError('new output label required')
    spec = importlib.util.spec_from_file_location('probe15_private_parser', HERE / 'readonly_hero15.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if args.credentials_stdin:
        print('READY_FOR_PRIVATE_CREDENTIALS', flush=True)
        username, password = module.parse_credential(sys.stdin.buffer.readline(4097))
    else:
        username = input('BMC username (not saved): ')
        password = getpass.getpass('BMC password (not echoed or saved): ')
        module.parse_credential(json.dumps({'username':username,'password':password}).encode('utf-8'))
    secret_input = (json.dumps({'username':username,'password':password})+'\n').encode('utf-8')
    username=password=None
    clean_env = {k:v for k,v in os.environ.items() if not re.fullmatch(r'(?:https?|all|no)_proxy',k,re.I)}
    process = subprocess.Popen([str(ROOT / 'tools/rea-runtime/node-v26.13.0-win-x64/node.exe'),
                                str(HERE / 'dashboard_probe.cjs'),args.out_label],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=ROOT,
        env=clean_env,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    timed_out=False
    try:
        stdout,stderr=process.communicate(secret_input,timeout=120)
    except subprocess.TimeoutExpired:
        timed_out=True
        process.kill()
        stdout,stderr=process.communicate()
    secret_input=None
    # Node prints a fixed-shape summary only. Do not echo arbitrary library output.
    for line in stdout.decode('utf-8',errors='replace').splitlines():
        try:
            data=json.loads(line)
            if isinstance(data,dict) and set(data).issubset({'output','ok','informationStatus','sensorsStatus','failureType','blocked'}):
                print(json.dumps(data,ensure_ascii=False))
        except ValueError:
            pass
    print(json.dumps({'return_code':process.returncode,'hard_timeout':timed_out,'unrecorded_stderr_bytes':len(stderr)}))
    return 124 if timed_out else process.returncode


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (ValueError,OSError):
        print('Browser probe stopped before completion; no secret details recorded.',file=sys.stderr)
        raise SystemExit(2)

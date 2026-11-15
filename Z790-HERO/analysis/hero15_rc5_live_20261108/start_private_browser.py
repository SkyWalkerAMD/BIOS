"""Launch the fixed-origin BMC controller with a non-echoed, memory-only secret."""
from pathlib import Path
import getpass
import json
import subprocess

here = Path(__file__).resolve().parent
root = here.parents[1]
password = getpass.getpass('BMC password (not echoed): ')
payload = json.dumps({'username': 'admin', 'password': password}) + '\n'
password = None
child = subprocess.Popen(
    [str(root / 'tools/rea-runtime/node-v26.13.0-win-x64/node.exe'), str(here / 'browser.cjs')],
    stdin=subprocess.PIPE,
    cwd=root,
    creationflags=subprocess.CREATE_NO_WINDOW,
)
child.stdin.write(payload.encode('utf-8'))
child.stdin.close()
payload = None
raise SystemExit(child.wait())

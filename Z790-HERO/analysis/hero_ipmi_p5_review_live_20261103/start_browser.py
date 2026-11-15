"""Read the supplied BMC password without echo; keep it in process memory."""
from pathlib import Path
import getpass,json,subprocess
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[1]
secret=getpass.getpass('BMC password (memory only, not recorded): ')
p=subprocess.Popen([str(ROOT/'tools/rea-runtime/node-v26.13.0-win-x64/node.exe'),str(OUT/'browser.cjs')],stdin=subprocess.PIPE,text=True,cwd=ROOT)
p.stdin.write(json.dumps({'username':'siadmin','password':secret})+'\n');p.stdin.flush();p.stdin.close()
del secret
try:p.wait()
except KeyboardInterrupt:p.terminate();p.wait()
raise SystemExit(p.returncode)

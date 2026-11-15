"""Read supplied credentials without echo; pass only over a private stdin pipe."""
from pathlib import Path
import getpass,json,subprocess
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
secret=getpass.getpass('BMC password (memory only): ')
p=subprocess.Popen([str(ROOT/'tools/rea-runtime/node-v26.13.0-win-x64/node.exe'),str(P/'browser.cjs')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,cwd=ROOT,creationflags=subprocess.CREATE_NO_WINDOW)
p.stdin.write(json.dumps({'username':'siadmin','password':secret})+'\n');p.stdin.close();del secret
try:
 for line in p.stdout:print(line,end='',flush=True)
 p.wait()
except KeyboardInterrupt:p.terminate();p.wait()
raise SystemExit(p.returncode)

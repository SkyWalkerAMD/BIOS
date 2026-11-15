"""Run frozen .15 standard GET probe with a memory-only credential pipe."""
from pathlib import Path
import argparse
import getpass
import hashlib
import json
import subprocess
import sys

here=Path(__file__).resolve().parent
probe=here.parent/'hero15_ipmi_validation_20261108/readonly_hero15.py'
assert hashlib.sha256(probe.read_bytes()).hexdigest()=='0b42084db301754cc2db751e74f2ad2f74cd3be45b8d6780c61e694f4fd73834'
p=argparse.ArgumentParser()
p.add_argument('stage',choices=['before','after','repeat','final'])
p.add_argument('--lan-only',action='store_true')
a=p.parse_args()
out=probe.parent/('rc5-host15-'+a.stage+('-lan' if a.lan_only else '-core')+'.json')
assert not out.exists()
password=getpass.getpass('BMC password (not echoed): ')
payload=(json.dumps({'username':'admin','password':password})+'\n').encode()
password=None
cmd=[sys.executable,'-I','-S','-B',str(probe),'--collect','--credentials-stdin','--out',str(out)]
if a.lan_only:cmd+=['--lan-only']
r=subprocess.run(cmd,input=payload,timeout=210)
payload=None
raise SystemExit(r.returncode)

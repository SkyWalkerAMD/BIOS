"""Exercise the physical-capture wrapper using immutable existing VM screenshots."""
from pathlib import Path
import hashlib,json,shutil,subprocess,sys
HERE=Path(__file__).resolve().parent
SAGE=HERE.parents[3]
HW=SAGE/'remote_172_20_2_162'
review=json.loads((HERE/'linux_payload_parent_review.json').read_text())
results=[]
for item in review['decoded_vm_cases']:
    folder=HERE/'capture_wrapper_tests'/item['case'];folder.mkdir(parents=True,exist_ok=True)
    shot=folder/'page-01.png';shutil.copyfile(item['screenshot'],shot)
    proc=subprocess.run([sys.executable,'-X','utf8',str(HW/'read_linux_capacity01_qr.py'),'capture',str(shot)],capture_output=True,timeout=20)
    expect=item['semantic']['variant']=='PRODUCTION'
    assert (proc.returncode==0)==expect, (item['case'],proc.stderr)
    if expect:
        parsed=json.loads(proc.stdout);assert parsed['semantic']==item['semantic']
    else: assert b'Lab payload forbidden' in proc.stderr
    results.append({'case':item['case'],'accepted':expect,'outcome':'PASS'})
record={'status':'PASS','cases':results,'decoder_sha256':hashlib.sha256((HW/'read_linux_capacity01_qr.py').read_bytes()).hexdigest(),
        'operation_sha256':hashlib.sha256((HW/'operations/capture_linux_capacity01.mjs').read_bytes()).hexdigest(),
        'scope':'Production screenshots accepted, all lab screenshots refused; no BMC access.'}
(HERE/'linux_capture_wrapper_review.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({'status':'PASS','cases':len(results)}))

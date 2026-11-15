"""Actual new fixed-selection EFI boots in OVMF; unchanged P3 UI/CRC checks.
Only the obsolete inventory-specific watchdog log assertion is replaced with
the D7 marker; the frozen original verifier is read, never edited.
"""
from pathlib import Path
import hashlib,importlib.util,json,sys,types
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];LEGACY=ROOT/'analysis/aitweaker_lock/probe_p3_kvm';OUT=HERE/'build'
for part in ('pydeps','vm-pydeps','kvm-pydeps'):sys.path.insert(0,str(ROOT/'tools'/part))
sys.path.insert(0,str(LEGACY))
from transport import parse
from verify_efi import BASE
def main():
 source_path=LEGACY/'verify_vm.py';source=source_path.read_text();before="assert b'Watchdog.disable=0x0000000000000000\\r\\n' in log";after="assert b'W890_DELTA07_DIAGNOSTIC_ONLY\\r\\n' in log";assert source.count(before)==1;source=source.replace(before,after)
 module=types.ModuleType('delta07_real_ovmf');module.__file__=str(source_path);exec(compile(source,str(source_path),'exec'),module.__dict__);module.OUT=OUT;module.ISO=OUT/'W890-DELTA07-STRUCTURE-NOFLASH.iso'
 selection=json.loads((HERE/'selection_hardware02.json').read_text());payload=selection['payload'];results=[]
 for args in [('sata',800,600,0),('usb',1024,768,0)]:
  r=module.run(*args);results.append(r);assert r['passed'],r
  data=(OUT/r['folder']/'RESTORED-LOG.TXT').read_bytes();decoded=parse(data,payload['targets'],bytes.fromhex(payload['source_log_sha256']),bytes.fromhex(selection['selection_sha256']),BASE,15360)
  assert decoded['refused']==[1,2,3,4,5] and decoded['spf']['carrier_state']=='MODULE_UNAVAILABLE' and decoded['environment']['map']=='READY'
  r['d7_decoded']={'refused':decoded['refused'],'bytes':len(data),'spf_state':decoded['spf']['carrier_state'],'log_sha256':decoded['log_sha256']}
 (OUT/'ovmf_tests.json').write_text(json.dumps({'passed':True,'results':results,'frozen_verifier_sha256':hashlib.sha256(source_path.read_bytes()).hexdigest(),'source_adaptation':{'before':before,'after':after}},indent=2)+'\n')
if __name__=='__main__':main()

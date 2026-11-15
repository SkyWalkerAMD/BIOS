"""Only local read-only ISO boot; reuse frozen P3 QR verifier without modifying it."""
from pathlib import Path
import importlib.util,json,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];LEGACY=ROOT/'analysis/aitweaker_lock/probe_p3_kvm';OUT=HERE/'build'
for part in ('pydeps','vm-pydeps','kvm-pydeps'):sys.path.insert(0,str(ROOT/'tools'/part))
sys.path.insert(0,str(LEGACY))
def main():
 spec=importlib.util.spec_from_file_location('hii06_qr_vm',LEGACY/'verify_vm.py');vm=importlib.util.module_from_spec(spec);spec.loader.exec_module(vm);vm.OUT=OUT;vm.ISO=OUT/'W890-HII06-FINGERPRINT-NOFLASH.iso'
 results=[]
 for args in [('sata',800,600,0),('usb',1024,768,0)]:
  r=vm.run(*args);results.append(r);assert r['passed'],r
  text=(OUT/r['folder']/'RESTORED-LOG.TXT').read_text();assert 'HII06_FINGERPRINTS_DIAGNOSTIC_NOT_AUTHORITY' in text
 (OUT/'ovmf_tests.json').write_text(json.dumps({'passed':True,'results':results},indent=2)+'\n')
if __name__=='__main__':main()

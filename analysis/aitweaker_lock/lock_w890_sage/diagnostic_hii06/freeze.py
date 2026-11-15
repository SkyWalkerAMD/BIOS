"""Bind the reviewed candidate and evidence without editing older directories."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;OUT=HERE/'build';ROOT=HERE.parents[3]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 build=json.loads((OUT/'build.json').read_text());efi=OUT/'BOOTX64.EFI';iso=OUT/'W890-HII06-FINGERPRINT-NOFLASH.iso'
 assert sha(efi)==build['efi_sha256'] and sha(iso)==build['iso_sha256']
 reports={}
 for name in ('core_tests','efi_tests','decoder_tests','artifact_tests'):
  data=json.loads((OUT/(name+'.json')).read_text());assert data['passed'] and data['efi_sha256']==sha(efi);reports[name]=data.get('count',True)
 vm=json.loads((OUT/'ovmf_tests.json').read_text());assert vm['passed']
 for r in vm['results']:assert r['passed'] and r['efi_sha256']==sha(efi) and r['iso_sha256_before']==r['iso_sha256_after']==sha(iso)
 for rel,digest in build['sources'].items():assert sha(HERE/'source'/rel)==digest
 for item in build['inputs']:assert sha(Path(item['path']))==item['sha256']
 include=[p for p in HERE.iterdir() if p.is_file() and p.name!='component_manifest.json']
 include+=list((HERE/'source').rglob('*'));include+=[p for p in OUT.iterdir() if p.is_file() and p.suffix in ('.json','.dll','.EFI','.iso','.map') and not p.name.startswith('efi_test_')]
 include+=list((OUT/'efi_cases').glob('*.txt'))
 for r in vm['results']:
  folder=OUT/r['folder'];include+=[folder/'result.json',folder/'RESTORED-LOG.TXT',folder/'command.json',folder/'qr-001.png',folder/'text-001.png',folder/'serial.log']
 include=sorted(set(p for p in include if p.is_file()))
 bindings=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for p in include]
 result={'status':'LOCAL_TESTED_READ_ONLY_DIAGNOSTIC_AWAITING_INDEPENDENT_REVIEW','not_hardware_qualified_by_this_manifest':True,'efi_sha256':sha(efi),'iso_sha256':sha(iso),'tests':reports,'ovmf_runs':len(vm['results']),'files':bindings,'scope':['No device connection or hardware change performed.','Unknown owners remain unknown; no navigation/write authority.','Old P2 file output and P3 output remain unchanged.','No new file-output fingerprint frontend or raw-IFR/delta export implemented.']}
 (HERE/'component_manifest.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'bindings':len(bindings),'tests':reports,'manifest_sha256':sha(HERE/'component_manifest.json')},indent=2))
if __name__=='__main__':main()

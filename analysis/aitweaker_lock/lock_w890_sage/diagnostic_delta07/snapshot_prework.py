"""Bind the completed prerequisite codec work; not a deployable qualification."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];OUT=HERE/'build'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 build=json.loads((OUT/'build.json').read_text());assert sha(OUT/'delta_core_test.dll')==build['dll_sha256']
 core=json.loads((OUT/'core_tests.json').read_text());transport=json.loads((OUT/'transport_tests.json').read_text());assert core['passed'] and transport['passed'] and core['dll_sha256']==transport['core_dll_sha256']==build['dll_sha256']
 h6=HERE.parent/'diagnostic_hii06/component_manifest.json';frozen=json.loads(h6.read_text())
 for r in frozen['files']:assert sha(ROOT/r['path'])==r['sha256']
 selected=[p for p in HERE.iterdir() if p.is_file() and p.name!='prework_manifest.json']
 selected+=list((HERE/'source').glob('*'))+[OUT/'delta_core_test.dll',OUT/'build.json',OUT/'core_tests.json',OUT/'transport_tests.json',OUT/'SYNTHETIC-selection-example.json']
 selected+=list((OUT/'synthetic').glob('*'))+list((OUT/'qr').rglob('result.json'))+list((OUT/'qr').rglob('RESTORED-LOG.TXT'))+list((OUT/'qr').rglob('qr-001.png'))
 result={'status':'PREWORK_ONLY_NO_REAL_SELECTION_NO_EFI_NO_DEPLOYMENT_BUDGET','dll_sha256':sha(OUT/'delta_core_test.dll'),'core_checks':core['count'],'transport_checks':transport['count'],'hii06_frozen_bindings_rechecked':len(frozen['files']),'real_hardware_input':None,'deployment_qr_capacity':None,'files':[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(set(selected))]}
 (HERE/'prework_manifest.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'bindings':len(result['files']),'sha256':sha(HERE/'prework_manifest.json')},indent=2))
if __name__=='__main__':main()

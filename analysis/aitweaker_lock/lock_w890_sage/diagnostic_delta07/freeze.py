"""Freeze exact candidate/evidence; no device access."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];OUT=HERE/'build'
def record(p):return {'path':p.resolve().relative_to(ROOT.resolve()).as_posix(),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
def main():
 reports={name:json.loads((OUT/name).read_text()) for name in ('core_tests.json','efi_tests.json','transport_tests.json','collector_transport_tests.json','ovmf_tests.json','artifact_tests.json')}
 assert all(r['passed'] for r in reports.values())
 assert [reports[n]['count'] for n in ('core_tests.json','efi_tests.json','transport_tests.json','collector_transport_tests.json')]==[68,18,22,15]
 efi=record(OUT/'BOOTX64.EFI');iso=record(OUT/'W890-DELTA07-STRUCTURE-NOFLASH.iso')
 assert efi['sha256']=='3918cbaea2559429a30bf8e78208b9df02c3a4a79ce4f1ea143e537a630dfcff'
 assert iso['sha256']=='8f99b7e0b04779000c9cc4763bacb8cd33316096c8ef79d9a2da428ed72d5e13'
 paths=[p for p in HERE.iterdir() if p.is_file() and p.suffix in ('.py','.c','.h')]+[HERE/'README.txt',HERE/'selection_hardware02.json']
 paths+=[p for p in (OUT/'source').rglob('*') if p.is_file()]
 paths+=[OUT/n for n in ('BOOTX64.EFI','W890-DELTA07-STRUCTURE-NOFLASH.iso','efiboot.img','build.json','probe.map','profiles.json','core_build.json','delta_core_test.dll','shipping_spf_decode.json')]
 paths+=[OUT/n for n in reports]
 for directory in ('efi_cases','collector_qr','vm'):
  paths+=[p for p in (OUT/directory).rglob('*') if p.is_file() and p.suffix.lower() in ('.json','.txt','.log','.png')]
 for directory in ('lab','lab_huge'):
  folder=OUT/directory;paths+=[folder/n for n in ('BOOTX64.EFI','build.json','probe.map','SYNTHETIC-selection.json')]
  paths+=[p for p in (folder/'efi_cases').glob('*.txt')];paths+=[folder/'source/selection.h']
 paths+=[OUT/'rebuilt/build.json',OUT/'rebuilt/BOOTX64.EFI']
 files=[record(p) for p in sorted(set(paths))];dependencies={}
 for r in json.loads((OUT/'build.json').read_text())['inputs']:
  actual=record(Path(r['path']));assert actual['sha256']==r['sha256'];dependencies[actual['path']]=actual
 for path in ('diagnostic_hii06/component_manifest.json','spf_sampler06/component_manifest.json','collector_review06/review.json','parser_review06/original_inventory.json'):
  r=record(HERE.parent/path);dependencies[r['path']]=r
 manifest={'status':'FROZEN_READONLY_DIAGNOSTIC_CANDIDATE_NOT_A_BIOS_OR_PASSWORD_LOCK','board':'ASUS Pro WS W890E-SAGE SE','bios':'0603','authorization':False,'hardware_operations_by_this_agent':False,'efi':efi,'iso':iso,'qr_budget_bytes':15360,'maximum_qr_pages':20,'selection_path':record(HERE/'selection_hardware02.json')['path'],'selection_sha256':'fb9dae754fbacaff55d2278cc6bc552133d6c141467b6aa2d87d707ce75bd48d','tests':{'native_codec':68,'actual_efi_cases':18,'transport':22,'collector_transport':15,'real_ovmf_boots':2},'files':files,'dependencies':list(dependencies.values()),'limitations':['Hardware selection rejects changed content/instances.','Positive HII cases use separate LAB binaries/configurations.','Shipping EFI full SPF test uses exact original SPF and modeled services.','OVMF lacks original modules and reports unavailable targets.','Unknown content remains unknown; no runtime authority or firmware integration.']}
 destination=HERE/'component_manifest.json';destination.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n');print(json.dumps({'files':len(files),'dependencies':len(dependencies),'manifest_sha256':record(destination)['sha256'],'efi_sha256':efi['sha256'],'iso_sha256':iso['sha256']},indent=2))
if __name__=='__main__':main()

from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
SOURCE=ROOT/'analysis/hero_ipmi_rc5_s22_20261108'
def record(p):
 b=p.read_bytes();return {'path':p.relative_to(ROOT).as_posix(),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def main():
 names=('independent-byte-audit.json','verification-regressions.json','independent-inventory-exclusion.json')
 reports=[json.loads((HERE/n).read_text()) for n in names]
 assert all(r['passed'] for r in reports)
 assert reports[0]['candidate_sha256']=='8adf138c82c71d8d599b625fa5776bcd201096f59d6f357fd2ef75251efdf70f'
 assert reports[1]['cases']==19 and reports[1]['root_guards']==31
 initial=json.loads((SOURCE/'builder-source-provenance.json').read_text())
 addon=json.loads((SOURCE/'builder-source-provenance-addendum.json').read_text())
 test=SOURCE/'test_builder_guards.py';assert record(test)['sha256']==addon['final_sha256']
 assert next(x['sha256'] for x in initial['files'] if x['output'].endswith('test_builder_guards.py'))==addon['initial_generated_sha256']
 for row in initial['files']:
  if row['output'].endswith('test_builder_guards.py'):continue
  assert record(ROOT/row['output'])['sha256']==row['sha256']
 out={'container_review_passed':True,'delivery_authorized':False,'candidate':'C04 R5 + S22 (historical)',
      'candidate_sha256':reports[0]['candidate_sha256'],'reports':[record(HERE/n) for n in names],
      'source_provenance_initial':record(SOURCE/'builder-source-provenance.json'),
      'source_provenance_length_fix':record(SOURCE/'builder-source-provenance-addendum.json'),
      'evidence':['Only two existing GUIDs changed; exact R5/S22 pins, 543 other FFS preserved.',
                  'Original HERO DxeCore accepts both strict section streams and rejects former trailing two zero bytes.',
                  '19 independent counterexamples and 31 author guards passed.',
                  'Official-to-baseline-to-C04 preserves 541 stock files; no known project I3/I5 publishers present.'],
      'remaining':'S22 actual host test stopped at HII bind EFI_NOT_FOUND. Parent is preparing separately reviewed S23/C05; this historical static pass is not functional acceptance or permission to deliver C04.',
      'hardware_flash_performed_by_reviewer':False,'frozen_c03_unchanged':True}
 dest=HERE/'static-review.json';dest.write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
 print(json.dumps(record(dest),indent=2))
if __name__=='__main__':main()

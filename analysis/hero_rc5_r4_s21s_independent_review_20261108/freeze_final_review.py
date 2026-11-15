"""Recheck exact deliverable/report pins; no firmware or hardware mutations."""
from pathlib import Path
import hashlib,json,sys
if not __debug__:raise RuntimeError('Assertions required')
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
CAP=ROOT/'analysis/hero_ipmi_rc5_s21s_20261108/RC5-IPMI-ONLY-R4-S21S-CANDIDATE03/HERO-3107-IPMI-RC5-IPMI-ONLY-R4-S21S-CANDIDATE03-UNSIGNED.CAP'
PIN='7a21f28c5a805ea29d651524b2ec2e05925252ff0799b71251583d99e1d53624'
def sha(b):return hashlib.sha256(b).hexdigest()
def fingerprint(p):b=p.read_bytes();return dict(path=p.relative_to(ROOT).as_posix(),bytes=len(b),sha256=sha(b))
def main():
 cap=fingerprint(CAP);assert cap['sha256']==PIN and cap['bytes']==33558528
 reports={}
 for name in ('independent-byte-audit.json','verification-regressions.json','independent-inventory-exclusion.json'):
  p=OUT/name;obj=json.loads(p.read_text(encoding='utf8'));assert obj['passed'] is True
  reports[name]=fingerprint(p)
 byte=json.loads((OUT/'independent-byte-audit.json').read_text())
 checks=json.loads((OUT/'verification-regressions.json').read_text())
 inv=json.loads((OUT/'independent-inventory-exclusion.json').read_text())
 assert byte['candidate_sha256']==PIN and byte['unchanged_ffs_count']==543
 assert checks['cases']==18 and checks['root_guards']==31 and checks['source_unchanged']
 source=ROOT/'analysis/hero_ipmi_rc5_s21s_20261108'
 for n,h in checks['source_sha256'].items():assert sha((source/n).read_bytes())==h
 assert inv['input_sha256']['candidate']==PIN and inv['no_project_i3_i5_publisher_in_baseline_or_candidate']
 assert len(inv['known_compiled_project_executables'])==15
 hw=ROOT/'analysis/hero_p6_s21s_independent_review_20261108/hardware-verification.json'
 assert sha(hw.read_bytes())=='7133485ca073e689322ca48b2af887e4fc0ed7b7f8353212e224dcf0f1f1c591'
 live=json.loads(hw.read_text());assert live['passed_first_real_afterboot_cycle'] and live['passed_repeated_real_afterboot_no_replay']
 assert live['total_independently_decoded_png_pages']==35 and live['restoration']['os_login_prompt_visually_confirmed']
 assert byte['payloads'][1]['pe_sha256']==live['core_sha256']
 reports['S21S-hardware']=fingerprint(hw)
 result=dict(passed=True,field_candidate_packaging_allowed=True,candidate=cap,reports=reports,
  independent_container_passed=True,target_dxe_core_section_validator_passed=True,
  only_two_original_ipmi_cores_replaced=True,no_project_inventory_in_baseline_and_candidate=True,
  original_platform_regions_unchanged=True,all_543_unrelated_baseline_ffs_unchanged=True,
  author_guard_cases=31,independent_regression_cases=18,known_inventory_pe_exclusions=15,
  exact_s21s_ram_real_afterboot_verified=True,repeat_callback_did_not_replay=True,
  source_sha256=checks['source_sha256'],hardware_actions_performed_by_this_review=False,
  verified_final_cap_flash=False,verified_native_first_setupenter=False,verified_f10_real_configuration_write=False,
  verified_official_recovery=False,official_asus_signed_release=False,failed_candidate02_remains_withheld=True,
  scope='Allows delivery as an explicitly limited field candidate only. Offline CAP validity and exact RAM-driver success are separate evidence; neither proves native first cold boot, F10 setters, FlashBack acceptance or recovery.',
  audit_scripts=[fingerprint(OUT/n) for n in ('audit_final.py','audit_inventory_absence.py','freeze_final_review.py')])
 p=OUT/'final-review.json';p.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
 print(json.dumps(dict(passed=True,path=p.relative_to(ROOT).as_posix(),sha256=sha(p.read_bytes()),candidate_sha256=PIN)))
if __name__=='__main__':main()

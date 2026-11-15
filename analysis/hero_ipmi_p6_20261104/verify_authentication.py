"""Confirm unchanged vendor capsule header and expected invalid modified signature."""
from pathlib import Path
import importlib.util,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
path=ROOT/'analysis/hero_ipmi_flash_validation_20261104/capsule/verify_hero_capsule.py'
spec=importlib.util.spec_from_file_location('auth',path);auth=importlib.util.module_from_spec(spec);spec.loader.exec_module(auth)
original=auth.ORIGINAL.read_bytes();candidate=(HERE/'firmware/HERO-3107-IPMI-P6-R2-RC4-UNSIGNED.CAP').read_bytes()
assert auth.sha(original)==auth.PIN_ORIGINAL
oldh,newh=auth.parse_capsule(original),auth.parse_capsule(candidate)
assert oldh==newh and original[:4096]==candidate[:4096]
old,new=auth.signatures(original,oldh),auth.signatures(candidate,newh)
assert old['certificate']['valid'] and old['firmware']['valid']
assert new['certificate']['valid'] and not new['firmware']['valid']
report=dict(passed_expected_results=True,candidate_sha256=auth.sha(candidate),original_sha256=auth.sha(original),original=old,candidate=new,capsule_header_unchanged=True,firmware_signature_valid=False,official_asus_release=False,scope='Mathematical signature check, not FlashBack acceptance. RC4 hardware test pending.')
(HERE/'authentication-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print('RC4 expected signature checks PASS; modified payload is not ASUS-signed.')

"""Check RC3 with the already audited HERO public-key parser; no signing."""
from pathlib import Path
import hashlib, importlib.util, json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCRIPT = ROOT/'analysis/hero_ipmi_flash_validation_20261104/capsule/verify_hero_capsule.py'
spec = importlib.util.spec_from_file_location('hero_auth', SCRIPT)
auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)

def main():
    path = HERE/'firmware/HERO-3107-IPMI-P5-R2-RC3-UNSIGNED.CAP'
    old = auth.ORIGINAL.read_bytes()
    new = path.read_bytes()
    oh, nh = auth.parse_capsule(old), auth.parse_capsule(new)
    assert oh == nh and old[:4096] == new[:4096]
    assert auth.sha(old) == auth.PIN_ORIGINAL
    original = auth.signatures(old, oh)
    candidate = auth.signatures(new, nh)
    assert original['firmware']['valid'] and original['certificate']['valid']
    assert candidate['certificate']['valid'] and not candidate['firmware']['valid']
    report = dict(passed_expected_results=True,
        scope='Local mathematical public-key verification, not a flash controller test',
        candidate_sha256=auth.sha(new), original_sha256=auth.sha(old),
        parser_sha256=auth.sha(SCRIPT.read_bytes()), original=original, rc3=candidate,
        official_capsule_header_unchanged=True,
        firmware_signature_valid=False, official_asus_release=False,
        interpretation='RC3 keeps the vendor header but the modified firmware is not ASUS-signed. No signature bypass or signing was performed.',
        flash_path='RC2 FlashBack success is user-reported. RC3 FlashBack acceptance and boot are pending onsite test; EZ Flash acceptance is not established.')
    (HERE/'authentication-verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('original','rc3')},indent=2))

if __name__ == '__main__': main()

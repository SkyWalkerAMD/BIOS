"""Isolated internal EXP03 review integration; not a flash or release package."""
from pathlib import Path
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
LAB = HERE.parent
CASE = LAB.parent
sys.path.insert(0,str(LAB))
from build_asus_review import build, SOURCE, SOURCE_SHA


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    driver = CASE/'review/flash_readiness/late_attach_candidate/build/AiTweakerLock1904.efi'
    output = HERE/'W790E-SAGE-SE-1904-lock-EXP03-EBS-SESSION-UNSIGNED.review.bin'
    assert not output.exists(), 'Preserve existing review result'
    pins = {
        driver:'e41ac0009a5658aff0546e637d0cf89a16edd1d16d726ee97dadf675f46c67d1',
        SOURCE:SOURCE_SHA,
        CASE/'driver/build/AiTweakerLock1904.efi':'da52a08f0e477867f4f08e3d1514b156be1ac67fa3bc9c47d09272a869aaf2e2',
        CASE/'review/flash_readiness/ebs_candidate/build/AiTweakerLock1904.efi':'93237af8b9b59437f0135524d8283c4685f6f454e3050c0ed6dc5a6495387c80',
        LAB/'asus_review_exp02/W790E-SAGE-SE-1904-lock-EXP02.review.bin':'95a95856ae9ed393c8ab313ae7763edf9d30534f423f77c894d11d7be6a46a0e',
        CASE/'review/flash_readiness/late_attach_candidate/candidate_summary.json':'422116aa5d137477af0621f5b2ffc0916e3ba58802a5fb5404bc5962a4851aac',
        CASE/'review/flash_readiness/late_attach_build_binding_review.json':'03f62e0f0c33164a49b1b146b62e2ea5249aa7cdfdb315e2ffb89c0178a39e78',
    }
    for p,h in pins.items():
        assert sha(p)==h,str(p)
    attempt = {
        'purpose':'INTERNAL UNSIGNED REVIEW ONLY; NOT A FORMAL OR FLASH-READY BIOS',
        'inputs':{str(p):h for p,h in pins.items()},
        'recipe_sha256':sha(LAB/'build_asus_review.py'),
        'ffs_builder_sha256':sha(LAB/'inject_ovmf.py'),
        'wrapper_sha256':sha(Path(__file__)),
        'output':str(output),
        'integrated_changes':'Frozen late-attach/session-owner candidate including preserved EBS cleanup fix',
        'capsule_signing_performed':False,'hardware_test_performed':False,'root_package_published':False,
    }
    try:
        report=build(driver,output)
        attempt['status']='BUILT_PENDING_INDEPENDENT_STRUCTURE_VERIFICATION'
        attempt['result_sha256']=report['candidate_sha256']
        attempt['manifest']=str(output.with_suffix('.json'))
    except Exception as exc:
        attempt['status']='STOPPED_NO_APPROVED_IMAGE'
        attempt['error']=type(exc).__name__+': '+str(exc)
        (HERE/'build_attempt.json').write_text(json.dumps(attempt,indent=2)+'\n',encoding='utf8')
        raise
    for p,h in pins.items():
        assert sha(p)==h,str(p)
    attempt['all_inputs_unchanged_after_build']=True
    (HERE/'build_attempt.json').write_text(json.dumps(attempt,indent=2)+'\n',encoding='utf8')
    print(json.dumps(attempt,indent=2))


if __name__=='__main__':
    main()

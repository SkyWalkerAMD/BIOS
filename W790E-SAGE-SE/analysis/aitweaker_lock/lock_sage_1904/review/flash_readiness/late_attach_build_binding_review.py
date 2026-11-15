"""Independent read-only final late-attach candidate artifact binding."""
from pathlib import Path
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
CASE = HERE.parents[1]
CAND = HERE/'late_attach_candidate'
PIN = 'e41ac0009a5658aff0546e637d0cf89a16edd1d16d726ee97dadf675f46c67d1'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf8'))


def main():
    summary = read(CAND/'candidate_summary.json')
    assert sha(CAND/'candidate_summary.json') == '422116aa5d137477af0621f5b2ffc0916e3ba58802a5fb5404bc5962a4851aac'
    assert summary['candidate_driver_sha256'] == PIN
    assert summary['hardware_acceptance_inherited'] is False
    checked = {}
    for path, expected in summary['files'].items():
        actual = sha(CAND/path)
        assert actual == expected, path
        checked[str((CAND/path).relative_to(CASE))] = actual
    build = read(CAND/'build/build.json')
    source = read(CAND/'source_manifest.json')
    assert build['candidate_driver_sha256'] == sha(CAND/'build/AiTweakerLock1904.efi') == PIN
    assert build['hardware_acceptance_inherited'] is False
    assert build['candidate_sources'] == source['candidate_sources'] == summary['source_sha256']
    for name, expected in source['baseline_sources'].items():
        assert sha(CASE/name)==expected, name
    for name, expected in source['candidate_sources'].items():
        assert sha(CAND/name)==expected, name
    objects = {}
    for name, expected in build['object_sha256'].items():
        assert sha(CASE/name)==expected, name
        objects[name] = expected
    assert len(objects)==10
    local = [p for p in objects if p.startswith('review\\')]
    assert {Path(p).name for p in local} == {'platform.obj','hii.obj','ui.obj','services.obj'}
    assert len(objects)-len(local)==6
    link = build['commands'][-1]
    assert [Path(p).resolve() for p in link if p.endswith('.obj')] == [ (CASE/p).resolve() for p in objects ]
    assert '/timestamp:0' in link and '/subsystem:efi_boot_service_driver' in link and '/entry:efi_main' in link
    old_h = (CASE/'driver/lock.h').read_text()
    new_h = (CAND/'lock.h').read_text()
    normalized_h = new_h.replace('#include "../../../core/password_core.h"','#include "../core/password_core.h"').replace('int platform_session_owned(void);\n','').replace('int platform_can_enter(void);\n','')
    assert normalized_h == old_h, 'Unexpected header ABI/type change'
    # Verify the EBS implementation portion is identical to the reviewed candidate.
    old_services = (HERE/'ebs_candidate/services.c').read_text()
    new_services = (CAND/'services.c').read_text()
    marker = 'static int update_runtime_set'
    assert marker in old_services and marker in new_services
    ebs_tail = old_services[old_services.index(marker):]
    assert new_services[new_services.index(marker):] == ebs_tail
    regress = read(CAND/'full_regression/summary.json')
    assert regress['candidate_driver_sha256']==PIN and regress['hardware_acceptance_inherited'] is False
    assert regress['candidate_build_manifest_sha256']==sha(CAND/'build/build.json')
    assert regress['build_context_sha256']==sha(CAND/'full_regression/build_context.json')
    assert regress['runner_sha256']==sha(CAND/'run_full_regression.py')
    reports = []
    for row in regress['tests']:
        assert row['status']=='PASS'
        assert sha(CAND/'full_regression'/row['test'])==row['adapted_test_sha256']
        assert sha(CASE/'driver'/row['test'])==row['original_test_sha256']
        path=Path(row['report'])
        assert path.resolve().is_relative_to(CAND.resolve())
        assert sha(path)==row['report_sha256']
        report=read(path)
        assert PIN in (report.get('driver_sha256'),report.get('efi_sha256'),report.get('driver_efi_sha256')), str(path)
        reports.append(row)
    assert [r['checks_or_cases'] for r in reports]==[36,12,10,8,6357,131]
    extra=[]
    for name, count in [('late_attach_regression.json',269),('ebs_regression.json',83)]:
        r=read(CAND/name)
        assert PIN in (r.get('candidate_driver_sha256'),r.get('driver_sha256'),r.get('efi_sha256')), name
        actual=r.get('checks',r.get('cases'))
        assert actual==count,(name,actual)
        assert str(r['status']).startswith('PASS')
        extra.append({'path':str(CAND/name),'sha256':sha(CAND/name),'checks':count,'driver_sha256':PIN})
    preserved={
        'driver/build/AiTweakerLock1904.efi':'da52a08f0e477867f4f08e3d1514b156be1ac67fa3bc9c47d09272a869aaf2e2',
        'review/flash_readiness/ebs_candidate/build/AiTweakerLock1904.efi':'93237af8b9b59437f0135524d8283c4685f6f454e3050c0ed6dc5a6495387c80',
        'lab/asus_review_exp02/W790E-SAGE-SE-1904-lock-EXP02.review.bin':'95a95856ae9ed393c8ab313ae7763edf9d30534f423f77c894d11d7be6a46a0e',
    }
    for name, expected in preserved.items():
        assert sha(CASE/name)==expected, name
    result={
        'status':'PASS_INDEPENDENT_ARTIFACT_BINDING_NOT_A_RUNTIME_OR_FLASH_ACCEPTANCE',
        'driver_sha256':PIN,'candidate_summary_sha256':sha(CAND/'candidate_summary.json'),
        'script_sha256':sha(Path(__file__)),
        'candidate_files_verified':checked,'objects_verified':objects,
        'changed_objects':sorted(Path(p).name for p in local),'original_objects_unchanged':6,
        'header_changes':'Include relocation plus two function declarations only; data types, structs and ABI definitions unchanged.',
        'ebs_implementation_tail_sha256':hashlib.sha256(ebs_tail.encode()).hexdigest(),
        'ebs_implementation_tail_identical':True,
        'six_regression_report_bindings':reports,'new_regression_report_bindings':extra,
        'preserved_artifacts':preserved,'hardware_acceptance_inherited':False,
        'limits':[
            'Read-only artifact and link/source-map audit; did not execute tests again, compile/relink or execute an EFI entry.',
            'HII ABI suite explicitly seeds owned-session fixture before its existing assertions; it is not identical fixture setup to EXP02.',
            'All counts refer to local simulations with the tests documented stubs, not native platform boot or real NVRAM writes.',
            *summary['unresolved'],
        ],
    }
    out=HERE/'late_attach_build_binding_review.json'
    out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'report':str(out),'sha256':sha(out),'status':result['status']}))


if __name__=='__main__':
    main()

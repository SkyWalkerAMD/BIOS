"""Retarget the narrow EBS fixture without changing any tested driver object."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / 'ebs_candidate'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    summary = json.loads((HERE / 'candidate_summary.json').read_text(encoding='utf-8'))
    for name, digest in summary['files'].items():
        assert sha(HERE / name) == digest, name
    original = json.loads((OLD / 'candidate_summary.json').read_text(encoding='utf-8'))
    for name in ('ovmf_handoff.c', 'run_ovmf_handoff.py'):
        assert sha(OLD / name) == original['artifact_sha256'][name]

    source = (OLD / 'ovmf_handoff.c').read_text(encoding='utf-8')
    marker = 'void end_platform(void) {} /* Navigation is absent from this EBS-only fixture. */'
    assert source.count(marker) == 1
    source = source.replace(marker, marker + '''
/* This fixture never invokes navigation, password management or variable writes.
 * No owned browser is provided. These explicit stubs resolve the new services
 * object's owner checks; they do not claim to test ASUS session ownership. */
int platform_session_owned(void) {return 0;}
int platform_can_enter(void) {return 0;}
''')
    (HERE / 'ovmf_handoff.c').write_text(source, encoding='utf-8')

    runner = (OLD / 'run_ovmf_handoff.py').read_text(encoding='utf-8')
    replacements = {
        "OUT=HERE/'build'": "OUT=HERE/'ovmf_build';OUT.mkdir(exist_ok=True)",
        "'-I',str(DRIVER),": "'-I',str(HERE),'-I',str(DRIVER),",
        "OUT/'ovmf_handoff.obj',OUT/'services.obj'": "OUT/'ovmf_handoff.obj',HERE/'build/services.obj'",
        "sha(OUT/'services.obj')": "sha(HERE/'build/services.obj')",
        "No ASUS navigation, physical boot, or hardware flash claim.":
            "Owner predicates are explicit false stubs; no navigation or password writes run. No ASUS navigation, physical boot, or hardware flash claim.",
    }
    for before, after in replacements.items():
        assert runner.count(before) == 1, before
        runner = runner.replace(before, after)
    check = "assert sha(HERE/'services.c')==build['candidate_source_sha256']"
    assert runner.count(check) == 1
    runner = runner.replace(check, check + '''
for object_path, digest in build['object_sha256'].items():
 assert sha(CASE/object_path)==digest,object_path
assert sha(HERE/'build/AiTweakerLock1904.efi')==build['candidate_driver_sha256']
''')
    (HERE / 'run_ovmf_handoff.py').write_text(runner, encoding='utf-8')
    (HERE / 'ovmf_handoff_binding.json').write_text(json.dumps({
        'purpose': 'Retarget exact new services.obj to existing isolated OVMF EBS fixture.',
        'candidate_driver_sha256': summary['candidate_driver_sha256'],
        'original_source_sha256': sha(OLD / 'ovmf_handoff.c'),
        'original_runner_sha256': sha(OLD / 'run_ovmf_handoff.py'),
        'fixture_source_sha256': sha(HERE / 'ovmf_handoff.c'),
        'runner_sha256': sha(HERE / 'run_ovmf_handoff.py'),
        'services_obj_sha256': sha(HERE / 'build/services.obj'),
        'changes': ['Output directories and include paths target the isolated late-attach candidate.',
                    'All original EBS assertions retained; no navigation test added.',
                    'Two explicit false ownership stubs resolve services.obj dependencies.',
                    'All candidate linked-object hashes are checked before compile/link.'],
        'firmware_upload_or_flash': False,
    }, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('Prepared exact-object OVMF handoff fixture; no driver or old fixture modified.')

if __name__ == '__main__':
    main()

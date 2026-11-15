"""Re-run fixed verifier and explicit container-order / header negatives."""
from pathlib import Path
import contextlib
import io
import json
import os
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
import audit_rc5 as a


def repack(original, parsed, order, replacement=None):
    replacement = replacement or {}
    result = bytearray(parsed['header'])
    for g in order:
        result.extend(b'\xff' * (a.aligned(len(result), 8) - len(result)))
        result.extend(replacement.get(g, parsed['files'][g]['data']))
    a.check(len(result) <= len(original), 'negative repack exceeds FV')
    result.extend(b'\xff' * (len(original) - len(result)))
    return bytes(result)


def main():
    names = ('build_candidate.py', 'verify_candidate.py', 'test_builder_guards.py')
    hashes = {n: a.sha((a.SOURCE / n).read_bytes()) for n in names}
    snapshot = a.OUT / ('fixed-source-' + hashes['verify_candidate.py'][:12])
    snapshot.mkdir(exist_ok=True)
    for n in names:
        (snapshot / n).write_bytes((a.SOURCE / n).read_bytes())
    builder = a.module('build_candidate', a.SOURCE / 'build_candidate.py')
    builder.HERE = a.OUT
    verifier = a.module('verify_candidate', a.SOURCE / 'verify_candidate.py')
    tests = a.module('final_root_guards', a.SOURCE / 'test_builder_guards.py')
    log = io.StringIO()
    run = unittest.TextTestRunner(stream=log, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(tests.GuardTests))
    (a.OUT / 'fixed-root-guard-tests.txt').write_text(log.getvalue())
    a.check(run.wasSuccessful(), 'root guards')
    source_report = json.loads((a.OUT / 'R3-REVIEW-ONLY/build-report.json').read_text())
    manifest = json.loads((a.OUT / 'review-manifest.json').read_text())
    candidate = a.ROOT / source_report['candidate']
    old, current, byte_audit = a.check_candidate(candidate)
    cases = []
    def verify_case(name, directory, expected):
        verdict = a.capture_verify(verifier, directory)
        cases.append(dict(name=name, expected=expected, accepted=verdict['accepted'],
                          passed=verdict['accepted'] == expected,
                          detail=verdict.get('detail', ''), exception=verdict.get('exception', ''),
                          directory=str(directory.relative_to(a.ROOT))))
    verify_case('exact frozen R3 candidate', candidate.parent, True)
    for name in ('NEGATIVE-OLD-R2', 'NEGATIVE-P6-AS-SENSOR', 'NEGATIVE-WRAPPER-PREFIX'):
        verify_case(name, a.OUT / name, False)
    # Keep the original padding file first (FV extension metadata lives there).
    order = list(current['outer']['order'])
    order[2], order[3] = order[3], order[2]
    outer = repack(current['cap'][a.BASE:a.BASE + a.LENGTH], current['outer'], order)
    changed = current['cap'][:a.BASE] + outer + current['cap'][a.BASE + a.LENGTH:]
    directory = a.make_negative('NEGATIVE-OUTER-ORDER', changed, manifest, source_report)
    verify_case('existing outer FFS order changed', directory, False)
    # Change only the type of the compressed FV wrapper, preserving GUID/body
    # and all derived checksums. A verifier must not mistake it for valid FV_IMAGE.
    raw = bytearray(current['outer']['files'][a.WRAPPER]['data'])
    original_type = raw[18]
    raw[18] = 7 if original_type != 7 else 0x0B
    raw[16] = 0
    raw[16] = -(sum(raw[:16]) + sum(raw[18:23])) & 255
    outer = repack(current['cap'][a.BASE:a.BASE + a.LENGTH], current['outer'], current['outer']['order'], {a.WRAPPER: bytes(raw)})
    changed = current['cap'][:a.BASE] + outer + current['cap'][a.BASE + a.LENGTH:]
    directory = a.make_negative('NEGATIVE-WRAPPER-FILE-TYPE', changed, manifest, source_report)
    verify_case('wrapper FFS type changed', directory, False)
    # Direct approval tests ensure malformed manifest roles/identities never
    # approve an executable, independent of checks in read_image.
    good = a.entry(a.R3_FFS)
    modules = [('exact R3', [good], True), ('empty', [], False), ('duplicate', [good, good], False),
               ('unapproved inventory', [good, dict(good, role='inventory', guid=a.P6)], False)]
    for field, value in [('guid', a.P6), ('guid', a.WRAPPER), ('sha256', '0' * 64),
                         ('pe_sha256', '0' * 64), ('role', 'inventory'), ('role', 'unknown'),
                         ('path', '../not-an-artifact.ffs')]:
        modules.append(('approval ' + field + ':' + value, [dict(good, **{field: value})], False))
    for name, items, expected in modules:
        try:
            verifier.approved_modules(items)
            accepted, detail = True, ''
        except Exception as e:
            accepted, detail = False, type(e).__name__ + ': ' + str(e)
        cases.append(dict(name=name, accepted=accepted, expected=expected, passed=accepted == expected, detail=detail))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    for filename, arg in [('verify_candidate.py', a.OUT / 'NEGATIVE-P6-AS-SENSOR'),
                          ('build_candidate.py', a.OUT / 'review-manifest.json')]:
        proc = subprocess.run([sys.executable, '-O', '-X', 'utf8', str(a.SOURCE / filename), str(arg)],
                              capture_output=True, text=True, env=env)
        passed = proc.returncode != 0 and 'Optimized Python disables required assertions' in proc.stderr
        cases.append(dict(name=filename + ' refuses -O', passed=passed, returncode=proc.returncode, stderr=proc.stderr))
    current_hashes = {n: a.sha((a.SOURCE / n).read_bytes()) for n in names}
    result = dict(passed=all(c['passed'] for c in cases), cases=cases, source_hashes=hashes,
                  source_hashes_at_end=current_hashes, source_unchanged=hashes == current_hashes,
                  root_guards=run.testsRun, independent_container=byte_audit,
                  reviewed_wrapper_original_ffs_type=original_type,
                  no_hardware_access=True, no_parent_files_modified=True)
    a.save('final-regressions.json', result)
    print(json.dumps({'passed': result['passed'], 'cases': len(cases),
                      'failed': [c['name'] for c in cases if not c['passed']],
                      'source_unchanged': result['source_unchanged']}))


if __name__ == '__main__':
    main()

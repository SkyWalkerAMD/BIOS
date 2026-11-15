"""Independent selected replay; writes only this review directory.

Uses the author's declared outer-container/service fixtures, not their main()
or saved PASS results. Additional fault injection is explicitly non-normative:
it executes the real revocation callback inside modeled RaiseTPL. This does
not assert a conforming UEFI RaiseTPL normally dispatches ExitBootServices.
"""
from pathlib import Path
import sys, json, hashlib, time
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = BASE.parents[2]
sys.path[:0] = [str(ROOT / 'tools/pydeps'), str(ROOT / 'tools/vm-pydeps'),
               str(BASE / 'navigation07_exit')]
import verify_caller as c
import verify_tail as t
from unicorn.x86_const import UC_X86_REG_RIP

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def validate_manifest():
    p = BASE / 'navigation07_exit/component_manifest.json'
    j = json.loads(p.read_text())
    counts = {}
    for key in ['local_bindings', 'external_bindings']:
        rows = j[key]
        for row in rows:
            q = ROOT / row['path']
            assert sha(q) == row['sha256'], str(q)
            assert q.stat().st_size == row['bytes'], str(q)
        counts[key] = len(rows)
    return {'sha256': sha(p), 'counts': counts}

class FaultVM(t.VM):
    def __init__(self):
        super().__init__()
        self.end_during_raise = False
    def hook(self, u, address, size, opaque):
        if (getattr(self, 'end_during_raise', False) and
                address == self.oh['raise'] and self.arg(0) == 31):
            self.end_during_raise = False
            previous = self.current_tpl
            self.current_tpl = 31
            self.did_end = True
            self.nested(t.OS['no_end_boot'], [0, 0], previous)
            return
        return super().hook(u, address, size, opaque)

def main():
    initial = validate_manifest()
    cases = []
    begin = time.monotonic()
    v = c.VM()
    v.ready_full()
    v.tail(continuation=True, setup=lambda w: w.w(w.native_input + 8, b'\x01\0' + bytes([0x39]) * 22))
    assert len(v.resumes) == 1 and not v.faults
    assert v.input_resets == v.input_boundaries == 1
    assert not v.set_count and not v.free_trace and not v.form_callbacks
    expected = dict(v.before_state)
    app = bytearray(expected['app']); app[0x5a] = 0
    expected['app'] = bytes(app)
    assert v.resumes[0]['state'] == expected
    cases.append({'case': 'actual original B8DC caller through private loop, guard and next input',
                  'status': 'PASS', 'seconds': round(time.monotonic() - begin, 3),
                  'native_state_only_change': 'App+5A cleared; saved RAX restored to App; original zero-compare flags',
                  'input_boundary_rva': '0x61FE4'})
    begin = time.monotonic()
    v = t.VM(); v.ready_full()
    v.tail(setup=lambda w: w.w(w.native_rsp + 0xd8, t.Q(t.TSE + 0xb8e1)))
    assert not v.resumes and len(v.faults) == 1
    assert v.r(v.app + 0x5a, 1) == b'\x01' and not v.set_count
    cases.append({'case': 'wrong original stack anchor is refused before cancellation',
                  'status': 'PASS', 'reason': v.run('n07_last_reason'),
                  'seconds': round(time.monotonic() - begin, 3)})
    begin = time.monotonic()
    v = FaultVM(); v.ready_full(); v.end_during_raise = True
    result = v.run('n07_fault_wait')
    assert result == 2
    assert v.efi_after_end == [v.oh['restore']], v.efi_after_end
    assert not v.waits and not v.transcript and not v.set_count
    cases.append({'case': 'non-normative revocation inside modeled RaiseTPL in fault wait',
                  'status': 'REPRODUCED_SCOPED_HARDENING_GAP', 'result': result,
                  'post_revoke_service_calls': ['cached RestoreTPL'],
                  'continued_gui': False, 'output_or_wait_or_variable_write': False,
                  'seconds': round(time.monotonic() - begin, 3),
                  'interpretation': 'Does not prove ordinary UEFI can signal EBS from RaiseTPL. The new fault-wait source does not uphold a blanket no-service-after-revocation statement under this explicit boundary model.'})
    assert validate_manifest() == initial
    result = {'component_sha256': t.SHA, 'manifest': initial,
              'review_script_sha256': sha(Path(__file__)), 'cases': cases,
              'limits': ['Original BrowserLoop middle, outer native objects, UEFI services and CPU map remain author fixtures.',
                         'No owner=true is supplied; real private wrapper and exact consumer windows execute.',
                         'No BIOS installation, actual firmware services, physical ownership or full GUI tested.',
                         'This script does not change any frozen source or result.']}
    (HERE / 'selected_replay.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'component': t.SHA, 'cases': [x['status'] for x in cases], 'manifest': initial}))

if __name__ == '__main__': main()

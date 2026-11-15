"""Bounded original ACE Core replay; no candidate driver or device access.

Reuse the already-reviewed SAGE fixture, with allocator and reporter addresses
rebound from the actual ACE direct-call operands. All event/queue/TPL/EBS code
executed by Unicorn is taken from the pinned ACE image.
"""
import hashlib
import importlib.util
import json
import struct
import sys
import uuid
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import capstone
import pefile

FIXTURE = ROOT / 'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness/before_exit_core_support.py'
spec = importlib.util.spec_from_file_location('reviewed_sage_core_fixture', FIXTURE)
ref = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ref)
CORE = HERE / 'modules/OriginalDxeCore.efi'
CAP = ROOT / 'analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP'
PIN_CORE = '6259bedcef838d21e9f48a86e28ecea0e399c216681c7543cf727fa38023c6a7'
PIN_CAP = '03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29'


class AceHarness(ref.CoreHarness):
    def hook(self, uc, address, size, data):
        if address == ref.BASE + 0x1084c:
            self.executed_native.add(0x1084c)
            length = uc.reg_read(ref.x86.UC_X86_REG_RDX)
            ref.require(length == 0xb8, 'unexpected ACE event allocation size')
            pointer = self.heap
            self.heap += (length + 15) & ~15
            self.return_stub(pointer)
        elif address == ref.BASE + 0x111b8:
            self.executed_native.add(0x111b8)
            self.return_stub(0)
        else:
            # Ensure obsolete SAGE hook addresses cannot accidentally intercept
            # a different ACE instruction on these covered paths.
            ref.require(address not in (ref.BASE + 0x1083c, ref.BASE + 0x111a8),
                        'unexpected execution at obsolete SAGE stub target')
            super().hook(uc, address, size, data)


def evidence(label):
    path = HERE / 'core_rea/responses' / (label + '.json')
    outer = json.loads(path.read_text(encoding='utf-8'))
    return json.loads(outer['result']['content'][0]['text'])


def main():
    source = CORE.read_bytes()
    ref.require(ref.sha(source) == PIN_CORE, 'ACE Core SHA')
    ref.require(ref.sha(CAP.read_bytes()) == PIN_CAP, 'ACE official CAP SHA')
    inventory = json.loads((HERE / 'ace_original_module_inventory.json').read_text())
    original = ROOT / inventory['selected']['OriginalDxeCore']
    ref.require(original.read_bytes() == source, 'ACE original extraction mismatch')
    sage_core = FIXTURE.parent / 'runtime_navigation/OriginalDxeCore.efi'
    ref.require(ref.sha(sage_core.read_bytes()) == ref.PIN_CORE, 'SAGE comparison Core SHA')
    pe = pefile.PE(data=source)
    mapped = pe.get_memory_mapped_image()
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True
    rebindings = []
    for site, target in ((0x9465, 0x1084c), (0x26cd, 0x111b8)):
        ins = next(cs.disasm(mapped[site:site+15], site))
        ref.require(ins.mnemonic == 'call' and ins.operands[0].imm == target,
                    'ACE fixture rebinding must match native direct call')
        rebindings.append({'call_rva': hex(site), 'bytes': ins.bytes.hex(),
                           'target_rva': hex(target)})
    for offset, value in ((0x15e90 + 0xe8, 0x25a0), (0x15e90 + 0x170, 0x9328)):
        ref.require(struct.unpack_from('<Q', mapped, offset)[0] == value, 'BS function slot')
    for offset, value in ((0x15af0, ref.BEFORE), (0x15c20, ref.BEFORE),
                          (0x15be0, ref.EXIT), (0x159c0, ref.FAILED)):
        ref.require(mapped[offset:offset+16] == uuid.UUID(value).bytes_le, 'ACE event GUID')
    ref.require(mapped[0x15cc0] == 1, 'initial one-time flag')
    cases, registrations, visited = [], [], set()
    for scenario in ('first_valid', 'first_invalid_then_valid', 'two_invalid'):
        h = AceHarness(source)
        registrations.append({'scenario': scenario, 'events': [
            h.register('before16', ref.BEFORE, 16),
            h.register('before8', ref.BEFORE, 8),
            h.register('exit16', ref.EXIT, 16),
            h.register('failed16', ref.FAILED, 16),
            h.register('other16', ref.OTHER, 16),
        ]})
        if scenario == 'first_valid':
            c = h.ebs(0x1234, scenario)
            ref.assert_trace(c, ['before16', 'before8', 'before16', 'before8', 'exit16'], 1, 0)
            cases.append(c)
        else:
            c = h.ebs(0x1233, scenario + ':first_invalid')
            ref.assert_trace(c, ['before16', 'before8', 'before16', 'before8', 'exit16', 'failed16'], 1, ref.INVALID)
            cases.append(c)
            valid = scenario == 'first_invalid_then_valid'
            c = h.ebs(0x1234 if valid else 0x1233, scenario + ':retry')
            ref.assert_trace(c, [] if valid else ['failed16'], 0, 0 if valid else ref.INVALID)
            cases.append(c)
        visited.update(h.executed_native)
    ref.require({0x25d7, 0x25e3, 0x25fe, 0x92bc, 0xcd4c, 0x26a6}.issubset(visited),
                'required ACE native paths not exercised')
    ranges = {}
    for name, start, end in (('ExitBootServices', 0x25a0, 0x277f),
                             ('NotifySignalList', 0x9280, 0x92e4),
                             ('QueueEventNotification', 0x921c, 0x927d),
                             ('CreateEventEx', 0x9328, 0x955f),
                             ('RestoreTplAndDispatch', 0xcc98, 0xcdc4)):
        ranges[name] = [{'rva': hex(i.address), 'bytes': i.bytes.hex(),
                         'instruction': i.mnemonic + ' ' + i.op_str}
                        for i in cs.disasm(mapped[start:end], start)]
    records = []
    for label in ('002-exit-boot-services', '003-notify-signal-list',
                  '004-create-event-ex', '005-restore-tpl'):
        ev = evidence(label)
        ref.require(ev['subject']['digest']['sha256'] == PIN_CORE, 'REA source digest')
        records.append({'response': 'core_rea/responses/' + label + '.json',
                        'evidence_id': ev['evidence_id'], 'provider': ev['provider']})
    report = {
        'status': 'PASS_ACE_ORIGINAL_CORE_BEFORE_EXIT_DISPATCH',
        'script_sha256': ref.sha(Path(__file__).read_bytes()),
        'inputs': {
            'core': {'path': str(CORE), 'original_path': str(original), 'sha256': PIN_CORE, 'bytes': len(source)},
            'cap': {'path': str(CAP), 'sha256': PIN_CAP},
            'fixture': {'path': str(FIXTURE), 'sha256': ref.sha(FIXTURE.read_bytes())},
            'sage_core_comparison': {'path': str(sage_core), 'sha256': ref.PIN_CORE,
                                      'whole_image_equal': False},
        },
        'scope': {'device_access': False, 'candidate_driver_executed': False,
                  'production_files_changed': False,
                  'native': ['ACE original EBS', 'CreateEventEx', 'event list/queue', 'TPL dispatch'],
                  'test_doubles': ['zero allocator', 'status reporter', 'terminal CRC',
                                   'CPU and timer protocols', 'callback observers'],
                  'map_fixture': 'empty descriptor list; current/minimum accepted key 0x1234'},
        'fixture_rebindings_verified_against_ace_calls': rebindings,
        'rea_evidence': records,
        'observations': [
            'ACE and SAGE complete Core images differ; this report independently binds the ACE source.',
            'First EBS broadcasts the same Before group twice, at 0x25d7 and 0x25e3.',
            'TPL16 then TPL8 callbacks execute for each broadcast before timer stop at 0x25f4.',
            'Exit group is broadcast at 0x25fe; one-time flag 0x15cc0 is then cleared.',
            'An invalid first map key still runs these callbacks before EFI_INVALID_PARAMETER and failed-group callback.',
            'Retries never repeat Before/Exit or timer-stop. Corrected retry succeeds; invalid retry repeats only failed-group notification.',
        ],
        'driver_implications': [
            'Cleanup must be idempotent because first EBS dispatches Before callbacks twice.',
            'An invalid EBS attempt still retires the hooks; continuing Boot Services must not rearm retired state.',
            'Do not rely on a retry to trigger cleanup a second time.',
        ],
        'limitations': [
            'Bounded local native emulation is not an observation of the physical ACE machine.',
            'Does not validate candidate cleanup ownership or all firmware event registrants.',
            'Only the pinned ACE1904 source and listed scenarios are covered.',
        ],
        'registrations': registrations, 'native_emulation_cases': cases,
        'executed_native_rvas': [hex(v) for v in sorted(visited)], 'disassembly': ranges,
    }
    output = HERE / 'ace_before_exit_core_support.json'
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'output': str(output),
                      'sha256': ref.sha(output.read_bytes()), 'cases': len(cases),
                      'registrations': sum(len(r['events']) for r in registrations)}, indent=2))


if __name__ == '__main__':
    main()

"""Original ACE save caller evidence and bounded ABI/branch replay.

No patches are installed. Native caller tests deliberately substitute only the
save result, to establish what changing AL can and cannot repair. The original
save tail test starts at the identified commit call with explicit loop fixtures.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import capstone
import pefile
import unicorn
from unicorn import x86_const as x86

MODULE = ROOT / 'analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF/modules/AMITSE.efi'
PIN = '99ff85060750d39c9e1a861fd29c48726aa0c82f47b1ec7e6c12150836070ec5'
BASE, ARENA, STACK, STOP = 0x10000000, 0x20000000, 0x30000000, 0x40000000
sha = lambda data: hashlib.sha256(data).hexdigest()


def record(i):
    return {'rva': hex(i.address), 'bytes': i.bytes.hex(),
            'instruction': i.mnemonic + ' ' + i.op_str}


def ev(label):
    out = json.loads((HERE / 'responses' / (label + '.json')).read_text())
    return json.loads(out['result']['content'][0]['text'])


class Fixture:
    def __init__(self, source):
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        pe = pefile.PE(data=source)
        pe.relocate_image(BASE)
        mapped = pe.get_memory_mapped_image()
        self.uc.mem_map(BASE, (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095)
        self.uc.mem_write(BASE, mapped)
        self.uc.mem_map(ARENA, 0x10000)
        self.uc.mem_map(STACK, 0x20000)
        self.uc.mem_map(STOP, 0x1000)
        self.uc.mem_write(STOP, b'\xc3')
        self.calls = []
        self.native = []
        self.stubs = {}
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.hook)
        self.q(BASE + 0x82748, ARENA)
        self.uc.mem_write(BASE + 0x82738, b'\x7a')
        self.uc.mem_write(BASE + 0x82740, b'\x00\x00')

    def q(self, address, value):
        self.uc.mem_write(address, struct.pack('<Q', value))

    def hook(self, uc, address, size, data):
        if address == STOP:
            uc.emu_stop()
            return
        self.native.append(address - BASE)
        if address - BASE in self.stubs:
            rva = address - BASE
            value = self.stubs[rva]
            self.calls.append({'rva': hex(rva), 'stub_result': hex(value)})
            rsp = uc.reg_read(x86.UC_X86_REG_RSP)
            ret = struct.unpack('<Q', uc.mem_read(rsp, 8))[0]
            uc.reg_write(x86.UC_X86_REG_RAX, value)
            uc.reg_write(x86.UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(x86.UC_X86_REG_RIP, ret)

    def run(self, rva):
        self.uc.emu_start(BASE + rva, STOP + 1, timeout=1_000_000, count=20000)
        assert self.uc.reg_read(x86.UC_X86_REG_RIP) == STOP
        return self.uc.reg_read(x86.UC_X86_REG_RAX)

    def caller(self, rva, result):
        self.stubs = {0x142ac: result}
        rsp = STACK + 0x1f000 - 8
        self.q(rsp, STOP)
        self.uc.reg_write(x86.UC_X86_REG_RSP, rsp)
        self.uc.reg_write(x86.UC_X86_REG_RCX, ARENA)
        ret = self.run(rva)
        return {'entry_rva': hex(rva), 'substituted_save_boolean': result,
                'native_return': hex(ret), 'exit_byte': self.uc.mem_read(ARENA + 0x5a, 1)[0],
                'reset_flags_82740_82741': list(self.uc.mem_read(BASE + 0x82740, 2)),
                'state_82738_before': 0x7a, 'state_82738_after': self.uc.mem_read(BASE + 0x82738, 1)[0],
                'stub_calls': self.calls, 'native_rvas': [hex(x) for x in self.native]}

    def commit_tail(self, result):
        self.stubs = {0x111b4: result, 0x5ab8: 0, 0x64e4: 0, 0x29d14: 0}
        rsp = STACK + 0x10000
        self.q(rsp + 0x98 + 8 * 8, STOP)
        self.q(BASE + 0x92278, ARENA + 0x1000)
        self.uc.mem_write(ARENA + 0x1000, struct.pack('<I', 1))
        for reg, value in ((x86.UC_X86_REG_RSP, rsp), (x86.UC_X86_REG_RBP, rsp + 0x79),
                           (x86.UC_X86_REG_R12, 0), (x86.UC_X86_REG_R13, 1),
                           (x86.UC_X86_REG_R14, 0), (x86.UC_X86_REG_R15, ARENA + 0x2000)):
            self.uc.reg_write(reg, value)
        ret = self.run(0x1489a)
        assert ret & 255 == 1
        return {'entry_rva': '0x1489a', 'substituted_commit_status': hex(result),
                'native_save_return': hex(ret), 'native_save_AL': ret & 255,
                'stub_calls': self.calls, 'native_rvas': [hex(x) for x in self.native]}


def main():
    source = MODULE.read_bytes()
    assert sha(source) == PIN
    pe = pefile.PE(data=source)
    mapped = pe.get_memory_mapped_image()
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail, cs.skipdata = True, True
    targets = {0x111b4, 0x1427c, 0x142ac, 0x330f8, 0x44060, 0x44090, 0x440fc}
    calls, pointers = [], []
    for section in pe.sections:
        if section.Characteristics & 0x20000000:
            start = section.VirtualAddress
            end = start + min(section.Misc_VirtualSize, section.SizeOfRawData)
            for i in cs.disasm(mapped[start:end], start):
                if i.id and i.mnemonic in ('call', 'jmp') and i.operands[0].type == capstone.x86.X86_OP_IMM:
                    if i.operands[0].imm in targets:
                        calls.append(record(i) | {'target': hex(i.operands[0].imm)})
    for block in pe.DIRECTORY_ENTRY_BASERELOC:
        for item in block.entries:
            if item.type == 10:
                value = struct.unpack_from('<Q', mapped, item.rva)[0] - pe.OPTIONAL_HEADER.ImageBase
                if value in targets:
                    pointers.append({'slot_rva': hex(item.rva), 'target': hex(value),
                                     'original_8bytes': mapped[item.rva:item.rva+8].hex()})
    prologues = []
    for name, entry, length in (('SaveIterator', 0x142ac, 18), ('VariableCommit', 0x111b4, 22)):
        items = list(cs.disasm(mapped[entry:entry+length], entry))
        assert sum(i.size for i in items) == length
        assert all(i.id and i.mnemonic not in ('call', 'jmp', 'ret') for i in items)
        assert all(not (op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP)
                   for i in items for op in i.operands)
        prologues.append({'name': name, 'entry_rva': hex(entry), 'whole_instruction_bytes': length,
                          'original_bytes': mapped[entry:entry+length].hex(),
                          'resume_rva': hex(entry+length), 'instructions': [record(i) for i in items],
                          'position_independent_stolen_instructions': True,
                          'no_patch_installed': True})
    caller_rows = []
    for name, entry in (('F10', 0x330f8), ('ExitActionSaveExit', 0x44060),
                         ('ExitActionSaveReset', 0x44090), ('ExitActionSaveStay', 0x440fc)):
        for result in (0, 1):
            row = Fixture(source).caller(entry, result)
            row['name'] = name
            assert row['exit_byte'] == (0 if name.endswith('Stay') else result)
            assert row['reset_flags_82740_82741'] == ([0, result] if name.endswith('Stay') else [result, result])
            assert row['state_82738_after'] == (0 if name.endswith('Stay') else 0x7a)
            caller_rows.append(row)
    tail_rows = [Fixture(source).commit_tail(s) for s in (0, 0x8000000000000007, 0x800000000000000f)]
    evidence = []
    for label in ('004-save-iterator', '005-variable-commit', '006-f10-save-exit',
                  '007-vendor-initializer', '008-save-stay'):
        item = ev(label)
        assert item['subject']['digest']['sha256'] == PIN
        evidence.append({'label': label, 'evidence_id': item['evidence_id'],
                         'incoming_ref_sites': [r['source_address'] for r in item['normalized_result']['incoming_references']],
                         'relationship_coverage': item['relationship_coverage']})
    ranges = {}
    for name, start, end in (('Commit', 0x111b4, 0x11258), ('SaveWrapper', 0x1427c, 0x142a9),
                             ('SaveIterator', 0x142ac, 0x148f3), ('SaveActions', 0x44060, 0x4412f),
                             ('Initializer', 0x5ef44, 0x5efa4)):
        ranges[name] = [record(i) for i in cs.disasm(mapped[start:end], start)]
    report = {
        'status': 'PASS_ORIGINAL_ACE_SAVE_BRANCH_EVIDENCE_DESIGN_ONLY',
        'module': {'path': str(MODULE), 'sha256': PIN},
        'script_sha256': sha(Path(__file__).read_bytes()),
        'no_production_mutation_or_device_access': True,
        'direct_calls_linear_original_inventory': calls,
        'relocated_function_pointers': pointers, 'candidate_trampoline_spans': prologues,
        'rea_evidence': evidence,
        'original_commit_tail_replays': tail_rows,
        'original_caller_branch_replays_with_substituted_save_AL': caller_rows,
        'minimum_change_design': {
            'phase_1_denial_feedback': [
                'Wrap the common SaveIterator entry 0x142ac using its verified original 18-byte prologue and a register-preserving trampoline to 0x142be.',
                'Push a bounded per-invocation scope; save the previous scope, owner token and first failure. A scope records results and never grants authorization.',
                'Mark the active scope at an existing guard denial, without suppressing the original native iterator or unrelated variable calls.',
                'Call the complete original SaveIterator exactly once with all original ABI inputs; on a recorded denial force only its BOOLEAN result false. On no denial retain its original result.',
                'Unwind the scope on every return and propagate nested failure to the owning parent. Never reuse a previous attempt failure for a later save.',
                'Do not reject every scope without a UI session: original vendor initialization at 0x5ef85 uses this same entry. Existing write policy still decides authorization.',
            ],
            'optional_broader_backend_feedback': [
                'If policy expands to backend EFI_ERROR feedback, wrap VariableCommit entry 0x111b4 with the verified 22-byte prologue to 0x111ca; call the complete original routine and return its status unchanged.',
                'Record only selected in-scope failures after the original call. Cover all direct callers and relocation pointer 0x7ab58 by intercepting the common entry, not a single call site.',
                'The iterator also has direct RT.SetVariable calls for BootOrder/DriverOrder. A commit-only wrapper cannot aggregate those failures; use the existing Runtime guard if broader all-variable reporting is required.',
                'Broader error aggregation changes legacy semantics and needs explicit success/error cases for HII routing, optional variables and initialization. It is not required for the smallest deliberate guard-denial fix.',
            ],
            'save_stay_followup': [
                'AL false preserves pending flag 0x82741, but native SaveStay unconditionally clears 0x82738. A common iterator wrapper cannot restore a write that occurs after it returns.',
                'The identified SaveStay dispatch slot is 0x6bb18 -> 0x440fc. An owner-checked wrapper around that callback could snapshot only proven state and restore it after a denied attempt; this is a separate change requiring UI/native replay.',
                'Do not claim complete SaveStay graphical feedback or transactional rollback from phase 1 alone.',
            ],
            'publication_and_cleanup': [
                'Precheck whole-module identity and all stolen bytes; construct executable trampolines before any entry publication.',
                'Commit all related pointers/entries transactionally with reverse rollback and exact readback; any partial or foreign mutation makes the installation terminal.',
                'BeforeExit cleanup must restore only still-owned entries and retain reachable trampoline storage on any ownership conflict. Integrate new hooks into existing retire state.',
                'Before applying entry hooks, verify no discovered incoming reference lands inside stolen spans and validate forwarding ABI, stack alignment, nonvolatile registers and recursion behavior.',
            ],
        },
        'limitations': [
            'This is a design and original-binary observation, not an implemented or accepted native feedback patch.',
            'Caller tests explicitly substitute save AL; tail tests explicitly substitute per-variable status and OEM callbacks. They do not execute a candidate wrapper.',
            'Linear section scan supplements REA known-function references; REA missed the unseeded SaveReset function. Indirect/runtime callers remain nonexhaustive.',
            'Commit failures can follow successful unrelated writes; false feedback does not roll back NVRAM or in-memory caches.',
            'The original save tail still runs post-save OEM callbacks, whose full live side effects require later validation.',
        ],
        'disassembly': ranges,
    }
    out = HERE / 'ace_save_hook_design.json'
    out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'output': str(out), 'sha256': sha(out.read_bytes()),
                      'direct_calls': len(calls), 'pointer_slots': len(pointers),
                      'caller_cases': len(caller_rows), 'tail_cases': len(tail_rows)}, indent=2))


if __name__ == '__main__':
    main()

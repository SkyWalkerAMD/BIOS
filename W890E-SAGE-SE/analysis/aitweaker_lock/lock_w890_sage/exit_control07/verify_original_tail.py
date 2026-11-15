"""Actual original BrowserLoop tail; explicit service/cleanup return models.

No binary patches, password operations, BMC access, or firmware writes.
This checks where cancellation can still precede original teardown effects.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import pefile
import capstone
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.x86_const import *

ORIGINAL = BASE / 'navigation/modules/AMITSE.efi'
DIGEST = '43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
assert hashlib.sha256(ORIGINAL.read_bytes()).hexdigest() == DIGEST
TSE, DATA, STACK = 0x28000000, 0x50000000, 0x60000000
APP, BS, RT, HOOKS = DATA, DATA + 0x1000, DATA + 0x2000, DATA + 0x3000
PE = pefile.PE(str(ORIGINAL))
CODE = PE.get_data(0x1995f, 0x130)
assert CODE[:16].hex() == '488b056a64090038585a0f8490fdffff'
PE.relocate_image(TSE)
MAPPED = PE.get_memory_mapped_image().ljust(PE.OPTIONAL_HEADER.SizeOfImage, b'\0')
ERR = lambda n: (1 << 63) | n
REGS = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]

def run(name, exit_requested, reset_requested, cleanup_status, locate_status=0,
        bypass_reset=False, render_buffer=True, history=True):
    u = Uc(UC_ARCH_X86, UC_MODE_64)
    u.mem_map(TSE, len(MAPPED)); u.mem_write(TSE, MAPPED)
    u.mem_map(DATA, 0x10000); u.mem_map(STACK, 0x10000)
    def w64(a, x): u.mem_write(a, struct.pack('<Q', x))
    def r64(a): return struct.unpack('<Q', u.mem_read(a, 8))[0]
    def ret(value):
        sp = u.reg_read(UC_X86_REG_RSP)
        u.reg_write(UC_X86_REG_RAX, value)
        u.reg_write(UC_X86_REG_RIP, r64(sp))
        u.reg_write(UC_X86_REG_RSP, sp + 8)
    services = {HOOKS: 'FreePool', HOOKS + 0x10: 'UninstallProtocolInterface',
                HOOKS + 0x20: 'LocateProtocol', HOOKS + 0x30: 'ResetSystem'}
    for address in services: u.mem_write(address, b'\xc3')
    w64(BS + 0x48, HOOKS); w64(BS + 0x150, HOOKS + 0x10)
    w64(BS + 0x140, HOOKS + 0x20); w64(RT + 0x68, HOOKS + 0x30)
    for off, value in {0xafbc8: BS, 0xafbd8: RT, 0xafdd0: APP,
                       0xbaab8: DATA + 0x4000, 0xbaa68: int(bypass_reset),
                       0xafde8: DATA + 0x6000 if history else 0}.items():
        w64(TSE + off, value)
    u.mem_write(TSE + 0xafdc8, bytes([bool(reset_requested)]))
    u.mem_write(TSE + 0xafe00, struct.pack('<I', 7))
    u.mem_write(TSE + 0xafddc, struct.pack('<I', 9))
    u.mem_write(APP + 0x5a, bytes([bool(exit_requested)]))
    u.mem_write(APP + 0x28, struct.pack('<I', 1))
    rsp, rbp = STACK + 0x8000, STACK + 0x8100
    u.reg_write(UC_X86_REG_RSP, rsp); u.reg_write(UC_X86_REG_RBP, rbp)
    u.reg_write(UC_X86_REG_RBX, 0)
    u.reg_write(UC_X86_REG_R15, DATA + 0x5000 if render_buffer else 0)
    w64(rbp + 0x7f, ERR(14))
    calls, writes, executed = [], [], []
    stopped = None
    def hook(uc, address, size, opaque):
        nonlocal stopped
        if address in (TSE + 0x196ff, TSE + 0x19a7b):
            stopped = hex(address - TSE); uc.emu_stop(); return
        if TSE + 0x1995f <= address <= TSE + 0x19a76:
            executed.append(address - TSE); return
        args = [uc.reg_read(r) for r in REGS]
        if address in services:
            op = services[address]; calls.append({'operation': op, 'arguments': args})
            if op == 'ResetSystem': stopped = op; uc.emu_stop(); return
            ret(locate_status if op == 'LocateProtocol' else 0); return
        if address in (TSE + 0x64b2c, TSE + 0xfd18, TSE + 0x748c):
            op = {0x64b2c: 'render_cleanup', 0xfd18: 'OEM_callback', 0x748c: 'cleanup_model'}[address - TSE]
            calls.append({'operation': op, 'arguments': args})
            ret(cleanup_status if op == 'cleanup_model' else 0); return
        raise AssertionError(('unmodelled original execution', hex(address)))
    def onwrite(uc, access, address, size, value, opaque):
        if TSE <= address < TSE + len(MAPPED):
            writes.append({'rva': hex(address - TSE), 'bytes': size, 'value': value})
    u.hook_add(UC_HOOK_CODE, hook); u.hook_add(UC_HOOK_MEM_WRITE, onwrite)
    u.emu_start(TSE + 0x1995f, TSE + 0x19a8f, count=300)
    ops = [x['operation'] for x in calls]
    if not exit_requested:
        assert stopped == '0x196ff' and not calls and not writes
    elif reset_requested and not bypass_reset:
        assert stopped == 'ResetSystem'
        assert ops.index('UninstallProtocolInterface') < ops.index('cleanup_model') < ops.index('ResetSystem')
        assert calls[-1]['arguments'][0] == (1 if locate_status >> 63 else 0)
        assert sum(x == 'cleanup_model' for x in ops) == 1
    else:
        assert stopped == '0x19a7b' and ops[-1] == 'cleanup_model'
        assert u.reg_read(UC_X86_REG_RAX) == cleanup_status
        assert any(x['rva'] == '0xbaab8' for x in writes)
        assert any(x['rva'] == '0xafe00' for x in writes)
        assert any(x['rva'] == '0xafddc' for x in writes)
    assert r64(TSE + 0xafdd0) == APP, 'Cleanup callee is a return-value model, not a destructor model.'
    return {'name': name, 'passed': True, 'stop': stopped, 'cleanup_return_model': hex(cleanup_status),
            'calls': calls, 'original_image_writes': writes, 'instruction_rvas': [hex(x) for x in executed]}

def main():
    checks = [run('No exit request returns to original input loop before teardown', False, True, ERR(15))]
    for status in (0, ERR(1), ERR(15)):
        checks.append(run('Reset branch ignores cleanup status ' + hex(status), True, True, status))
        checks.append(run('Normal exit returns cleanup status after earlier teardown ' + hex(status), True, False, status))
    checks += [run('Locate failure selects warm reset despite cleanup refusal', True, True, ERR(15), ERR(14)),
               run('Native BAA68 branch suppresses reset but retains normal teardown', True, True, ERR(15), bypass_reset=True),
               run('No optional buffers does not avoid protocol teardown before refusal', True, False, ERR(15), render_buffer=False, history=False)]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    (HERE / 'original_tail.asm.txt').write_text('\n'.join(f'{x.address:05x} {x.bytes.hex():24} {x.mnemonic} {x.op_str}' for x in md.disasm(CODE, 0x1995f)) + '\n')
    report = {'status': 'ORIGINAL_CONTROL_FLOW_OBSERVATIONS_NOT_A_PATCH', 'passed': True,
              'original_sha256': DIGEST, 'count': len(checks), 'checks': checks,
              'models': ['UEFI FreePool, UninstallProtocolInterface, LocateProtocol and ResetSystem are observations only.',
                         'Native render/OEM callees return zero without executing their bodies.',
                         'Native 748C body is replaced by the stated return-value model; no destructor behavior is claimed.',
                         'Input-loop continuation and function epilogue are stop boundaries.'],
              'findings': ['Returning failure from 748C does not suppress the reset branch.',
                           'Both normal and reset paths have performed earlier native protocol teardown before 748C.',
                           'The 1995F flag check reaches 196FF without tail effects when exit flag equals zero.',
                           'A production cancellation guard must validate ownership and run before tail effects; this script supplies no such guard.']}
    (HERE / 'original_tail_tests.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'count': len(checks), 'report': str(HERE / 'original_tail_tests.json')}))

if __name__ == '__main__': main()

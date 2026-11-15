"""Bounded original-code replay; no hardware, firmware writes or trust changes.

Uses the root selected by the exact official PEI FV. It does not assert that
this root was read from the live customized machine. No capsule signature is
stubbed as successful: positive chain traversal stops before the first hash.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

BASE = Path(__file__).resolve().parent
ROOT = next(p for p in BASE.parents if (p / 'tools/pydeps').is_dir())
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP

CASE = BASE.parent
NATIVE = CASE / 'update_path_reference/native_inputs'
OFFICIAL = ROOT / 'analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP'
ENGINEERING = CASE / 'engineering_signature/W790-ACE-1904-CANDIDATE05-ENGINEERING-NONOEM-NOT-FLASH-READY.CAP'
CRYPTO = NATIVE / 'CryptoSMM-2ad511c7-0.efi'
SECFLASH = NATIVE / 'SecSMIFlash-3370a4bd-0.efi'
C, S, DATA, STACK, STUB = 0x100000, 0x200000, 0x400000, 0x700000, 0x900000
ERR26 = 0x800000000000001a


def sha(b):
    return hashlib.sha256(b).hexdigest()


def checked(path, expected):
    b = path.read_bytes()
    assert sha(b) == expected
    return b


def ref(p):
    b = p.read_bytes()
    return {'path': p.relative_to(ROOT).as_posix(), 'bytes': len(b), 'sha256': sha(b)}


def q(v):
    return struct.pack('<Q', v)


def main():
    official = checked(OFFICIAL, '03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29')
    engineering = checked(ENGINEERING, 'e330039ecd2c334c4f9d502589e7f9503000b34462a7e21f6b97b1b581794d08')
    crypto = checked(CRYPTO, '265112ff89d0dff3992820698f8c6fbe430d0565628113a77c4011fd94c1347b')
    sec = checked(SECFLASH, 'bff5fca82753c1076d00efbf6aefa3f27affc91d4a24530914aecc0b1a256da0')
    root_key = official[0x3e811d4:0x3e812d4]
    assert root_key == official[0x258:0x358] and len(root_key) == 256
    crypto_image = pefile.PE(data=crypto).get_memory_mapped_image()
    sec_image = pefile.PE(data=sec).get_memory_mapped_image()
    assert crypto_image[0xe0d0:0xe0e0] == sec_image[0x9480:0x9490]

    def vm():
        u = Uc(UC_ARCH_X86, UC_MODE_64)
        for address, size in [(C, (len(crypto_image) + 4095) & ~4095), (S, (len(sec_image) + 4095) & ~4095), (DATA, 0x10000), (STACK, 0x10000), (STUB, 0x1000)]:
            u.mem_map(address, size)
        u.mem_write(C, crypto_image)
        u.mem_write(S, sec_image)
        u.mem_write(DATA + 0x2000, root_key)
        # The original PEI producer selects the raw-RSA key type for this FV;
        # these are CryptoSMM's initialized root fields, not modified code.
        u.mem_write(C + 0xea10, crypto_image[0xe0d0:0xe0e0])
        u.mem_write(C + 0xea20, struct.pack('<I', 256))
        u.mem_write(C + 0xea28, q(DATA + 0x2000))
        u.mem_write(STUB, b'\xc3' * 0x1000)
        return u

    def run(u, address, rcx=0, rdx=0, r8=0, r9=0, stop_hash=False):
        hits = []
        stopped = []
        def hook(uc, pc, size, _):
            if pc == C + 0x20d4:
                descriptor = uc.reg_read(UC_X86_REG_R8)
                pointer = struct.unpack('<Q', uc.mem_read(descriptor + 24, 8))[0]
                hits.append(sha(bytes(uc.mem_read(pointer, 256))))
            if pc in (STUB, STUB + 0x10, STUB + 0x20):
                stopped.append({STUB: 'return', STUB + 0x10: 'first_hash_boundary', STUB + 0x20: 'signature_verify_boundary'}[pc])
                uc.emu_stop()
        u.hook_add(UC_HOOK_CODE, hook)
        rsp = STACK + 0xff08
        u.mem_write(rsp, q(STUB))
        for reg, value in [(UC_X86_REG_RSP, rsp), (UC_X86_REG_RCX, rcx), (UC_X86_REG_RDX, rdx), (UC_X86_REG_R8, r8), (UC_X86_REG_R9, r9)]:
            u.reg_write(reg, value)
        u.emu_start(address, STUB + 0x100, count=100000)
        assert len(stopped) == 1, 'Unexpected instruction limit or execution exit'
        return {'stop': stopped[0], 'return_rax': hex(u.reg_read(UC_X86_REG_RAX)), 'public_key_attempt_sha256': hits}

    cases = []
    for name, key, expected in [
        ('official_certificate_key_is_trusted', official[0x258:0x358], 0),
        ('official_firmware_key_requires_certificate_chain', official[0x48:0x148], ERR26),
        ('engineering_certificate_key_is_not_trusted', engineering[0x258:0x358], ERR26),
        ('engineering_firmware_key_is_not_trusted', engineering[0x48:0x148], ERR26),
    ]:
        u = vm()
        u.mem_write(DATA + 0x3000, key)
        u.mem_write(DATA + 0x4000, crypto_image[0xe0d0:0xe0e0] + struct.pack('<IIQ', 256, 0, DATA + 0x3000))
        result = run(u, C + 0x20d4, 0, C + 0xe090, DATA + 0x4000)
        assert result['stop'] == 'return' and int(result['return_rax'], 16) == expected
        cases.append({'name': name, 'pass': True, 'result': result, 'expected_status': hex(expected)})

    for name, header, expected_stop in [('official_chain_reaches_certificate_hash', official[:4096], 'first_hash_boundary'),
                                        ('engineering_chain_rejected_before_any_hash_or_signature', engineering[:4096], 'return')]:
        u = vm()
        u.mem_write(DATA, header)
        u.mem_write(S + 0xa280, q(DATA))
        u.mem_write(S + 0xa630, q(DATA + 0x5000))
        u.mem_write(DATA + 0x5000, q(STUB + 0x20) + q(0) + q(STUB + 0x10) + q(0) + q(C + 0x20d4))
        result = run(u, S + 0x397c, 0, DATA + 0x6000, 0x4000000, 0)
        assert result['stop'] == expected_stop
        assert len(result['public_key_attempt_sha256']) == 2
        if expected_stop == 'return':
            assert int(result['return_rax'], 16) == ERR26
        cases.append({'name': name, 'pass': True, 'result': result,
                      'complete_signature_success_claimed': False})

    report = {'status': 'PASS_BOUNDED_ORIGINAL_ROOT_GATE_REPLAY', 'case_count': len(cases), 'failure_count': 0,
              'inputs': [ref(p) for p in [OFFICIAL, ENGINEERING, CRYPTO, SECFLASH]],
              'root_public_key_sha256': sha(root_key), 'script': ref(Path(__file__)), 'cases': cases,
              'executed_original_functions': ['CryptoSMM0x20d4', 'CryptoSMM0x1fec', 'CryptoSMM0x1340', 'SecSMIFlash0x397c'],
              'limits': ['Only immutable original-code execution in Unicorn; no hardware or target firmware execution.',
                         'Crypto root globals initialized from the exact official FV/PEI selection; live188 root not read.',
                         'Official positive chain stops before its first hash callback; no complete signature or flash success is claimed.',
                         'Engineering chain rejects with EFI_SECURITY_VIOLATION before reaching any hash/verify boundary.',
                         'No modified trust anchor, firmware patch, bypass or executable test media created.']}
    path = BASE / 'native_root_gate_replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    print(json.dumps({'report': ref(path), 'cases': len(cases), 'failure_count': 0}))


if __name__ == '__main__':
    main()

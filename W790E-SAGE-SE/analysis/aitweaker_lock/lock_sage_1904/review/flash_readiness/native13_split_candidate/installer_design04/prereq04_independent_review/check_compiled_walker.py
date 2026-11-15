"""Independent read-only page-walker checks on a copied production EFI.

The EFI is never executed by Windows. Unicorn runs its exact exported ms_abi
walk_with_env function against synthetic page tables and a synthetic EFI map.
No real CR/MSR values, ASUS services or hardware are modeled by these tests.
Only this review directory is written; the candidate is read-only.
"""
from pathlib import Path
import argparse, hashlib, json, re, struct, sys

OUT = Path(__file__).resolve().parent
PROBE = OUT.parent / 'prerequisite_probe04'
ROOT = next(p for p in OUT.parents if (p / 'tools/pydeps').is_dir())
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_RAX, UC_X86_REG_RSP, UC_X86_REG_RIP

B, DATA, STACK, TABLES, STOP = 0x1000000, 0x2000000, 0x3000000, 0x4000000, 0x5000000
NX = 1 << 63
ADDRESS = 0x123456789
ENV_ADDR, OUT_ADDR, MAP_ADDR = DATA + 0x2000, DATA + 0x3000, DATA + 0x1000


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def snapshot(label):
    assert re.fullmatch(r'[a-z0-9_]+', label)
    dest = OUT / ('walker_' + label + '_snapshot')
    names = ['build/SageNative13Prerequisite04.efi', 'build/probe.map', 'build/build.json', 'source/pagewalk.inc', 'source/preflight.c']
    if not dest.exists():
        build = json.loads((PROBE / 'build/build.json').read_text(encoding='utf8'))
        assert digest(PROBE / names[0]) == build['efi_sha256']
        bindings = {x['path'].replace('\\', '/'): x['sha256'] for x in build['sources']}
        for name in names:
            if name.startswith('source/'):
                assert digest(PROBE / name) == bindings[name], 'Candidate is changing; wait for a complete build'
        captured = {name: (PROBE / name).read_bytes() for name in names}
        # Avoid silently binding metadata from a simultaneously replaced build.
        assert hashlib.sha256(captured[names[0]]).hexdigest() == build['efi_sha256']
        assert captured['build/build.json'] == (PROBE / 'build/build.json').read_bytes()
        for name, raw in captured.items():
            p = dest / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(raw)
    return dest, [{'path': name, 'sha256': digest(dest / name), 'bytes': (dest / name).stat().st_size} for name in names]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--snapshot', required=True)
    args = parser.parse_args()
    snap, bindings = snapshot(args.snapshot)
    source = (snap / 'source/pagewalk.inc').read_text(encoding='utf8')
    assert re.search(r'\bint\s+EA\s+walk_with_env\s*\(', source), 'Requires explicit external ms_abi helper'
    pe_path = snap / 'build/SageNative13Prerequisite04.efi'
    symbols = {m.group(1): int(m.group(2), 16) for m in re.finditer(r'^\s+\w+:\w+\s+(\S+)\s+([0-9a-fA-F]{16})\s', (snap / 'build/probe.map').read_text(encoding='utf8'), re.M)}
    original = pefile.PE(str(pe_path)).OPTIONAL_HEADER.ImageBase
    sym = lambda name: B + symbols[name] - original
    pe = pefile.PE(str(pe_path)); pe.relocate_image(B)
    image = pe.get_memory_mapped_image()
    cases = []

    def run(name, *, leaf=1, levels=4, address=ADDRESS, pat=0, user=1,
            change=None, expected_error=0, expected_rw=1, expected_nx=0, expected_user=None):
        u = Uc(UC_ARCH_X86, UC_MODE_64)
        for a, n in [(B, (len(image) + 4095) & ~4095), (DATA, 0x10000), (STACK, 0x10000), (TABLES, 0x10000), (STOP, 0x1000)]:
            u.mem_map(a, n)
        u.mem_write(B, image)
        def write64(a, value): u.mem_write(a, struct.pack('<Q', value))
        def read64(a): return struct.unpack('<Q', u.mem_read(a, 8))[0]
        env = [0x80010033, TABLES, 0x620 | ((1 << 12) if levels == 5 else 0), 0xd00, 0x0007040600070406, 48, 0]
        descriptors = [(4, TABLES, 16, 0)]
        entries = {}
        for level in range(levels, leaf - 1, -1):
            table = TABLES + (levels - level) * 4096
            slot = table + 8 * ((address >> (12 + 9 * (level - 1))) & 511)
            flags = 3 | (4 if user else 0)
            if level == leaf:
                size = 1 << (12 + 9 * (level - 1))
                value = (address & ~(size - 1)) | flags | (128 if level > 1 else 0)
                value |= ((pat & 3) << 3) | (((pat >> 2) & 1) << (7 if level == 1 else 12))
            else:
                value = (table + 4096) | flags
            write64(slot, value)
            entries[level] = slot
        context = {'u': u, 'env': env, 'descriptors': descriptors, 'entries': entries, 'write64': write64, 'read64': read64}
        if change:
            change(context)
        rawmap = b''.join(struct.pack('<IIQQQQ', typ, 0, start, 0, pages, attrs) for typ, start, pages, attrs in descriptors)
        u.mem_write(MAP_ADDR, rawmap)
        write64(sym('map'), MAP_ADDR); write64(sym('map_bytes'), len(rawmap)); write64(sym('stride'), 40)
        u.mem_write(ENV_ADDR, struct.pack('<5Q2I', *env))
        u.mem_write(OUT_ADDR, b'\xa5' * 48)
        reads, forbidden = [], []
        def on_read(uc, access, a, size, value, data):
            if TABLES <= a < TABLES + 0x10000:
                reads.append((a, size))
        def on_write(uc, access, a, size, value, data):
            if not (STACK <= a and a + size <= STACK + 0x10000) and not (OUT_ADDR <= a and a + size <= OUT_ADDR + 48):
                forbidden.append((a, size)); uc.emu_stop()
        u.hook_add(UC_HOOK_MEM_READ, on_read)
        u.hook_add(UC_HOOK_MEM_WRITE, on_write)
        sp = STACK + 0xf008; write64(sp, STOP)
        u.reg_write(UC_X86_REG_RSP, sp)
        for reg, value in [(UC_X86_REG_RCX, address), (UC_X86_REG_RDX, ENV_ADDR), (UC_X86_REG_R8, OUT_ADDR)]:
            u.reg_write(reg, value)
        u.emu_start(sym('walk_with_env'), STOP, count=200000)
        assert not forbidden, (name, forbidden)
        assert u.reg_read(UC_X86_REG_RIP) == STOP, (name, 'No normal return')
        ret = u.reg_read(UC_X86_REG_RAX) & 0xffffffff
        assert ret == expected_error, (name, ret, expected_error)
        result = struct.unpack('<3Q6I', u.mem_read(OUT_ADDR, 48))
        if expected_error:
            assert result == (0,) * 9, (name, result)
        else:
            expected = (address, 1 << (12 + 9 * (leaf - 1)), read64(entries[leaf]), expected_rw, expected_nx, pat, leaf, user if expected_user is None else expected_user, 0)
            assert result == expected, (name, result, expected)
            # The EFI's safe u64 helper is compiled as several byte/word reads;
            # check their exact byte union, not an assumed instruction count.
            observed_bytes = {b for a, n in reads for b in range(a, a + n)}
            expected_bytes = {b for a in entries.values() for b in range(a, a + 8)}
            assert observed_bytes == expected_bytes, (name, reads)
        cases.append({'case': name, 'passed': True, 'return_code': ret, 'table_read_operations': len(reads), 'output': list(result), 'writes_only_output_and_stack': True})

    def bit(level, flag, set_to=True):
        def mutate(c):
            a = c['entries'][level]; v = c['read64'](a)
            c['write64'](a, (v | flag) if set_to else (v & ~flag))
        return mutate
    for leaf in (1, 2, 3):
        for pat in range(8):
            run(f'identity_leaf_{leaf}_pat_{pat}', leaf=leaf, pat=pat)
        for level in range(leaf, 5):
            run(f'effective_rw_leaf_{leaf}_ancestor_{level}', leaf=leaf, change=bit(level, 2, False), expected_rw=0)
            run(f'effective_nx_leaf_{leaf}_ancestor_{level}', leaf=leaf, change=bit(level, NX), expected_nx=1)
            run(f'effective_user_leaf_{leaf}_ancestor_{level}', leaf=leaf, change=bit(level, 4, False), expected_user=0)
    for leaf in (1, 2, 3):
        run(f'la57_leaf_{leaf}_identity_above_47bit', leaf=leaf, levels=5, address=(1 << 47) + 0x3456789)
    for name, address in [('low_null', 0), ('low_below_page', 4095), ('noncanonical_48bit', 1 << 47), ('upper_canonical_not_supported', 0xffff800000000000)]:
        run(name, address=address, expected_error=1)
    for name, index, flag in [('PE', 0, 1), ('PG', 0, 1 << 31), ('PAE', 2, 1 << 5), ('LMA', 3, 1 << 10)]:
        run('context_missing_' + name, change=lambda c, i=index, f=flag: c['env'].__setitem__(i, c['env'][i] & ~f), expected_error=1)
    for width in (31, 53):
        run(f'physical_width_{width}_refused', change=lambda c, w=width: c['env'].__setitem__(5, w), expected_error=1)
    for flag, name in [(20, 'SMEP'), (21, 'SMAP'), (22, 'PKE'), (23, 'CET'), (24, 'PKS')]:
        run('unmodeled_' + name + '_refused', change=lambda c, f=flag: c['env'].__setitem__(2, c['env'][2] | (1 << f)), expected_error=1)
    run('root_above_physical_width', change=lambda c: c['env'].__setitem__(1, TABLES | (1 << 49)), expected_error=1)
    run('table_conventional_memory_refused', change=lambda c: c['descriptors'].__setitem__(0, (7, TABLES, 16, 0)), expected_error=2)
    run('table_read_protected_refused', change=lambda c: c['descriptors'].__setitem__(0, (4, TABLES, 16, 0x2000)), expected_error=2)
    run('overlapping_table_descriptors_refused', change=lambda c: c['descriptors'].append((4, TABLES + 4096, 1, 0)), expected_error=2)
    for level in (1, 2, 3, 4):
        run(f'not_present_level_{level}', change=bit(level, 1, False), expected_error=3)
        run(f'entry_above_physical_width_level_{level}', change=bit(level, 1 << 49), expected_error=4)
    run('NX_without_NXE', change=lambda c: (c['env'].__setitem__(3, c['env'][3] & ~(1 << 11)), bit(1, NX)(c)), expected_error=4)
    run('PS_at_PML4_reserved', change=bit(4, 128), expected_error=4)
    run('PS_at_PML5_reserved', levels=5, change=bit(5, 128), expected_error=4)
    run('unaligned_2MiB_leaf', leaf=2, change=bit(2, 1 << 13), expected_error=4)
    run('unaligned_1GiB_leaf', leaf=3, change=bit(3, 1 << 21), expected_error=4)
    run('nonidentity_leaf_refused', change=lambda c: c['write64'](c['entries'][1], c['read64'](c['entries'][1]) ^ 4096), expected_error=5)

    report = {'status': 'PASS_INDEPENDENT_COMPILED_WALKER', 'case_count': len(cases), 'binary_sha256': digest(pe_path),
              'snapshot_bindings': bindings, 'cases': cases,
              'scope': 'Exact compiled external ms_abi walker under Unicorn, synthetic low identity-mapped page-table memory and explicit CPU environment. No actual CR/MSR access, EFI attribute services, TLB behavior, ASUS firmware, UI interception, or physical hardware is tested.'}
    path = OUT / ('walker_' + args.snapshot + '_result.json')
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf8')
    print(json.dumps({'status': report['status'], 'case_count': len(cases), 'binary_sha256': report['binary_sha256']}))


if __name__ == '__main__':
    main()

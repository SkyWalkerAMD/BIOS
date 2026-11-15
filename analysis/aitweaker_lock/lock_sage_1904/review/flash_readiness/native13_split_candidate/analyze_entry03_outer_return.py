"""Exact original-code interpretation of the physical EP3 outer return.

No new probe or installer. Synthetic opaque-ancestor fixtures demonstrate the
observation boundary, not reachable ASUS browser ancestry.
"""
from pathlib import Path
from collections import deque
import hashlib
import json
import struct
import sys
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
OUT = HERE / 'entry03_hardware_review'
OUT.mkdir(exist_ok=True)
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import capstone
import pefile
from unicorn import UC_HOOK_MEM_READ

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

original = HERE / 'boot_context/AMITSE.original.efi'
assert sha(original) == '531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1'
pe = pefile.PE(str(original))
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
start, end = 0x2780, 0x302a
raw = pe.get_data(start, end - start)
instructions = list(md.disasm(raw, start))
assert sum(x.size for x in instructions) == len(raw)
assert instructions[-1].address == 0x3029 and instructions[-1].mnemonic == 'ret'
by_address = {x.address: x for x in instructions}

def item(address):
    x = by_address[address]
    return {'rva': hex(x.address), 'bytes': bytes(x.bytes).hex(), 'mnemonic': x.mnemonic, 'operands': x.op_str}

def direct_target(address, mnemonic='call'):
    x = by_address[address]
    assert x.mnemonic == mnemonic and x.operands[0].type == capstone.x86.X86_OP_IMM
    return x.operands[0].imm

def rip_target(address):
    x = by_address[address]
    parts = [o for o in x.operands if o.type == capstone.x86.X86_OP_MEM and o.mem.base == capstone.x86.X86_REG_RIP]
    assert len(parts) == 1
    return x.address + x.size + parts[0].mem.disp

def wide_string(rva):
    raw = pe.get_data(rva, 128)
    result = raw.decode('utf-16-le').split('\0')[0]
    return result

assert direct_target(0x2d78) == 0x9f78
assert direct_target(0x2b65) == 0xe1b8
assert rip_target(0x2ca8) == 0x7bb48 and wide_string(0x7bb48) == 'BootNext'
assert rip_target(0x2c53) == 0x7bb30 and wide_string(0x7bb30) == 'BootOrder'
assert rip_target(0x2d3f) == 0x7be80 and wide_string(0x7be80) == 'BootCurrent'
assert direct_target(0x2caf) == 0x13e4
assert by_address[0x2cc1].op_str == 'qword ptr [rbp - 0x79], 2'
assert direct_target(0x2d08) == 0x90a8
assert rip_target(0x2799) == rip_target(0x2848) == rip_target(0x300c) == 0x834b8
assert by_address[0x284f].op_str == 'rax, r12'
assert direct_target(0x2852, 'jne') == 0x2be1
assert by_address[0x2c1e].op_str.endswith(', 7') and rip_target(0x2c1e) == 0x83468

# Local CFG only. Calls are represented as returning to their next instruction;
# this is structural reachability, not branch-condition satisfiability or a
# transitive call-graph proof.
edges = {}
for x in instructions:
    fall = x.address + x.size
    if x.mnemonic == 'ret':
        targets = []
    elif x.mnemonic == 'jmp':
        assert x.operands[0].type == capstone.x86.X86_OP_IMM
        targets = [x.operands[0].imm]
    elif x.group(capstone.CS_GRP_JUMP):
        assert x.operands[0].type == capstone.x86.X86_OP_IMM
        targets = [x.operands[0].imm, fall]
    else:
        targets = [fall]
    assert all(t in by_address for t in targets)
    edges[x.address] = targets

def route(begin, target, forbidden=()):
    queue = deque([begin]); previous = {begin: None}
    while queue:
        here = queue.popleft()
        if here == target:
            path = []
            while here is not None:
                path.append(here); here = previous[here]
            return list(reversed(path))
        for nxt in edges[here]:
            if nxt not in previous and nxt not in forbidden:
                previous[nxt] = here; queue.append(nxt)
    return None

after_browser = route(0x2b6a, 0x2d78)
without_browser = route(start, 0x2d78, (0x2b65,))
assert after_browser and without_browser
stack_writes = []
for x in instructions:
    _, writes = x.regs_access()
    if x.mnemonic != 'call' and (capstone.x86.X86_REG_RSP in writes or capstone.x86.X86_REG_RBP in writes):
        stack_writes.append(item(x.address))
assert not any(0x2799 <= int(x['rva'], 16) < 0x3016 for x in stack_writes)

# One bounded original-module reference inventory. It does not resolve indirect
# callers, and is deliberately not expanded into another outward stack probe.
scan = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
scan.detail = True; scan.skipdata = True
text_section = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text')
direct_refs = []
for x in scan.disasm(pe.get_data(text_section.VirtualAddress, text_section.Misc_VirtualSize), text_section.VirtualAddress):
    if x.id and x.mnemonic in ('call', 'jmp') and x.operands[0].type == capstone.x86.X86_OP_IMM and x.operands[0].imm == start:
        direct_refs.append(hex(x.address))
pointer_refs = []
for block in pe.DIRECTORY_ENTRY_BASERELOC:
    for entry in block.entries:
        if entry.type == 10 and int.from_bytes(pe.get_data(entry.rva, 8), 'little') == pe.OPTIONAL_HEADER.ImageBase + start:
            pointer_refs.append(hex(entry.rva))
assert pointer_refs == ['0x6b4f0']
interface_guid = str(uuid.UUID(bytes_le=pe.get_data(0x6b130, 16)))
assert interface_guid == '8a91b1e1-56c7-4adc-abeb-1c2ca1729eff'

# Execute the frozen EP3 collector for two distinct opaque upper-frame values.
# Both have the observed original CALL 2D78->9F78. The older return slot and
# counter are *synthetic*, deliberately not asserted to be reachable firmware
# paths. Same output demonstrates that EP3 cannot distinguish their contents.
sys.path.insert(0, str(HERE / 'entry_probe03'))
import verify_context_probe as fixture
fixture.OUT = OUT / 'opaque_ancestor_fixtures'
fixture.OUT.mkdir(exist_ok=True)
fixture.ROWS = []
f = fixture.f
upper_reads = []
synthetic_cases = [
    ('opaque_older_frame_A', 0x123456789abcdef0, 1),
    ('opaque_older_frame_B', 0xfedcba9876543210, 2),
]
for name, older_return, nesting_count in synthetic_cases:
    vm = fixture.VM()
    vm.w(vm.parent_rsp + 0x190, f.q(f.TSE + 0x2d7d))
    vm.w(vm.parent_rsp + 0x188, f.q(vm.parent_rsp + 0x241))
    vm.w(vm.parent_rsp + 0x2a0, f.q(older_return))
    vm.w(f.TSE + 0x834b8, f.q(nesting_count))
    reads = []
    vm.u.hook_add(UC_HOOK_MEM_READ, lambda u, access, a, n, value, data, dest=reads: dest.append((a - vm.parent_rsp, n)), begin=vm.parent_rsp + 0x198, end=vm.parent_rsp + 0x3ff)
    vm.run(name, lambda log: 'LaunchOuterReturnRVA=0000000000002D7D' in log and 'BROWSER_ABSENCE_PROOF=NO' in log)
    assert not reads
    upper_reads.append(reads)
logs = [(fixture.OUT / (case[0] + '.log')).read_bytes() for case in synthetic_cases]
assert logs[0] == logs[1]

listing = OUT / 'AMITSE_2780_302A.original.asm.txt'
listing.write_text(''.join(f'{x.address:08x}: {bytes(x.bytes).hex():24s} {x.mnemonic:8s} {x.op_str}\n' for x in instructions))
evidence = {
    'status': 'BOUNDED_EP3_OUTER_RETURN_INTERPRETED_NOT_BROWSER_ABSENCE_PROOF',
    'original_amitse_sha256': sha(original),
    'function': {
        'rva_begin': hex(start), 'rva_end_exclusive': hex(end),
        'byte_count': len(raw), 'instruction_count': len(instructions),
        'sha256': hashlib.sha256(raw).hexdigest(),
        'classification': 'Original AMITSE boot-selection/BootNext dispatch function; role inferred from exact variable strings and launch instructions, not a recovered vendor symbol.',
        'listing_sha256': sha(listing),
        'stack_register_changes': stack_writes,
    },
    'physical_binding': {
        'raw_rsp': '0x54f68af8', 'observed_return': '0x60fa7d7d',
        'observed_call_rva': '0x2d78', 'call_bytes': bytes(by_address[0x2d78].bytes).hex(),
        'target_rva': '0x9f78', 'return_rva': '0x2d7d',
        'saved_outer_rbp': '0x54f68d39',
        'derived_rbp_relation': 'RawEntryRSP+0x241',
        'relation_matches': 0x54f68af8 + 0x241 == 0x54f68d39,
        'older_return_slot_derived_only_not_read': '0x54f68d98',
        'older_return_value': None,
    },
    'bootnext_branch': [item(a) for a in (0x2ca8, 0x2caf, 0x2cc1, 0x2ccc, 0x2ce6, 0x2cf1, 0x2d08, 0x2d19, 0x2d3f, 0x2d60, 0x2d63, 0x2d6b, 0x2d72, 0x2d75, 0x2d78)],
    'variable_names': {'0x7bb30': 'BootOrder', '0x7bb48': 'BootNext', '0x7be80': 'BootCurrent'},
    'branch_interpretation': [
        'The original function fetches BootNext via helper13E4 and accepts a two-byte value before selecting/resolving its boot option.',
        'The original function calls the RuntimeServices+58 slot with BootNext and DataSize0 before launching; it calls the same slot for a two-byte BootCurrent immediately before the observed CALL2D78.',
        'The probe itself does not write variables. These instructions belong to the original firmware launch path, not the probe.',
    ],
    'browser_and_reentry_boundary': {
        'conditional_native_browser_call': item(0x2b65),
        'native_browser_return_rva': '0x2b6a',
        'local_path_from_return_to_launch': [hex(x) for x in after_browser],
        'local_path_to_launch_bypassing_browser_call': [hex(x) for x in without_browser],
        'cfg_model': 'Intraprocedural structural graph; CALL falls through; branch feasibility and transitive callees are not proven.',
        'state7_write_before_BootNext': item(0x2c1e),
        'activation_counter_rva': '0x834b8',
        'counter_increment_and_reentry_branch': [item(a) for a in (0x2799, 0x27ca, 0x2848, 0x284f, 0x2852, 0x2be1, 0x2be4, 0x300c)],
        'counter_physical_value_observed': False,
        'direct_original_module_call_or_jump_refs_to_2780': direct_refs,
        'relocation_pointer_refs_to_2780': pointer_refs,
        'published_interface': {'interface_rva': '0x6b4f0', 'guid_rva': '0x6b130', 'guid': interface_guid, 'publish_call_rva': '0x2647', 'publish_BS_slot': '0x148'},
        'indirect_callers_resolved': False,
    },
    'actual_frozen_collector_observation_limit_test': {
        'efi_sha256': sha(f.EFI), 'cases': fixture.ROWS,
        'distinct_synthetic_upper_slots_and_counter_values': [{'case': name, 'older_return_value': hex(ret), 'counter': count} for name, ret, count in synthetic_cases],
        'output_bytes_identical': True,
        'reads_of_older_unobserved_frame': upper_reads,
        'scope': 'Actual frozen collector executes against two constructed EFI fixtures. It does not execute an outer browser or prove that either hypothetical ancestry is reachable on ASUS hardware.',
    },
    'meaningful_safety_implications': [
        'Physical entry is now attributable to the original BootNext branch, rather than merely an arbitrary AMITSE StartImage call.',
        'The observed original outer frame is consistent with its exact fixed prologue and saved RBP.',
        'The same function can enter and return from the browser and has a reentry path. The observed branch and stage7/app0 cannot identify all older activations or prove asynchronous quiescence.',
        'The current observation adds no exclusive allocation, page-permission, detour transaction, callback-lifetime, or rollback evidence; unchanged N12/P12 cannot use occupied adjacent pages.',
        'A separate allocation design remains an offline architecture candidate, not an installation-ready route. Any future installation boundary would need its own bounded ownership and lifetime proof, not merely one more successful QR capture.',
    ],
    'browser_absence_proven': False,
    'installation_authorized': False,
    'new_probe_created': False,
    'installer_created_or_run': False,
    'remote_or_device_actions': False,
    'analysis_source_sha256': sha(Path(__file__)),
}
result = OUT / 'outer_return_flow.json'
result.write_text(json.dumps(evidence, indent=2) + '\n')
print(json.dumps({'status': evidence['status'], 'function_sha256': evidence['function']['sha256'], 'instructions': len(instructions), 'synthetic_cases': len(fixture.ROWS), 'flow_sha256': sha(result)}))

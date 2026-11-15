"""Independent EP3 raw-PNG transport and bounded physical-frame review.

This does not modify the frozen EP3 candidate, use a device, or infer idle.
"""
from pathlib import Path
import hashlib
import json
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
CASE = HERE.parents[2]
EP3 = HERE / 'entry_probe03'
CAP = CASE / 'remote_172_20_2_162/hardware-native13-entry03-1793699303328'
OUT = HERE / 'entry03_hardware_review'
sys.path.insert(0, str(EP3))
from decode_probe import decode

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

manifest = EP3 / 'entry_context03_manifest.json'
manifest_hash = sha(manifest)
assert manifest_hash == '56bff292b3fe57b8d29888129e2db854d91f79ef61e546aa901234d4297dbc6c'
artifacts = json.loads(manifest.read_text())['artifacts']
assert len(artifacts) == 110
for artifact in artifacts:
    assert sha(HERE / artifact['path']) == artifact['sha256'], artifact['path']

screens = [CAP / f'page-{n:02}.png' for n in range(1, 11)]
raw, transport = decode(screens)
assert len(raw) == 7124
assert transport['crc32'] == 'F05C1C96'
assert transport['sha256'] == '609056637bb727cfcf01032e3b50730f989edf5f2782bb290b793ff57770909f'
assert raw == (CAP / 'hardware-log.txt').read_bytes()
assert raw.count(b'NO_FLASH_NO_HOOKS_NO_VARIABLE_WRITES_NO_DISK_WRITES\r\n') == 2
assert raw.count(b'BROWSER_ABSENCE_PROOF=NO\r\n') == 1
text = raw.decode('ascii')

def number(label):
    found = re.findall(r'^' + re.escape(label) + r'=([0-9A-F]{16})\r?$', text, re.M)
    assert len(found) == 1, (label, found)
    return int(found[0], 16)

core = text.split('CONTEXT_MODULE DxeCore\r\n')[1].split('CONTEXT_MODULE BdsArch')[0]
bds = text.split('CONTEXT_MODULE BdsArch\r\n')[1].split('EntryStackMemoryType')[0]
for part in (core, bds):
    assert 'PASS context module normalized complete text SHA256\r\n' in part
assert 'CoreAllocationRoundingUsed=YES\r\n' in core
assert 'ContextPEImageSize=0000000000020E60\r\n' in core
assert 'ContextModuleSize=0000000000021000\r\n' in core
assert 'CoreAllocationRoundingUsed=NO\r\n' in bds
assert text.count('PASS original relocation-free text SHA256\r\n') == 2
assert text.count(' ORIGINAL_OK\r\n') == 12

rsp = number('RawEntryRSP')
assert rsp == 0x54f68af8
assert number('EntryReturnAddress') == 0x54f69000 + 0x88af
assert number('NativeStartImageCallerReturn') == 0x60fa5000 + 0xa8e6
assert number('NativeCallerSavedRBP') == rsp + 0x131
assert number('LaunchOuterReturnSlot') == rsp + 0x190
assert number('LaunchOuterReturnAddress') == 0x60fa5000 + 0x2d7d
assert number('LaunchOuterSavedRBP') == 0x54f68d39
assert number('LaunchOuterReturnRVA') == 0x2d7d
assert number('EntryStackMemoryType') == 4
assert number('Warnings') == 0
for line in (
    'PASS exact fixed Core StartImage frame',
    'PASS exact known native StartImage callsite',
    'PASS complete original AMITSE launch function SHA256',
    'PASS exact outer CALL target9F78 and return RVA',
    'NO_FURTHER_OUTER_STACK_WALK',
    'INSTALLATION_AUTHORIZED_BY_CONTEXT=NO',
):
    assert line + '\r\n' in text

OUT.mkdir(exist_ok=True)
decoded = OUT / 'independently-decoded.log'
if decoded.exists():
    assert decoded.read_bytes() == raw
else:
    decoded.write_bytes(raw)

review = {
    'status': 'INDEPENDENT_EP3_PHYSICAL_IDENTITY_AND_BOUNDED_OUTER_RETURN_PASS_NOT_IDLE_PROOF',
    'decode': transport,
    'same_as_parent_log': True,
    'screens': [{'path': str(p), 'sha256': sha(p)} for p in screens],
    'observed': {
        'original_amitse_and_setup_complete_text_passed': True,
        'original_detour_sites_passed': 12,
        'core_base': '0x54f69000',
        'core_loaded_allocation_size': '0x21000',
        'core_live_pe_size': '0x20e60',
        'core_complete_normalized_text_passed': True,
        'bds_base': '0x613b4000',
        'bds_complete_text_passed': True,
        'stack_type': 4,
        'stack_map_attributes': '0xf',
        'raw_entry_rsp': hex(rsp),
        'core_return_rva': '0x88af',
        'native_startimage_parent': 'AMITSE+0xa8e6',
        'native_launch_function': 'AMITSE[0x9f78,0xaada)',
        'native_launch_complete_function_hash_passed': True,
        'saved_launch_rbp': hex(number('NativeCallerSavedRBP')),
        'outer_return_slot': hex(number('LaunchOuterReturnSlot')),
        'outer_return_address': hex(number('LaunchOuterReturnAddress')),
        'outer_return_rva': '0x2d7d',
        'outer_call_instruction_rva': '0x2d78',
        'outer_call_target_rva': '0x9f78',
        'saved_outer_rbp': hex(number('LaunchOuterSavedRBP')),
        'saved_outer_rbp_was_dereferenced': False,
        'warnings': 0,
    },
    'bounded_interpretation': [
        'The observed chain is original AMITSE CALL 2D78->9F78, original AMITSE CALL A8E0->Core StartImage, and original Core entry CALL returning to 88AF.',
        'The final observed AMITSE return 2D7D is inside the original BootNext-handling branch, as separately demonstrated by exact original instructions and variable-name strings.',
        'No stack slot outside the frozen collector contract was read; no further ancestor was observed.',
    ],
    'limits': [
        'The original outer function also contains a conditional browser-loop call and a reentry counter; identifying its BootNext branch does not prove all older frames are browser-free.',
        'The immediately inspected browser-call branch, when taken in this same activation, returns before its BootNext branch. That local control-flow fact is not an outer-chain or asynchronous-quiescence proof.',
        'Actual CPU page permissions, exclusive guard/state allocation, callback lifetime, and transactional rollback remain separate unresolved installer requirements.',
        'The occupied adjacent pages still cannot be used for unchanged N12/P12 payloads.',
    ],
    'browser_absence_proven': False,
    'installation_authorized': False,
    'installer_run': False,
    'provider_started': False,
    'remote_or_device_actions': False,
    'previous_ep3_manifest_sha256': manifest_hash,
    'frozen_ep3_artifacts_verified_unchanged': len(artifacts),
    'source_script_sha256': sha(Path(__file__)),
}
flow = OUT / 'outer_return_flow.json'
if flow.exists():
    review['original_outer_flow_review'] = {'path': str(flow), 'sha256': sha(flow)}
result = HERE / 'entry03_hardware_readonly_review.json'
result.write_text(json.dumps(review, indent=2) + '\n')
print(json.dumps({'review_sha256': sha(result), 'bytes': len(raw), 'crc32': transport['crc32'], 'outer_return_rva': '0x2d7d', 'frozen_artifacts_unchanged': len(artifacts)}))

"""Read-only baseline reproduction in Unicorn, not a firmware execution test.

Runs the pinned ACE driver and original ACE AMITSE history routines. The page
objects, memory services and password outcome are fixtures. No old files change.
"""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'tools/pydeps').is_dir())
DRIVER = ROOT / 'analysis/aitweaker_lock/lock_1904/driver'
CASE = ROOT / 'analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF'

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

assert sha(DRIVER / 'build/AiTweakerLock1904.efi') == 'eb4d9b43bc3fd88eef9b7b8570f636ea1c1c56cc36ae0693ebd1dfa7bdd71fb3'
assert sha(CASE / 'modules/AMITSE.efi') == '99ff85060750d39c9e1a861fd29c48726aa0c82f47b1ec7e6c12150836070ec5'
adapter = DRIVER / 'verify_adapter.py'
# Load only definitions. The original verification script's report-writing
# section after checks=[] is deliberately excluded.
ns = {'__file__': str(adapter)}
exec(compile(adapter.read_text(encoding='utf8').split('\nchecks=[]', 1)[0], str(adapter), 'exec'), ns)
for key in ['VM', 'TSE', 'SETUP', 'HEAP', 'symbols', 'q', 'd', 'w']:
    globals()[key] = ns[key]

HISTORY = HEAP + 0x180000
OUT = HEAP + 0x190000
CAPACITY = 28
v = VM()
for i, form in enumerate([0x6003, 0x2713, 0x2714, 0x271e, 0x6000, 0x6001, 0x6002, 0x271b]):
    v.u.mem_write(v.records + i * 64 + 10, w(form))
    v.u.mem_write(v.pages[i] + 0x2a, w(form))
v.u.mem_write(v.pages[0] + 0x20, q(0))
v.u.mem_write(v.pages[3] + 0x32, w(1))
v.u.mem_write(TSE + 0x82760, q(HISTORY))
v.u.mem_write(TSE + 0x82758, d(CAPACITY))
v.u.mem_write(TSE + 0x82754, d(2))
v.u.mem_write(TSE + 0x82778, d(0))
assert v.call(symbols['attach_platform'], TSE, 0xa2000, SETUP, 0x1a4000) == 1
v.start()
v.current(2)
v.call(TSE + 0x10270, 0, 2)
assert v.getd(TSE + 0x82778) == 1
before = {'current_index': v.getd(v.app + 0x28), 'history_root_form': v.getd(HISTORY + 8), 'history_start': v.getd(TSE + 0x82754)}
v.call(TSE + 0x34b7c)
after = {'current_index': v.getd(v.app + 0x28), 'history_root_form': v.getd(HISTORY + 8), 'history_start': v.getd(TSE + 0x82754)}
assert after == {'current_index': 1, 'history_root_form': 0x2714, 'history_start': 2}
v.current(3)
v.call(TSE + 0x10270, 1, 3)
v.u.mem_write(OUT, b'\xff' * 16)
status = v.call(TSE + 0x1017c, 3, OUT, OUT + 8)
parent_index = int.from_bytes(v.u.mem_read(OUT, 2), 'little')
assert status == 0 and parent_index == 2
report = {
    'status': 'BASELINE_HISTORY_DEFECT_REPRODUCED',
    'driver_sha256': sha(DRIVER / 'build/AiTweakerLock1904.efi'),
    'amitse_sha256': sha(CASE / 'modules/AMITSE.efi'),
    'setup_sha256': sha(CASE / 'modules/Setup.efi'),
    'before_denied_initial_ai': before,
    'after_denied_initial_ai': after,
    'security_parent_status': hex(status),
    'security_parent_index': parent_index,
    'expected_security_parent_index': 1,
    'native_history_lookup_rva': '0x1017c',
    'native_history_append_rva': '0x10270',
    'implication': 'Forced redirect changes visible current page to Main but leaves Ai as native history root; subsequent Security parent resolution returns the denied Ai page.',
    'limits': ['Page objects, firmware service/memory checks and password result are fixtures.', 'Original ACE history append/parent instructions and compiled driver poll redirect run under Unicorn.', 'No full OEM visual browser, direct Del/F2, host firmware execution, NVRAM change or flashing occurred.'],
}
(HERE / 'ace_history_baseline_reproduction.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
print(json.dumps(report, ensure_ascii=False, indent=2))

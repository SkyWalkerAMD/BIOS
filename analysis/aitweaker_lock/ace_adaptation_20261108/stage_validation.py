"""Stage isolated ACE validation tools without altering the historical projects."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'tools/pydeps').is_dir())
BASE = ROOT / 'analysis/aitweaker_lock/lock_1904'
SAGE = ROOT / 'analysis/aitweaker_lock/lock_sage_1904'
DEST = HERE / 'lock_1904_history02'
lineage = []


def sha(data):
    return hashlib.sha256(data).hexdigest()


def stage(source, target, replacements):
    raw = source.read_bytes()
    value = raw.decode('utf-8')
    for old, new in replacements:
        assert old in value, (str(source), old)
        value = value.replace(old, new)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(value, encoding='utf-8', newline='\n')
    lineage.append({'source': str(source.relative_to(ROOT)), 'source_sha256': sha(raw),
                    'target': str(target.relative_to(HERE)), 'target_sha256': sha(target.read_bytes())})


root_expr = "next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())"
module_expr = "ROOT/'analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF'"
for name in ('verify_adapter.py', 'verify_policy.py', 'verify_entropy.py'):
    repl = [('ROOT=HERE.parents[3]', 'ROOT=' + root_expr)]
    if name in ('verify_adapter.py', 'verify_policy.py'):
        repl.append(("HERE.parent.parent/'hardware_20261102_W790_ACE_E9B906DF'", module_expr))
    if name == 'verify_adapter.py':
        repl += [
            ("self.u.mem_write(page+0x30,w(i));", "self.u.mem_write(page+0x2a,w(form));self.u.mem_write(page+0x30,w(i));"),
            ("  for i,source_handle in", "  # OEM BrowserLoop initializes history before its first poll.\n"
             "  history=HEAP+0x180000\n"
             "  self.u.mem_write(TSE+0x82760,q(history));self.u.mem_write(TSE+0x82758,d(28))\n"
             "  self.u.mem_write(TSE+0x82754,d(1));self.u.mem_write(TSE+0x82778,d(1))\n"
             "  self.u.mem_write(history,q(self.handle)+d(0x2714))\n"
             "  for i,source_handle in"),
        ]
    stage(BASE/'driver'/name, DEST/'driver'/name, repl)

stage(BASE/'driver/verify_hii_abi.py', DEST/'driver/verify_hii_abi.py', [
    ("HERE.parents[3]/'tools/pydeps'", root_expr + "/'tools/pydeps'")])
stage(BASE/'driver/run_vm.py', DEST/'driver/run_vm.py', [
    ('ROOT=HERE.parents[3]', 'ROOT=' + root_expr),
    ("HERE.parent.parent/'uefi_vm_20261015'", "ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'")])
stage(BASE/'lab/inject_ovmf.py', DEST/'lab/inject_ovmf.py', [
    ('ROOT=OUT.parents[3]', "ROOT=next(p for p in OUT.parents if (p/'tools/pydeps').is_dir())")])
for name in ('build_asus_review.py', 'verify_asus_review.py'):
    stage(BASE/'lab'/name, DEST/'lab'/name, [])

repl = [
    ('original SAGE history', 'original ACE history'),
    ('ROOT=CASE.parents[2]', 'ROOT=' + root_expr),
    ("HARDWARE_DRIVER_SHA='da52a08f0e477867f4f08e3d1514b156be1ac67fa3bc9c47d09272a869aaf2e2'", "MODULES=" + module_expr),
    ('531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1', '99ff85060750d39c9e1a861fd29c48726aa0c82f47b1ec7e6c12150836070ec5'),
    ('719bad779e9ae60340187c7aae6c12ab9dff3ee398c58a9fca2a4e027a33f21d', 'cccec44562198457d7f72e76df3a73bc8ec61244c94428219ee990963d6922dc'),
    ("==build['efi_sha256']==HARDWARE_DRIVER_SHA", "==build['efi_sha256']"),
    ("CASE/'analysis/modules/", "MODULES/'modules/"),
    ("        'hardware_history01_driver_sha256':HARDWARE_DRIVER_SHA,\n", "        'hardware_validation_performed':False,\n"),
    ('0x1a6000', '0x1a4000'),
]
# Each ACE address is corroborated independently by the baseline reproduction
# and new REA review; the historical SAGE offsets are not used at runtime.
address_map = {
    '0x1012c': '0x1017c', '0x10220': '0x10270', '0x16c20': '0x16c70',
    '0x626c': '0x62bc', '0x5c60': '0x5cb0', '0x32264': '0x322b4',
    '0x3297c': '0x329cc', '0x930a8': '0x92268', '0x835a0': '0x82760',
    '0x83598': '0x82758', '0x83594': '0x82754', '0x835b8': '0x82778',
    '0x835bc': '0x8277c', '0x34b2c': '0x34b7c', '0x6b930': '0x6af80',
    '0x6b928': '0x6af78',
}
repl.extend(address_map.items())
stage(SAGE/'driver/verify_history.py', DEST/'driver/verify_history.py', repl)
(HERE/'validation_lineage.json').write_text(json.dumps(lineage, indent=2)+'\n', encoding='utf-8')
print(json.dumps({'validation_tools_staged': len(lineage), 'destination': str(DEST)}))

"""Independent FD02 delta audit; read candidates, write this review only."""
from pathlib import Path
import datetime, difflib, hashlib, importlib.util, io, json, re, sys, warnings, zipfile
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REMOTE = HERE.parent
CASE = REMOTE.parents[2]
ROOT = CASE.parents[2]
OLD = REMOTE / 'spi_descriptor_candidate01'
NEW = REMOTE / 'spi_descriptor_candidate02'
for folder in ('pydeps', 'vm-pydeps', 'kvm-pydeps'):
    sys.path.insert(0, str(ROOT / 'tools' / folder))
warnings.filterwarnings('ignore', message='pkg_resources is deprecated.*')
import pefile, pycdlib
from pyfatfs.PyFatFS import PyFatFS
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def obj(p): return json.loads(p.read_text(encoding='utf-8'))
def ref(p): return {'path': str(p), 'bytes': p.stat().st_size, 'sha256': sha(p)}

expected = 'e4ba56afde400afe019cd7fdd136802873dec223e6f4a66f3b40c279c03553b8'
assert sha(NEW / 'build/BOOTX64.EFI') == expected
assert sha(NEW / 'candidate_manifest.json') == 'd2095619ca09a2cb80e5adf44f21470a28de9d2317001c245777e268ab7b7f5c'
manifest = obj(NEW / 'candidate_manifest.json')
for row in manifest['artifact_bindings']:
    p = Path(row['path'])
    assert p.stat().st_size == row['bytes'] and sha(p) == row['sha256']
build = obj(NEW / 'build/build.json')
assert build['efi_sha256'] == expected
archive = NEW / 'build/source-snapshot.zip'
assert sha(archive) == build['source_archive_sha256']
with zipfile.ZipFile(archive) as z:
    for n, h in build['source_files'].items():
        assert sha(NEW / n) == h == hashlib.sha256(z.read(n)).hexdigest()
iso = NEW / 'build/SAGE1904-SPI-DESCRIPTOR02.iso'
assert sha(iso) == build['iso_sha256'] == 'a86ca64810bc476a06f14d01898591210fa4ae4fa0b335d7bb5da34127f93449'
cd = pycdlib.PyCdlib(); cd.open(str(iso)); outer = io.BytesIO(); boot = io.BytesIO()
cd.get_file_from_iso_fp(outer, iso_path='/EFI/BOOT/BOOTX64.EFI;1')
cd.get_file_from_iso_fp(boot, iso_path='/EFIBOOT.IMG;1')
assert cd.eltorito_boot_catalog.validation_entry.platform_id == 0xef
cd.close()
assert outer.getvalue() == (NEW / 'build/BOOTX64.EFI').read_bytes()
assert boot.getvalue() == (NEW / 'build/eltorito.img').read_bytes()
with PyFatFS(str(NEW / 'build/eltorito.img'), read_only=True, utc=True) as fat:
    assert fat.readbytes('/EFI/BOOT/BOOTX64.EFI') == outer.getvalue()

changes = []
for p in sorted((NEW / 'source').iterdir()):
    if not p.is_file(): continue
    prev = OLD / 'source' / p.name
    if sha(p) != sha(prev):
        changes.append({'file': p.name, 'before': ref(prev), 'after': ref(p),
                        'diff': ''.join(difflib.unified_diff(prev.read_text().splitlines(True), p.read_text().splitlines(True)))})
assert {r['file'] for r in changes} == {'fd_core.c', 'fd_core.h', 'inventory.c', 'frontend.inc'}
old_core = (OLD / 'source/fd_core.c').read_text()
new_core = (NEW / 'source/fd_core.c').read_text()
start = '    if(FAILED(rd(io,r,STS,&s)))return r->failure_status;r->last_status=s;'
end = '    if(!(s&BUSY)&&(s&DONE)){complete=1;break;}'
assert old_core[:old_core.index(start)] == new_core[:new_core.index(start)]
assert old_core[old_core.index(end):] == new_core[new_core.index(end):]
old_inv = (OLD / 'source/inventory.c').read_text()
new_inv = (NEW / 'source/inventory.c').read_text()
counter = ' field("POLL_OBSERVATIONS",r->poll_observations,8);field("EXACT_BUSY_FGO_OBSERVATIONS",r->busy_fgo_observations,8);\n'
assert old_inv.replace('SPI-DESCRIPTOR-01', 'SPI-DESCRIPTOR-02') == new_inv.replace(counter, '')
assert old_inv[old_inv.index('static ES EA io_write'):old_inv.index('static ES EA io_stall')] == new_inv[new_inv.index('static ES EA io_write'):new_inv.index('static ES EA io_stall')]

tests = {}
for report, script in [('core_regression.json', 'verify_core.py'), ('frontend_regression.json', 'verify_frontend.py'),
                       ('transport_regression.json', 'verify_transport.py'), ('build/ovmf_verification.json', 'verify_ovmf.py'),
                       ('parser_regression.json', 'verify_parser.py')]:
    r = obj(NEW / report)
    assert r['status'].startswith('PASS')
    if 'efi_sha256' in r: assert r['efi_sha256'] == expected
    assert r.get('verification_source_sha256', r.get('test_source_sha256')) == sha(NEW / script)
    if isinstance(r.get('cases'), list):
        assert all(c.get('passed') is True or c.get('status', '').startswith('PASS') for c in r['cases'])
    tests[report] = {'report': ref(NEW / report), 'script': ref(NEW / script), 'status': r['status'],
                     'case_count': r.get('case_count', len(r.get('cases', [])))}
core = obj(NEW / 'core_regression.json')
front = obj(NEW / 'frontend_regression.json')
assert core['case_count'] == 102 and front['case_count'] == 39
for c in front['cases']:
    assert sha(Path(c['log'])) == c['log_sha256']
parser = CASE / 'remote_172_20_2_162/read_spi_descriptor02_qr.py'
assert sha(parser) == obj(NEW / 'parser_regression.json')['parser_sha256']
for name in ('captured_busy_FGO_native_CPU_IO2', 'busy_FGO_native_timeout', 'native_FGO_idle_refused', 'native_busy_FGO_error_refused'):
    assert any(c['name'] == name and c['passed'] for c in front['cases'])

# Independent targeted replay does not invoke main() or overwrite candidate reports.
spec = importlib.util.spec_from_file_location('fd02_independent_core', NEW / 'verify_core.py')
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
replays = [mod.execute('independent_observed_busy_then_done', busy_status=0x3f01e820)]
for name, kw in [
    ('independent_busy_until_timeout', {'busy_status': 0x3f01e820, 'polls': 10001, 'expected_stage': 13}),
    ('independent_idle_GO1', {'completion_status': 0x3f01e801, 'expected_stage': 11}),
    ('independent_busy_GO1_error', {'busy_status': 0x3f01e822, 'expected_stage': 11}),
    ('independent_busy_and_done', {'busy_status': 0x3f00e821, 'expected_stage': 11}),
    ('independent_busy_stall_error', {'busy_status': 0x3f01e820, 'stall_fail': 1, 'expected_stage': 12}),
]:
    replays.append(mod.execute(name, **kw))
assert replays[0]['result']['busy_fgo_observations'] == 128
for r in replays[1:]:
    assert r['result']['writes'] == 2 and r['result']['go_attempts'] == 1
    assert r['result']['blocks'] == r['result']['final_transients_restored'] == 0
assert replays[1]['result']['poll_observations'] == replays[1]['result']['busy_fgo_observations'] == 10000

pe = pefile.PE(str(NEW / 'build/BOOTX64.EFI'))
assert pe.OPTIONAL_HEADER.Subsystem == 10 and pe.verify_checksum()
symbols = {n: int(v, 16) - pe.OPTIONAL_HEADER.ImageBase for n, v in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s', (NEW / 'build/inventory.map').read_text(), re.M)}
cs = Cs(CS_ARCH_X86, CS_MODE_64)
machine = {}
for name in ('fd_capture', 'io_write'):
    rva = symbols[name]; endrva = min(v for v in symbols.values() if v > rva)
    blob = pe.get_data(rva, endrva-rva)
    lines = [{'rva': hex(i.address), 'bytes': i.bytes.hex(), 'instruction': f'{i.mnemonic} {i.op_str}'} for i in cs.disasm(blob, rva)]
    machine[name] = {'rva': hex(rva), 'end_rva': hex(endrva), 'sha256': hashlib.sha256(blob).hexdigest(), 'instructions': lines}
assert any('0x3f01e820' in i['instruction'] for i in machine['fd_capture']['instructions'])
assert any('0x3f01e800' in i['instruction'] for i in machine['io_write']['instructions'])
assert all(sha(Path(r['path'])) == r['sha256'] for r in manifest['artifact_bindings'])
cleanup = CASE / 'remote_172_20_2_162/inventory-cleanup-1793681225473.json'
assert all(obj(cleanup)['verified'].values())
report = {
    'status': 'INDEPENDENT_OFFLINE_DELTA_REVIEW_NO_BLOCKER_FOR_FIXED_FD02_READ',
    'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'scope': 'Offline only. No hardware, network, candidate mutation or firmware update.',
    'manifest': ref(NEW / 'candidate_manifest.json'), 'binding_count': len(manifest['artifact_bindings']),
    'efi': ref(NEW / 'build/BOOTX64.EFI'), 'iso': ref(iso), 'source_changes': changes,
    'package_checks': {'all_manifest_hashes_match': True, 'source_zip_matches': True, 'ISO_outer_EFI_matches': True,
                       'ElTorito_FAT_EFI_matches': True, 'PE_checksum_and_application_subsystem': True},
    'semantic_review': {
        'new_allowed_state': 'Only post-GO exact 0x3F01E820 permits another bounded read/stall.',
        'completion': 'Only 0x3F00E801 passes complete condition and all masks.',
        'idle_and_write_allowlist_unchanged': True,
        'busy_DONE_ambiguous_now_rejected': True,
        'normal_effects': '128 fixed READ64 and 386 MMIO DWORD writes; no flash program or erase. Lock fields are repeated with validated original values.',
        'failure': 'All examined timeout/I/O/ambiguous paths stop at one GO and two MMIO writes for first-block failure; no cleanup or reissue.',
        'output_gate_unchanged': True,
        'counter_scope': 'Totals of valid read observations only, not timestamps or an entire controller trace.',
        'nonblocking_documentation_note': 'The shared status_valid comment still says hardware returns FGO zero; new polling comment correctly documents the observed exception.'
    },
    'author_test_evidence': tests,
    'independent_targeted_compiled_core_replay': replays,
    'actual_compiled_instructions': machine,
    'cleanup_record_read_only': ref(cleanup),
    'limitations': ['The real target has not demonstrated strict completion or descriptor export for FD02.',
                    'Intel read-zero wording discrepancy remains; Linux SCIP polling supports only continuing observation.',
                    'No exclusive SMM ownership or physical-controller emulation is proven.',
                    'OVMF is startup/rejection/QR/exit coverage, not the W790 controller positive path.',
                    'No complete SPI backup, recovery or flash update acceptance is established.'],
    'all_candidate_bindings_unchanged_after_review': True, 'review_script': ref(Path(__file__))
}
dest = HERE / 'fd02_independent_review.json'
dest.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'status': report['status'], 'path': str(dest), 'sha256': sha(dest), 'independent_cases': len(replays)}))

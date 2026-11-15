"""Bind the actual hardware stage1 QR receipt to unchanged-source stage2 media.

Only local files and two actual-EFI rejection cases are used. No device calls,
password access, stage1 rebuild or repeated full regression.
"""
from pathlib import Path
import datetime, hashlib, io, json, re, struct, sys, zlib

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent; NV = HERE.parent
ROOT = next(p for p in HERE.parents if (p / 'tools/pydeps').is_dir())
for folder in ['pydeps', 'vm-pydeps', 'kvm-pydeps']: sys.path.insert(0, str(ROOT / 'tools' / folder))
sys.path.insert(0, str(ROOT / 'analysis/aitweaker_lock/probe_p3_kvm'))
import pefile, pycdlib, capstone
from pyfatfs.PyFatFS import PyFatFS
from decode_captures import read_image, assemble, parse_frame

sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
S1 = NV / 'stage1/build'; S2 = NV / 'stage2/build'
RDIR = NV.parent / 'bmc_nv05/stage1-receipt'
LOGSHA = 'a47b5a24e3cd978e895bac63e40cf2095d535098e752b474457cf481d2cfe54b'
RECORD = 'c1d706f63848951af3c28e6378d719ea6ebd509adabb69a700060be84ae57379'
PIN = '71b05ebe21fd0b4de496fc9684f57e4acc79431e38a403dec9017501605eca98'
m1 = json.loads((S1 / 'build.json').read_text(encoding='utf8'))
m2 = json.loads((S2 / 'build.json').read_text(encoding='utf8'))
receipt = json.loads((RDIR / 'manifest.json').read_text(encoding='utf8'))
snapshots = {str(p): sha(p) for p in [S1 / 'build.json', S1 / 'BOOTX64.EFI', Path(m1['iso_path']),
                                    S2 / 'build.json', S2 / 'BOOTX64.EFI', Path(m2['iso_path']),
                                    RDIR / 'manifest.json', RDIR / 'hardware-log.txt']}
raw = (RDIR / 'hardware-log.txt').read_bytes()
assert sha(RDIR / 'hardware-log.txt') == LOGSHA and len(raw) == 2514
assert f'{zlib.crc32(raw):08X}' == '4AB319FF'
frames = []; screenshot_bindings = []
for shot in receipt['screenshots']:
    path = Path(shot['file']); assert sha(path) == shot['sha256']
    value = read_image(path); parsed = parse_frame(value); frames.append(value)
    screenshot_bindings.append({'path': str(path.relative_to(ROOT)), 'sha256': sha(path), 'page': parsed['page']})
decoded, transport = assemble(frames)
assert decoded == raw and transport == receipt['transport']
assert sorted(s['page'] for s in screenshot_bindings) == [1, 2, 3, 4]
fields = {}
for line in raw.decode('ascii').replace('\r\n', '\n').splitlines():
    if '=' in line:
        k, v = line.split('=', 1)
        fields.setdefault(k, []).append(v)
def one(name):
    assert len(fields[name]) == 1, name
    return fields[name][0]
required = {
    'DriverSHA256': PIN, 'SourceBundleSHA256': m1['source_bundle_sha256'],
    'Stage': '0x0000000000000001', 'CredentialAttributes': '0x0000000000000003',
    'CredentialBytes': '0x0000000000000080', 'CredentialSHA256': RECORD,
    'CredentialGeneration': '0x0000000000000001', 'AcceptedWrites': '0x0000000000000001',
    'NativeSetAttempts': '0x0000000000000001', 'BlockedWrites': '0x0000000000000000',
    'LastNativeSetStatus': '0x0000000000000000', 'LastNativeGetStatus': '0x0000000000000000',
    'OwnershipKnown': '0x0000000000000001', 'Fault': '0x0000000000000000',
    'ConsoleOwnerActive': '0x0000000000000000', 'CoreActive': '0x0000000000000000',
    'CoreUnlocked': '0x0000000000000000', 'Phase1Receipt': 'COMMITTED_EXACT_READBACK',
    'Checks': '0x000000000000000e', 'Failures': '0x0000000000000000'
}
assert all(one(k) == v for k, v in required.items())
assert raw.count(b'PASS OC/memory variable metadata and SHA256 unchanged\r\n') == 4
for field in ['efi_sha256', 'iso_sha256', 'source_bundle_sha256']:
    assert receipt[field] == m1[field]
assert receipt['build_manifest_sha256'] == sha(S1 / 'build.json')
assert sha(S1 / 'BOOTX64.EFI') == m1['efi_sha256'] and sha(Path(m1['iso_path'])) == m1['iso_sha256']

assert m1['stage'] == 1 and m2['stage'] == 2 and m1['production_driver_sha256'] == m2['production_driver_sha256'] == PIN
assert m1['source_bundle_sha256'] == m2['source_bundle_sha256']
for key in ['local_sources', 'external_sources', 'production_sources', 'production_external_sources',
            'production_manifest_sha256', 'all_production_object_hashes', 'linked_objects', 'excluded_objects']:
    assert m1[key] == m2[key], key
for name, digest in m2['local_sources'].items(): assert sha(NV / name) == digest
for name, digest in m2['external_sources'].items(): assert sha(ROOT / name) == digest
PROD = NV.parent / 'lock_1904_candidate05'
for name, digest in m2['all_production_object_hashes'].items(): assert sha(PROD / 'driver/build' / name) == digest
assert sha(S2 / 'PRODUCTION-RELINK-CHECK.EFI') == PIN
b = m2['stage1_receipt_binding']
assert Path(b['log_path']).resolve() == (RDIR / 'hardware-log.txt').resolve() and b['log_sha256'] == LOGSHA
assert Path(b['manifest_path']).resolve() == (S1 / 'build.json').resolve() and b['manifest_sha256'] == sha(S1 / 'build.json')
assert b['stage1_efi_sha256'] == m1['efi_sha256'] and b['record_sha256'] == RECORD

g1 = {p.name: p.read_bytes() for p in (S1 / 'source').iterdir() if p.is_file()}
g2 = {p.name: p.read_bytes() for p in (S2 / 'source').iterdir() if p.is_file()}
assert set(g1) == set(g2)
assert g1['target_detect.h'] == g2['target_detect.h']
assert g2['kvm.c'] == g1['kvm.c'].replace(b'ACE1904-CANDIDATE05-NV-STAGE1', b'ACE1904-CANDIDATE05-NV-STAGE2')
header = g2['build_identity.h'].decode('ascii')
assert '#define NV_STAGE 2u' in header and LOGSHA in header and PIN in header and m1['source_bundle_sha256'] in header
embedded = bytes(int(x) for x in re.search(r'NV_EXPECTED_RECORD\[32\]=\{([^}]+)\}', header).group(1).split(','))
assert embedded.hex() == RECORD
for name, digest in m2['generated_sources'].items(): assert sha(S2 / 'source' / name) == digest

normalize_coff = lambda raw: raw[:4] + bytes(4) + raw[8:]
object_changes = []
for name in ['nv_guard.obj', 'nv_maintenance.obj', 'kvm.obj', 'qrcodegen.obj']:
    old = (S1 / name).read_bytes(); new = (S2 / name).read_bytes()
    same = normalize_coff(old) == normalize_coff(new)
    if name in ['nv_guard.obj', 'qrcodegen.obj']: assert same
    object_changes.append({'object': name, 'stage1_sha256': sha(S1 / name), 'stage2_sha256': sha(S2 / name),
                           'equal_except_coff_timestamp': same,
                           'expected_reason': 'No implementation change' if same else 'Stage2 branch and receipt/header constants' if name == 'nv_maintenance.obj' else 'Stage2 QR title'})

assert sha(S2 / 'BOOTX64.EFI') == m2['efi_sha256'] and sha(Path(m2['iso_path'])) == m2['iso_sha256']
iso = pycdlib.PyCdlib(); iso.open(m2['iso_path']); boot = io.BytesIO()
iso.get_file_from_iso_fp(boot, iso_path='/EFIBOOT.IMG;1'); iso.close()
assert boot.getvalue() == (S2 / 'eltorito.img').read_bytes()
with PyFatFS(str(S2 / 'eltorito.img'), read_only=True, utc=True) as fat:
    assert fat.readbytes('/EFI/BOOT/BOOTX64.EFI') == (S2 / 'BOOTX64.EFI').read_bytes()

# Only two gate rejections execute; all other unchanged fixtures remain bound
# to their existing results. No synthetic positive hardware receipt is made.
helper = NV / 'verify_nv_guard.py'
prefix = helper.read_text(encoding='utf8').split('\nchecks=[]', 1)[0]
assert prefix.count("OUT=HERE/'stage1/build'") == 1
prefix = prefix.replace("OUT=HERE/'stage1/build'", "OUT=HERE/'stage2/build'")
ns = {'__file__': str(helper), '__name__': 'stage2_binding_fixture'}
exec(compile(prefix, str(helper), 'exec'), ns)
rows = []
for label, value in [('absent credential', None), ('unrelated valid enabled record', ns['record']())]:
    v = ns['NvVM'](value)
    address = v.symbols['NV_EXPECTED_RECORD']
    assert bytes(v.u.mem_read(address, 32)) == embedded
    assert v.call('initialize_services') == 1
    result = v.call('nv_prepare', ns['GET'], ns['SET'], 2, address)
    assert result == 0 and not v.native_sets and not v.state()['owned'] and not v.state()['ready']
    rows.append({'case': label, 'result': 'REJECTED_WITHOUT_NATIVE_WRITE', 'embedded_real_receipt_hash_used': True})

pe = pefile.PE(str(S2 / 'BOOTX64.EFI')); base = pe.OPTIONAL_HEADER.ImageBase
image = pe.get_memory_mapped_image(); pe.close()
v = ns['NvVM'](); entry = v.symbols['efi_main']
next_function = min(a for a in v.symbols.values() if a > entry and a < base + 0x10000)
instructions = list(capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64).disasm(image[entry-base:next_function-base], entry))
calls = [i for i, op in enumerate(instructions) if op.mnemonic == 'call' and op.op_str == hex(v.symbols['nv_prepare'])]
assert len(calls) == 1
window = instructions[max(0, calls[0]-10):calls[0]+1]
assert any(op.mnemonic == 'mov' and op.op_str == 'r8d, 2' for op in window)
native_prepare_call = [{'va': hex(op.address), 'bytes': op.bytes.hex(), 'instruction': op.mnemonic + ' ' + op.op_str} for op in window]

evidence = []
p = S2 / 'boot_validation.json'
if p.is_file():
    boot_result = json.loads(p.read_text(encoding='utf8'))
    assert boot_result['efi_sha256'] == m2['efi_sha256'] and boot_result['iso_sha256'] == m2['iso_sha256']
    evidence.append({'path': str(p.relative_to(ROOT)), 'sha256': sha(p), 'status': boot_result['status'], 'independent_rerun': False})

report = {'status': 'PASS_REAL_STAGE1_QR_TO_STAGE2_MEDIA_BINDING', 'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'physical_receipt': {'log_sha256': LOGSHA, 'transport': transport, 'screenshots': screenshot_bindings,
                               'screenshots_independently_decoded': True, 'decoded_bytes_equal_actual_log': True,
                               'verified_single_fields': required,
                               'origin_limit': 'Parent supplied the BMC captures and deployment manifest. Reviewer independently checks their bytes, QR and media binding; no independent live BMC access.'},
          'stage1': {'efi_sha256': m1['efi_sha256'], 'iso_sha256': m1['iso_sha256'], 'build_manifest_sha256': sha(S1 / 'build.json')},
          'stage2': {'efi_sha256': m2['efi_sha256'], 'efi_bytes': m2['efi_bytes'], 'iso_sha256': m2['iso_sha256'],
                     'build_manifest_sha256': sha(S2 / 'build.json'), 'expected_record_sha256': RECORD, 'receipt_log_sha256': LOGSHA,
                     'source_bundle_sha256': m2['source_bundle_sha256'], 'iso_embedded_efi_exact': True},
          'same_source_and_production_coff': True, 'full_production_relink_exact': PIN,
          'object_changes': object_changes, 'generated_source_changes': ['NV_STAGE1 -> 2', 'NV_BUILD_ID and QR title',
              'real first-stage log SHA and expected record SHA; production driver/source bundle/target detector unchanged'],
          'actual_entry_nv_prepare_call': native_prepare_call, 'necessary_actual_efi_rejections': rows,
          'prior_29_case_fixture_rerun': False, 'prior_full_pbkdf_or_gate_matrix_rerun': False,
          'additional_evidence': evidence, 'review_script_sha256': sha(Path(__file__)), 'helper_sha256': sha(helper),
          'stage1_or_production_modified': False, 'hardware_access': False, 'password_or_runner_memory_access': False,
          'limits': ['This stage2 image has not yet demonstrated physical cold-boot receipt acceptance, password change/clear or deletion persistence.',
                     'A source-identical stage2 compile intentionally enables its phase2 console branches. It is not claimed byte-identical to stage1.',
                     'The two local rejection tests use absent/unrelated records, not a copy or reconstruction of the real credential.',
                     'Only dedicated-variable normal NVRAM operations are in scope; no full Setup save, permanent native owner, whole-flash backup or flashability conclusion.']}
assert all(sha(p) == digest for p, digest in snapshots.items()), 'Concurrent build/media/log change'
path = HERE / 'stage2_binding_review.json'
path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
print(json.dumps({'status': report['status'], 'sha256': sha(path), 'stage2_efi_sha256': m2['efi_sha256'], 'path': str(path)}))

"""Read-only independent build/COFF attribution and guard design review.

Does not rebuild, produce stage-2 receipts, read credentials or contact devices.
The source/manifest snapshot is rechecked before publishing this review.
"""
from pathlib import Path
import datetime, hashlib, io, json, re, sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
NV = HERE.parent
ROOT = next(p for p in HERE.parents if (p / 'tools/pydeps').is_dir())
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import pefile

PIN = '71b05ebe21fd0b4de496fc9684f57e4acc79431e38a403dec9017501605eca98'
PROD = NV.parent / 'lock_1904_candidate05'
BUILD = NV / 'stage1/build'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
build_path = BUILD / 'build.json'
build_hash = sha(build_path)
m = json.loads(build_path.read_text(encoding='utf8'))
bound = []
def bind(path, expected, role):
    path = Path(path)
    actual = sha(path)
    assert actual == expected, (str(path), actual, expected)
    bound.append({'path': str(path.relative_to(ROOT)), 'sha256': actual, 'bytes': path.stat().st_size, 'role': role})

assert m['stage'] == 1 and not m['stage1_receipt_binding'] and m['production_driver_sha256'] == PIN
bind(PROD / 'driver/build/build.json', m['production_manifest_sha256'], 'Frozen production05 build')
prod = json.loads((PROD / 'driver/build/build.json').read_text(encoding='utf8'))
assert prod['efi_sha256'] == PIN and prod['revision'] == 'ACE1904_CANDIDATE05'
bind(PROD / 'driver/build/AiTweakerLock1904.efi', PIN, 'Frozen production05 EFI')
bind(BUILD / 'PRODUCTION-RELINK-CHECK.EFI', PIN, 'All original production COFF relink exactly reproduces production EFI')
bind(BUILD / 'BOOTX64.EFI', m['efi_sha256'], 'Actual maintenance application EFI')
assert Path(m['efi_path']).resolve() == (BUILD / 'BOOTX64.EFI').resolve()
for name, digest in m['production_sources'].items(): bind(PROD / name, digest, 'Production source')
for name, digest in m['production_external_sources'].items(): bind(ROOT / name, digest, 'Production external source')
for name, digest in m['all_production_object_hashes'].items(): bind(PROD / 'driver/build' / name, digest, 'Original production COFF')
for name, digest in m['local_sources'].items(): bind(NV / name, digest, 'Maintenance source/build input')
for name, digest in m['external_sources'].items(): bind(ROOT / name, digest, 'Maintenance external source')
for name, digest in m['generated_sources'].items(): bind(BUILD / 'source' / name, digest, 'Generated build input')

expected = {'password_core.obj', 'password_crypto.obj', 'services.obj', 'ui.obj', 'cpu_entropy.obj', 'probe_core.obj', 'save_feedback.obj'}
excluded = {'entry.obj', 'platform.obj', 'hii.obj', 'policy.obj'}
assert set(m['linked_objects']) == expected and set(m['excluded_objects']) == excluded
assert set(m['all_production_object_hashes']) == expected | excluded
for name, digest in m['linked_objects'].items(): assert digest == m['all_production_object_hashes'][name]
last_link = m['commands'][-1]
assert last_link[1] == 'lld-link' and '/subsystem:efi_application' in last_link
linked_paths = [Path(a) for a in last_link if a.lower().endswith('.obj')]
actual_production = {p.name for p in linked_paths if p.parent.resolve() == (PROD / 'driver/build').resolve()}
assert actual_production == expected
assert {p.name for p in linked_paths} == expected | {'nv_guard.obj', 'nv_maintenance.obj', 'kvm.obj', 'qrcodegen.obj'}

map_text = (BUILD / 'nv_test.map').read_text(encoding='utf8')
symbols = re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s+(\S+)', map_text, re.M)
map_objects = {obj for _, _, obj in symbols}
assert not map_objects.intersection(excluded)
important = {
    'efi_main': 'nv_maintenance.obj', 'platform_session_owned': 'nv_maintenance.obj',
    'platform_can_enter': 'nv_maintenance.obj', 'end_platform': 'nv_maintenance.obj',
    'nv_guard_set': 'nv_guard.obj', 'nv_cleanup_tombstone': 'nv_guard.obj',
    'persist_record': 'services.obj', 'read_record': 'services.obj', 'initialize_services': 'services.obj',
    'manage_password': 'ui.obj', 'ensure_unlocked': 'ui.obj',
    'ap_set_password': 'password_core.obj', 'ap_clear_password': 'password_core.obj',
    'ap_pbkdf2_sha256': 'password_crypto.obj'
}
attribution = []
for name, obj in important.items():
    found = [(addr, origin) for sym, addr, origin in symbols if sym == name]
    assert len(found) == 1 and found[0][1] == obj, (name, found)
    attribution.append({'symbol': name, 'object': obj, 'linked_va': '0x' + found[0][0]})

pe = pefile.PE(str(BUILD / 'BOOTX64.EFI'))
pe_info = {'machine': hex(pe.FILE_HEADER.Machine), 'subsystem': pe.OPTIONAL_HEADER.Subsystem,
           'checksum_valid': pe.verify_checksum(), 'imports_present': hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'),
           'relocation_bytes': pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size,
           'authenticode_bytes': pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size}
assert pe_info['machine'] == '0x8664' and pe_info['subsystem'] == 10 and pe_info['checksum_valid']
assert not pe_info['imports_present'] and pe_info['relocation_bytes'] and not pe_info['authenticode_bytes']
pe.close()
media = None
if m['iso_created']:
    for folder in ['vm-pydeps', 'kvm-pydeps']: sys.path.insert(0, str(ROOT / 'tools' / folder))
    import pycdlib
    from pyfatfs.PyFatFS import PyFatFS
    iso_path = Path(m['iso_path'])
    bind(iso_path, m['iso_sha256'], 'El Torito maintenance media')
    iso = pycdlib.PyCdlib(); iso.open(str(iso_path))
    image = io.BytesIO(); iso.get_file_from_iso_fp(image, iso_path='/EFIBOOT.IMG;1'); iso.close()
    assert image.getvalue() == (BUILD / 'eltorito.img').read_bytes()
    with PyFatFS(str(BUILD / 'eltorito.img'), read_only=True, utc=True) as fat:
        embedded = fat.readbytes('/EFI/BOOT/BOOTX64.EFI')
    assert embedded == (BUILD / 'BOOTX64.EFI').read_bytes()
    media = {'iso_path': str(iso_path.relative_to(ROOT)), 'sha256': m['iso_sha256'],
             'bytes': iso_path.stat().st_size, 'eltorito_exact_image_match': True,
             'embedded_efi_exact_match': True, 'extraction_writes': False}
residency_path = HERE / 'residency_validation.json'
residency = json.loads(residency_path.read_text(encoding='utf8'))
assert residency['efi_sha256'] == m['efi_sha256'] and residency['build_manifest_sha256'] == build_hash
assert residency['status'] == 'PASS_ACTUAL_NV_EFI_RESIDENCY_INPUT_AND_CANCEL_PATHS'

line_refs = {}
for name in ['nv_guard.c', 'nv_maintenance.c', 'build_nv_test.py']:
    lines = (NV / name).read_text(encoding='utf8').splitlines()
    patterns = {'nv_guard.c': ['int nv_prepare(', 'int nv_begin_action(', 'ES EA nv_guard_set(', 'int nv_cleanup_tombstone(', 'void nv_retire('],
                'nv_maintenance.c': ['int platform_session_owned(', 'static int make_resident(', 'static int publish_runtime_guards(', 'ES EA efi_main('],
                'build_nv_test.py': ['def receipt_binding(', 'def main(']}[name]
    line_refs[name] = {p: next(i for i, line in enumerate(lines, 1) if p in line) for p in patterns}

evidence = [{'path': str(residency_path.relative_to(ROOT)), 'sha256': sha(residency_path),
             'status': residency['status'], 'cases': residency['cases'], 'independent_execution': True}]
for name in ['guard_validation.json', 'stage2_binding_validation.json', 'boot_validation.json']:
    p = BUILD / name
    if p.is_file():
        obj = json.loads(p.read_text(encoding='utf8'))
        if obj.get('efi_sha256') == m['efi_sha256']:
            evidence.append({'path': str(p.relative_to(ROOT)), 'sha256': sha(p), 'status': obj.get('status'),
                             'checks': obj.get('checks'), 'cases': len(obj['cases']) if isinstance(obj.get('cases'), list) else obj.get('cases'),
                             'independent_execution': False,
                             'note': 'Builder-owned result inspected, not rerun or counted as independent scenarios.'})
chain_path = NV / 'password_chain_fixture/password_chain_validation.json'
if chain_path.is_file():
    chain = json.loads(chain_path.read_text(encoding='utf8'))
    if chain.get('efi_sha256') == m['efi_sha256']:
        assert chain['build_manifest_sha256'] == build_hash
        for name, digest in chain['all_linked_object_hashes'].items():
            assert sha(ROOT / name) == digest
        evidence.append({'path': str(chain_path.relative_to(ROOT)), 'sha256': sha(chain_path),
                         'status': chain['status'], 'checks': chain['checks'], 'independent_execution': False,
                         'note': 'Same exact COFF relinked as local DLL with firmware/entropy/time providers. Real production PBKDF/core/read/persist; no physical cold boot or console UI claim.'})

console_control = NV.parent / 'bmc_nv05/operations/nv_console.mjs'
console_review = None
if console_control.is_file():
    assert sha(console_control) == 'e74c001206e4e95a262fd111f810fd781625b00360d5694f672be5e7aa2f6f4e'
    console_review = {
        'path': str(console_control.relative_to(ROOT)), 'sha256': sha(console_control),
        'review_type': 'Static only, explicitly requested by parent; never executed by reviewer.',
        'findings': ['Three distinct 16-character printable ASCII inputs are generated with node:crypto and satisfy production UI length/encoding requirements.',
                     'Tool arguments select an enroll/changed/wrong slot; plaintext is not inserted into operation arguments, return objects or explicit log strings.',
                     'Only a short fixed console-key whitelist and three fixed input slots are accepted. Password typing requires the operator-observed masked-prompt flag.',
                     'Input is sent character by character followed by Enter. The unchanged production input_password function displays stars, with ESC cancellation and backspace handling.',
                     'wipe zeroes all three saved Buffer objects and deletes the stored object.'],
        'limits': ['The observed flags are operator assertions, not screen recognition; parent must verify each actual prompt before submitting.',
                   'The Buffer wipe claim does not cover temporary copies in the browser, protocol implementation or JavaScript engine.',
                   'No runner session, credential file or live BMC data was read for this code review.']
    }
visuals = []
for subdir, filename in [('20261108_130002_ordinary', 'page-01.png'), ('20261108_130005_spoof', 'page-02.png')]:
    p = NV / 'qemu_runs' / subdir / filename
    if p.is_file():
        visuals.append({'path': str(p.relative_to(ROOT)), 'sha256': sha(p), 'manually_viewed': True,
                        'observation': 'Stage1 maintenance title, page/CRC header and navigation text readable; QR lies fully within screen. Non-target failure diagnostic, not password or positive-target UI.'})

report = {
    'status': 'INDEPENDENT_LOCAL_REVIEW_COMPLETE_NO_ADDITIONAL_ACTIONABLE_GUARD_DEFECT',
    'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'efi_sha256': m['efi_sha256'], 'efi_bytes': m['efi_bytes'], 'build_manifest_sha256': build_hash,
    'production_driver_sha256': PIN, 'source_bundle_sha256': m['source_bundle_sha256'],
    'full_production_relink_exact_match': True, 'pe': pe_info, 'media': media, 'objects_reused': sorted(expected),
    'objects_not_linked': sorted(excluded), 'symbol_attribution': attribution,
    'architecture': 'The console owner adapter is a deliberate maintenance-only replacement. Actual production core/crypto/services/UI objects are retained. Native AMITSE SendForm/platform/HII/discovery/whole Setup are not started or claimed.',
    'guard_findings': [
        'The only saved firmware SetVariable calls are an exact credential-record replacement and the separate owned-disabled-tombstone deletion.',
        'Record writes require canonical production name/GUID pointers, attributes 3, 128 bytes, valid format/checksum, generation+1 and action-compatible enabled state.',
        'The active console owner, non-faulted busy production core and exact action/session token must agree. The native variable is reread before every write and must match the owned prior record or required initial absence.',
        'The desired candidate is privately copied before provider calls. Successful SetVariable must have exact status 0 and exact attributes/length/readback. Ambiguous changed or unreadable results fault and revoke ownership; clean unchanged failures may be retried within the bounded write budget.',
        'All public Runtime SetVariable calls are denied for the credential by the production public guard; other names reaching the maintenance gate are also denied. The production private persist path alone reaches the strict gate.',
        'Phase1 requires absence and an unconfigured/inactive core, seals after one verified enrollment, and never allows deletion.',
        'Phase2 requires a valid enabled live record matching the hash bound from phase1 and the actual production read into core. Change/clear still use the production UI/core authorization path.',
        'Cleanup is a separate single-attempt operation only after the owner session ends and the exact owned valid disabled record agrees with core and a fresh firmware read. Only success plus subsequent NOT_FOUND is reported as restored absence.'
    ],
    'early_review_followup_resolved': 'The maintenance application added its own BeforeExitBootServices callback, in addition to its final Exit callback. Both halt locally. Residency becomes irreversible immediately after the first event is installed, including failure to install the second event.',
    'phase2_receipt_binding': {
        'production_driver_pinned': True, 'stage1_log_explicit_sha_required': True,
        'stage1_manifest_and_actual_efi_checked': True, 'source_bundle_and_phase1_commit_metadata_checked': True,
        'stage1_guard_application_builder_and_production_coff_rechecked': True,
        'expected_live_record_hash_embedded': True,
        'physical_origin_authentication': 'Not provided by the text parser. Root must bind the real decoded hardware QR log to the deployed media and cold power cycle.',
        'synthetic_stage2_media_created_by_reviewer': False
    },
    'required_physical_acceptance': [
        'Phase1: begin with confirmed missing dedicated variable, enroll once through the unchanged password UI, capture successful exact readback receipt and source/media identity.',
        'Perform a real cold power cycle; phase2 must be built from that exact receipt and must match the live record before opening an owner session.',
        'Check wrong/correct password, explicit new-session relock, authenticated change/clear as planned, then end the owner and perform the one exact tombstone cleanup.',
        'Capture successful NOT_FOUND after deletion and unchanged monitored OC/memory metadata/hashes. A further independent cold read is needed to label cleanup persistence verified.'
    ],
    'limits': [
        'No physical NVRAM persistence, full Setup save, native-owner or permanent cold-DXE behavior is established by this review.',
        'The guard covers the application and current Runtime API table paths, not SMM, cached native pointers, unrelated firmware internals or whole-SPI rollback.',
        'A successful normal SetVariable may internally modify the firmware variable store. This is intentionally not a RAM-only or zero-flash-write test.',
        'Interruption after a phase2 replacement/clear cannot be silently adopted with the original phase1 receipt; unknown or mismatched records are preserved and require explicit recovery review.',
        'The app deliberately never returns after residency. ExitBootServices/Reset requests halt locally; external power control is the planned exit.',
        'The app keyboard currently retries non-success console statuses with Stall; persistent input failure may require external power-off. It does not authorize a write by itself.',
        'No stronger transactional atomicity is claimed than exact native status/readback and conservative loss-of-ownership on ambiguity.'
    ],
    'line_references': line_refs, 'bound_inputs': bound, 'execution_evidence': evidence,
    'console_operation_static_review': console_review, 'visual_review': visuals,
    'review_script_sha256': sha(Path(__file__)), 'production_or_harness_sources_modified': False,
    'media_created': False, 'hardware_access': False, 'deployment_authorization': 'Not issued by this review; parent owns deployment.'
}
assert sha(build_path) == build_hash
assert all(sha(ROOT / r['path']) == r['sha256'] for r in bound), 'Concurrent build/input mutation'
path = HERE / 'nv_independent_review.json'
path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
print(json.dumps({'status': report['status'], 'efi_sha256': report['efi_sha256'], 'bound_files': len(bound),
                  'sha256': sha(path), 'path': str(path)}))

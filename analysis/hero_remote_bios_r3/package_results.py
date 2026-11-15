"""Package the read-only build and a bounded, credential-free evidence set.

No BMC connections or firmware writes. Runtime logs are accepted only when their
decoded page manifest matches both SHA-256 and CRC32.
"""
from pathlib import Path
import hashlib, json, re, zipfile, zlib

BASE = Path(__file__).resolve().parent
LIVE = BASE.parent / 'hero_remote_bios_r3_live_20261102'
REPORT = '远程BIOS配置进展与实机结果-20261102.txt'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))

def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

logs = {}
for stem in ('R3-before', 'R3-apply', 'R3-final'):
    path = LIVE / (stem + '.TXT')
    data = path.read_bytes()
    manifest = read_json(LIVE / 'captures' / stem / 'manifest.json')
    assert len(data) == manifest['bytes']
    assert sha(path) == manifest['sha256']
    assert f'{zlib.crc32(data):08X}' == manifest['crc32']
    logs[stem] = data.decode('ascii')

assert 'SET_VARIABLE=0x800000000000001A' in logs['R3-apply']
assert logs['R3-final'].count('\nSET_VARIABLE=') == 1
assert 'RESTORE_SET_VARIABLE=' not in logs['R3-final']
assert 'RESTORE_VERIFIED_EXACT_ORIGINAL' in logs['R3-final']
assert set(re.findall(r'SETUP_SIZE=0D46 CRC32=(\w+)', logs['R3-final'])) == {'97EC1775'}
assert logs['R3-final'].endswith('TRANSACTION_READ=0x800000000000000E\r\n')
tested = read_json(BASE / 'tested-build-20261102/build.json')
current = read_json(BASE / 'build.json')
assert not current['native_setup_writes_enabled']
assert tested['iso_sha256'] == sha(BASE / 'tested-build-20261102/HERO-REMOTE-BIOS-R3.iso')
assert current['iso_sha256'] == sha(BASE / 'HERO-REMOTE-BIOS-R3.iso')
assert read_json(BASE / 'unit-tests.json')['passed']
assert read_json(BASE / 'vm/result.json')['passed']
assert read_json(BASE / 'vm-usb/result.json')['usb_file_log_readback']
assert read_json(LIVE / 'responses/014-get-bios.json')['result']['status'] == 404
assert 'Start Media' in read_json(LIVE / 'responses/118-eject-r3.json')['result']['text']

verification = {
    'date': '2026-11-02',
    'target': {'board': 'ROG MAXIMUS Z790 HERO', 'bios': '3107', 'bmc': '1.3.13'},
    'native_setup_reads_verified': ['BootupNumLockState', 'WaitForF1IfError', 'POSTDelayTime'],
    'uefi_application_write': {
        'tested_build_efi_sha256': tested['efi_sha256'],
        'tested_build_iso_sha256': tested['iso_sha256'],
        'attempts': 1, 'setting': 'BootupNumLockState', 'requested': [1, 0],
        'status': 'EFI_SECURITY_VIOLATION', 'status_hex': '0x800000000000001A',
        'native_setup_crc32_before_and_after': '97EC1775',
        'native_setup_unchanged_verified': True,
        'recovery_record_removed': True, 'recovery_setup_write_attempts': 0,
        'cause': 'Exact firmware policy/context not yet established.'
    },
    'native_bios_over_kvm': {
        'persisted_change_verified': {'setting': 'BootupNumLockState', 'from': 1, 'to': 0,
            'confirmation': 'screens/069-key-F10.png', 'after_reboot': 'screens/105-key-Enter.png'},
        'persisted_restoration_verified': {'setting': 'BootupNumLockState', 'from': 0, 'to': 1,
            'confirmation': 'screens/115-capture.png', 'after_reboot': 'screens/125-key-Enter.png'},
        'other_final_visible_values': {'WaitForF1IfError': 0, 'POSTDelayTime': 5, 'BootLogo': 'Auto'},
        'scope': 'One setting tested, no claim of testing all BIOS options.'
    },
    'native_bmc_web': {'bios_resource_status': 404, 'settings_not_populated': True,
        'writes_performed': False, 'equivalent_to_creator': False,
        'layout_get': 'HTTP 200 compressed payload was decoded as text, not verified as XML.'},
    'current_distribution': {'mode': 'read-only native settings', 'hardware_boot_retested': False,
        'iso_sha256': current['iso_sha256'], 'efi_sha256': current['efi_sha256'],
        'unit_assertions': read_json(BASE / 'unit-tests.json')['assertions'],
        'ovmf_optical_pass': True, 'ovmf_usb_and_file_readback_pass': True},
    'cleanup': {'virtual_media_ejected': True, 'final_screen': 'native BIOS Boot Configuration',
        'browser_process_closed': True, 'rea_session_closed': True,
        'server_logout_confirmed': False, 'server_logout_reason': '#logout locator timed out'},
    'firmware_flashed': False, 'creator_modified': False
}
write_json(LIVE / 'live-verification.json', verification)

# A project-internal mapping, intentionally not a published Redfish registry.
ifr = read_json(BASE / 'hero-3107-ifr.json')
attrs = []
for name, qid, off, maximum, value in [
    ('BootupNumLockState', 5185, 0, 1, 1),
    ('WaitForF1IfError', 5186, 3293, 1, 0),
    ('POSTDelayTime', 5183, 3291, 10, 5),
]:
    matches = [q for q in ifr['questions'] if q['question_id'] == qid and q['var_offset'] == off]
    assert len(matches) == 1
    q = matches[0]
    assert q['width'] == 1 and q['maximum'] == maximum
    attrs.append({'name': name, 'display_name': q['prompt'], 'offset': off, 'width': 1,
        'question_id': qid, 'ifr_offset': q['ifr_offset'], 'minimum': 0, 'maximum': maximum,
        'last_observed_value': value, 'read_only': True,
        'write_backend_status': 'unavailable; standalone UEFI SetVariable rejected',
        'conditions': q['conditions'], 'options': q['options']})
write_json(BASE / 'remote-config-map.json', {
    'format': 'hero-remote-config-internal-map-v1', 'published_to_bmc': False,
    'board': 'ROG MAXIMUS Z790 HERO', 'bios': '3107', 'observation_date': '2026-11-02',
    'source_setup_sha256': ifr['source_sha256'], 'attributes': attrs,
    'setup_variable': {'name': 'Setup', 'guid': 'ec87d643-eba4-4bb5-a1e5-3f3e36b20da9',
        'size': 3398, 'attributes': 7},
    'post_delay_dependency': {'name': 'BootLogo', 'store': 'AMITSESetup', 'offset': 80,
        'accepted_values': [1, 2], 'observed_value': 2, 'write_enabled': False}
})

files = {}
def include(src, dst):
    assert src.is_file(), src
    assert dst not in files
    files[dst] = src

for name in [REPORT, 'HERO-REMOTE-BIOS-R3.iso', 'build.json', 'build.py', 'inspect_ifr.py',
             'hero-3107-ifr.json', 'hero-3107-candidate-settings.json', 'remote-config-map.json',
             'test_settings.py', 'unit-tests.json', 'run_vm.py', 'decode_captures.py',
             'module-search.json', 'package_results.py', 'rea_session.py']:
    include(BASE / name, name)
for folder in ('USB', 'source'):
    for path in (BASE / folder).rglob('*'):
        if path.is_file(): include(path, path.relative_to(BASE).as_posix())
for folder in ('vm', 'vm-usb'):
    for name in ('result.json', 'serial.log', 'R3LOG000.TXT'):
        if (BASE / folder / name).exists(): include(BASE / folder / name, f'validation/{folder}/{name}')
for name in ('build.json', 'unit-tests.json'):
    include(BASE / 'tested-build-20261102' / name, 'evidence/tested-write-build/' + name)
for name in ('R3-before.TXT', 'R3-apply.TXT', 'R3-final.TXT', 'live-verification.json'):
    include(LIVE / name, 'evidence/' + name)
for stem in ('R3-before', 'R3-apply', 'R3-final'):
    include(LIVE / 'captures' / stem / 'manifest.json', f'evidence/captures/{stem}/manifest.json')
for name in ('035-key-Enter.png', '042-key-Enter.png', '049-key-Enter.png', '069-key-F10.png',
             '105-key-Enter.png', '115-capture.png', '125-key-Enter.png'):
    include(LIVE / 'screens' / name, 'evidence/screens/' + name)
for folder in ('rea-sync', 'rea-transport', 'rea-native-setup'):
    for path in (BASE / folder / 'responses').glob('*.c'):
        if path.name in ('014-save-event-seeded.c', '011-save-event.c'): continue
        include(path, 'analysis/' + path.relative_to(BASE).as_posix())
manifest = {name: {'bytes': src.stat().st_size, 'sha256': sha(src)} for name, src in sorted(files.items())}
write_json(BASE / 'package-manifest.json', manifest)
destination = BASE.parent / 'HERO-3107-REMOTE-BIOS-R3-READONLY.zip'
with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
    for name, src in sorted(files.items()): archive.write(src, name)
    archive.write(BASE / 'package-manifest.json', 'package-manifest.json')
with zipfile.ZipFile(destination) as archive:
    assert archive.testzip() is None
    for name, info in manifest.items():
        data = archive.read(name)
        assert len(data) == info['bytes'] and hashlib.sha256(data).hexdigest() == info['sha256']
destination.with_suffix(destination.suffix + '.sha256').write_text(sha(destination) + '  ' + destination.name + '\n')
print(json.dumps({'package': str(destination), 'bytes': destination.stat().st_size,
                  'sha256': sha(destination), 'verified_entries': len(manifest)}, indent=2))

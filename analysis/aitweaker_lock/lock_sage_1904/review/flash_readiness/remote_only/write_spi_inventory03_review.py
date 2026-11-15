"""Bind the independent manual INV03 review to final offline artifacts.

This script only reads candidates/evidence and writes this reviewer's JSON.
It does not execute a target binary or contact a device.
"""
from pathlib import Path
import hashlib
import io
import json
import sys
import warnings
import zipfile
import zlib

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[5]
CASE = BASE / 'spi_inventory_candidate03'
BUILD = CASE / 'build'
EXPECTED_SOURCE = '2f6856531adbb98403aeb4e455531c6d03149e0d426c10c62b1932bde97a442a'
EXPECTED_EFI = 'ffff289eb6e2b52ba8a53c66ffd70ff4e181443b23a1ef0b5ba60c445c50efba'
EXPECTED_ISO = 'cafd2b99a276897afa9bff0d330e2fecc58fecb5554c546e07fbdf7ef78f34e3'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def info(path):
    return {'path': path.relative_to(ROOT).as_posix(), 'sha256': sha(path), 'bytes': path.stat().st_size}

def load(path):
    return json.loads(path.read_text(encoding='utf-8'))

def source_location(text):
    lines = (CASE / 'source/inventory.c').read_text(encoding='utf-8').splitlines()
    found = [i + 1 for i, line in enumerate(lines) if text in line]
    assert len(found) == 1, (text, found)
    return {'path': (CASE / 'source/inventory.c').relative_to(ROOT).as_posix(), 'line': found[0]}

source = CASE / 'source/inventory.c'
efi = BUILD / 'BOOTX64.EFI'
iso_path = BUILD / 'SAGE1904-SPI-INVENTORY03.iso'
assert sha(source) == EXPECTED_SOURCE
assert sha(efi) == EXPECTED_EFI
assert sha(iso_path) == EXPECTED_ISO
build = load(BUILD / 'build.json')
local = load(BUILD / 'local_verification.json')
ovmf = load(BUILD / 'ovmf_verification.json')
assert build['efi_sha256'] == local['efi_sha256'] == ovmf['efi_sha256'] == EXPECTED_EFI
assert build['iso_sha256'] == ovmf['iso_sha256'] == EXPECTED_ISO
assert local['source_sha256'] == EXPECTED_SOURCE
assert local['build_sha256'] == sha(BUILD / 'build.json')
assert local['test_source_sha256'] == sha(CASE / 'verify_candidate.py')
assert ovmf['test_source_sha256'] == sha(CASE / 'verify_ovmf.py')
assert local['case_count'] == len(local['cases']) == 157
assert all(c['passed'] for c in local['cases'])
assert local['status'] == 'PASS_LOCAL_SIMULATION_ONLY'
assert ovmf['status'] == 'PASS_LOCAL_OVMF_ONLY'
assert len(ovmf['cases']) == 2
assert all(c['status'] == 'PASS_LOCAL_OVMF_ONLY' and c['owned_process_finished'] for c in ovmf['cases'])
assert sum(len(c['checks']) for c in ovmf['cases']) == 18
assert all(c['efi_sha256'] == EXPECTED_EFI and c['iso_sha256'] == EXPECTED_ISO for c in ovmf['cases'])
assert all(sha(CASE / name) == value for name, value in build['source_files'].items())
assert sha(BUILD / 'source-snapshot.zip') == build['source_archive_sha256']
with zipfile.ZipFile(BUILD / 'source-snapshot.zip') as archive:
    assert archive.testzip() is None
    assert set(archive.namelist()) == set(build['source_files'])
    assert all(hashlib.sha256(archive.read(name)).hexdigest() == value for name, value in build['source_files'].items())

for dep in ['pydeps', 'vm-pydeps', 'kvm-pydeps']:
    sys.path.insert(0, str(ROOT / 'tools' / dep))
warnings.filterwarnings('ignore', message='pkg_resources is deprecated.*')
import pycdlib
from pyfatfs.PyFatFS import PyFatFS
iso = pycdlib.PyCdlib()
iso.open(str(iso_path))
direct = io.BytesIO()
iso.get_file_from_iso_fp(direct, iso_path='/EFI/BOOT/BOOTX64.EFI;1')
assert direct.getvalue() == efi.read_bytes()
boot = io.BytesIO()
iso.get_file_from_iso_fp(boot, iso_path='/EFIBOOT.IMG;1')
assert boot.getvalue() == (BUILD / 'eltorito.img').read_bytes()
assert iso.eltorito_boot_catalog.validation_entry.platform_id == 0xef
iso.close()
with PyFatFS(str(BUILD / 'eltorito.img'), read_only=True, utc=True) as fat:
    assert fat.readbytes('/EFI/BOOT/BOOTX64.EFI') == efi.read_bytes()

old = BASE / 'spi_inventory_candidate02'
assert sha(old / 'source/inventory.c') == '20747e5fa983c34993059e052aafaae100be57a6fe7b534f3fddcd4da874a403'
assert sha(old / 'build/BOOTX64.EFI') == '9530c440c74ba13ad5294319b0e6aba647e348a4cb17122a2b8829bb0e2fbe8e'
assert sha(old / 'build/SAGE1904-SPI-INVENTORY02.iso') == 'e8f09b8665c18c1681b8ae123f9b384427bc6bce5d5052ec77654aa19d2c42f9'
old1 = BASE / 'spi_inventory_candidate'
assert sha(old1 / 'source/inventory.c') == '6d7ecec192b814ffd85805a3ea16ecf44f745e4b3d4a1674f8ad91468fe2f3df'
assert sha(old1 / 'build/BOOTX64.EFI') == '7950e97739264a395b71aea450c33274a01b0ec5411ed9ec705a5b08bfa973e0'
assert sha(old1 / 'build/SAGE1904-SPI-INVENTORY01.iso') == '7e023055a8c4e874d0e9d87a544ea948083705164b82eeafb439b1b46d8b3d8b'
helpers = ['efi_min.h', 'kvm.h', 'probe_core.c', 'probe_core.h', 'vendor/qrcodegen.c', 'vendor/qrcodegen.h', 'compat/assert.h', 'compat/string.h', 'compat/stdlib.h']
assert all((CASE / 'source/p3' / n).read_bytes() == (old / 'source/p3' / n).read_bytes() for n in helpers)
kvm02 = (old / 'source/p3/kvm.c').read_bytes()
kvm03 = (CASE / 'source/p3/kvm.c').read_bytes()
assert kvm02.replace(b'SPI INVENTORY 02', b'SPI INVENTORY 03').replace(b'SPI inventory 02', b'SPI inventory 03') == kvm03

hardware = ROOT / 'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162/hardware-spiinv02-1793673912543'
hm = load(hardware / 'manifest.json')
hb = (hardware / 'hardware-log.txt').read_bytes()
assert len(hb) == hm['bytes'] == 1644
assert f'{zlib.crc32(hb):08X}' == hm['crc32'] == '5B1EE3F2'
assert sha(hardware / 'hardware-log.txt') == hm['sha256'] == 'e4cf53695503e78c952c3968df0f9540c8804e2fa219ddb2ad8b26a24e78f4b9'
assert all(sha(hardware / n) == value for n, value in hm['files'].items())
assert hb.count(b'STATUS=0x8000000000000003') == 14
refs = load(CASE / 'root_bridge_evidence.json')
assert sha(CASE / 'root_bridge_evidence.json') == '36e7de72b38483ae0194da273ba65e2d80a6c9264a2c7901c856fdcd9a9eade6'
assert all(sha(CASE / 'source/reference_documents' / name) == value['sha256'] for name, value in refs['official_reference_files'].items())

checks = [
    ('prior_hardware_log', None, 'INV02 log/frame/image hashes and CRC all match. Exact observed PCI identity, revision, BDF, memory-decode bit and BAR are the new fallback gate. Fourteen EFI_UNSUPPORTED responses provide no FRAP/FREG/PR data and do not establish flash read protection.'),
    ('standard_abi', 'typedef ES(EA *ROOT_READ)', 'Official EDK2 header matches GUID, x64 ROOT structure slots and the five-argument Mem.Read ABI: UINT32 width, UINT64 address, UINTN count; no BarIndex. OFF assertions bind Mem.Read 0x18, Configuration 0x88 and UINT32 SegmentNumber 0x90.'),
    ('fallback_trigger', 'if(unsupported==14)', 'All fourteen primary PCI_IO.Mem.Read calls must return exactly EFI_UNSUPPORTED. Any mixed success or other error prevents root fallback. 7A24 remains eligible only for the unchanged primary path.'),
    ('target_binding', 'static int observed_target', 'Before root selection and again immediately before root reads, current GetLocation and PCI config must match 0000:00:1F.5, 8086:7AA4, revision/class 0x0C800011, enabled memory decode and BAR0 exactly 0xFE010000.'),
    ('resource_parser', 'static int root_resources', 'At most 64 QWORD descriptors, tag 0x8A, payload length43/total46, followed by EndTag0x79. Each header/body is bounded to known RAM; a conservative 4096-byte addition bound prevents wrap. Nonzero EndTag checksum validates the full stream. Resource buffers are borrowed and never freed.'),
    ('resource_meaning', 'if(type>2||(d[4]&0xf3)', 'Require consistent nonempty min/max/length, zero translation and supported positive-decode producer flags. Bus resources require granularity0, max<=255 and no specific flags. Memory requires granularity32/64, valid 32-bit maximum where applicable, and no memory-to-I/O/reserved translation bits.'),
    ('root_uniqueness', 'static ROOT *select_root', 'Enumerate at most32 standard root interfaces. An inaccessible interface or unparseable segment0 configuration makes the result uncertain and refuses fallback. Exactly one segment0 root covering bus0 and exactly one of its memory windows covering FE010000..FE010097 are required; missing methods, ambiguity or cleanup failure refuses.'),
    ('exact_reads', 'e=root->mem.read(root,2,0xfe010000ULL+offsets[i],1,&raw)', 'Only fourteen fixed aligned addresses are passed to standard RootBridgeIo.Mem.Read, each Uint32/count1. Maximum touched byte FE010097. No caller-controlled address/count, raw SPIBAR dereference or CPU_IO2 operation is present.'),
    ('metadata_scope', 'static void fallback_metadata', 'Memory map descriptions and CPU_IO2 LocateProtocol presence are metadata only. Neither grants permission nor bypasses root resources. The CPU_IO2 interface is not called.'),
    ('read_status_handling', 'static int observation', 'Failures and all-ones results remain untrusted. FDV clear or SCIP busy remains partial. Raw observations are preserved and primary failures remain visible in the log. No status clear or write is attempted.'),
    ('no_added_mutation', 'Flash bytes read=0; application PCI/MMIO write calls=0;', 'Read-only manual review found no PCI/MMIO write, SPI cycle initiation, selector write, decode enable, SetVariable, capsule, disk, file or network operation. Opaque write slots are not called. Existing standard watchdog disable and console/GOP display operations are permitted maintenance/display actions.'),
    ('artifact_binding', None, 'Final source map and archive, final EFI, both ISO EFI locations, test-source hashes and exact-EFI test reports independently verified. INV01/02 original source/EFI/ISO preserved. This reviewer did not rerun the synthetic or OVMF tests.')
]
review = {
    'status': 'INDEPENDENT_INV03_SOURCE_AND_ARTIFACT_REVIEW_COMPLETE_NO_BLOCKER_FOUND',
    'review_date': '2026-11-03',
    'reviewer': 'sage_original',
    'scope': 'Independent offline read-only review. Only this report and its binder script are written. No BMC access, hardware action, target execution, production edit or candidate edit by this reviewer.',
    'source_sha256': EXPECTED_SOURCE,
    'blocking_findings': [],
    'inputs': {
        'source': info(source), 'prior_review': info(BASE / 'spi_inventory02_source_review.json'),
        'hardware02_log': info(hardware / 'hardware-log.txt'), 'hardware02_manifest': info(hardware / 'manifest.json'),
        'root_bridge_evidence': info(CASE / 'root_bridge_evidence.json'),
        'layout_evidence': info(CASE / 'layout_evidence.json'), 'source_references': info(CASE / 'sources.json'),
        'patch': info(CASE / 'inventory02-to-03.patch'),
        'official_headers': {n: info(CASE / 'source/reference_documents' / n) for n in refs['official_reference_files']},
        'compiled_source_map': build['source_files'],
    },
    'build_binding': {
        'efi': info(efi), 'iso': info(iso_path), 'build': info(BUILD / 'build.json'),
        'source_snapshot': info(BUILD / 'source-snapshot.zip'),
        'manifest': info(CASE / 'candidate_manifest.json'),
        'review_snapshot': info(BUILD / 'review-snapshot.zip'),
        'source_map_matches': True, 'source_archive_members_match': True,
        'ISO_direct_EFI_and_ElTorito_FAT_EFI_match': True,
        'INV01_INV02_source_EFI_ISO_preserved': True,
    },
    'checks': [{'id': key, 'status': 'PASS_MANUAL_REVIEW_AND_BINDING', 'finding': finding, **({'location': source_location(token)} if token else {})} for key, token, finding in checks],
    'operation_bounds': refs['operation_bounds'],
    'resolved_during_review': [
        'Reject consumer/subtractive/reserved resource flags and memory-to-I/O translation, in addition to nonzero translation offsets.',
        'Require exactly one covering memory window instead of merely nonzero coverage.',
        'Explicitly reject resource-pointer addition overflow before bounded descriptor traversal.',
    ],
    'nonblocking_limits': [
        'Firmware-provided protocols, memory maps and SMBIOS remain trusted inputs. Standard method implementations and asynchronous firmware/SMM activity are not certified by the application no-write claim.',
        'Original PCI_IO route and fallback root reads are sequential, not an atomic hardware snapshot. The target binding is rechecked around root selection, not around every individual DWORD.',
        'Current RootBridgeIo availability, usable configuration resources and positive register reads on ASUS hardware remain unverified. Conservative parsing can refuse otherwise valid firmware layouts; missing resources are missing evidence, not proof that hardware is unreadable.',
        'A successful register inventory still proves no flash byte read, chip density/count, full dump coverage, restoration ability or modified-BIOS flash acceptance. No Boot Guard enablement/disablement is inferred.',
        'The original fourteen unsupported attempts remain in the log and warning count even when fallback returns all defined registers; screen partial-warning text must be interpreted together with explicit ROOT observations and final collection status.',
        'Only standard watchdog disable and display/keyboard handling are used outside inventory. A failed watchdog-disable call is logged; Escape returns to the boot caller. Attended maintenance and OFF-state restoration remain with the parent operator.',
    ],
    'external_validation_observed': {
        'owner': 'sage_navigation', 'local': info(BUILD / 'local_verification.json'),
        'local_status': local['status'], 'cases': 157, 'baseline_cases': 89, 'new_cases': 68,
        'all_passed': True, 'synthetic_qr_pages': local['qr_pages'],
        'synthetic_qr_bytes': local['qr_log_bytes'], 'synthetic_qr_crc32': local['qr_whole_crc32'],
        'ovmf': info(BUILD / 'ovmf_verification.json'), 'ovmf_status': ovmf['status'],
        'ovmf_cases': 2, 'ovmf_checks': 18, 'owned_qemu_processes_finished': True,
        'tests_rerun_by_reviewer': False, 'no_hardware_pass_inferred': True,
    },
    'independent_primary_source_crosschecks': [
        'https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/Protocol/PciRootBridgeIo.h',
        'https://raw.githubusercontent.com/tianocore/edk2/master/MdePkg/Include/IndustryStandard/Acpi10.h',
        'https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdeModulePkg/Bus/Pci/PciHostBridgeDxe/PciRootBridgeIo.c',
    ],
    'decision': {
        'source_or_artifact_blocker_found': False,
        'suitable_for_attended_authorized_register_inventory_boot': True,
        'qualification': 'Exact reviewed INV03 only. Missing target/resource/interface prerequisites refuse. No flash dump, protection change, erase/program, modified-BIOS deployment or recovery success is authorized or established by this review.',
        'hardware_access_by_reviewer': False, 'candidate_or_production_modified_by_reviewer': False,
    },
    'review_binder': info(Path(__file__).resolve()),
}
out = BASE / 'spi_inventory03_source_review.json'
out.write_text(json.dumps(review, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
print(json.dumps({'status': review['status'], 'report': info(out)}, indent=2))

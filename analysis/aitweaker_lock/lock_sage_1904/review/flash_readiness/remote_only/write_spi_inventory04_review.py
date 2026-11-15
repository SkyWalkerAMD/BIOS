"""Write the independent INV04 review after checking exact artifact bindings.

Reads local files only; does not execute EFI code, use BMC or modify candidates.
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
CASE = BASE / 'spi_inventory_candidate04'
BUILD = CASE / 'build'
PIN_SOURCE = 'cdee28b549b0d99939425e08021860b71ab826d9fa0048a131e28bc763910c54'
PIN_EFI = 'd64b934a06668b777b78663a786ff2287b8e062abdb883624071eb3e3451e3a0'
PIN_ISO = 'fd3a3f691c2a1823823ae8829f27729294451b123f9cc651efb06ccce5939a00'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
load = lambda p: json.loads(p.read_text(encoding='utf-8'))
def info(p):
    return {'path': p.relative_to(ROOT).as_posix(), 'sha256': sha(p), 'bytes': p.stat().st_size}
source = CASE / 'source/inventory.c'
lines = source.read_text(encoding='utf-8').splitlines()
def loc(token):
    found = [i + 1 for i, line in enumerate(lines) if token in line]
    assert len(found) == 1, (token, found)
    return {'path': source.relative_to(ROOT).as_posix(), 'line': found[0]}

efi = BUILD / 'BOOTX64.EFI'
iso_path = BUILD / 'SAGE1904-SPI-INVENTORY04.iso'
assert sha(source) == PIN_SOURCE and sha(efi) == PIN_EFI and sha(iso_path) == PIN_ISO
prelabel = source.read_bytes().replace(b'CPU_IO2_DISCOVERY=PRESENT', b'CPU_IO2=PRESENT_NOT_CALLED').replace(b'CPU_IO2_DISCOVERY=UNAVAILABLE', b'CPU_IO2=UNAVAILABLE')
assert hashlib.sha256(prelabel).hexdigest() == '2b43da24f756acf5b7872541b9ebb49bc7f582dfdfb2f4d6df8730935c249df2'
assert sha(CASE / 'cpu_io_evidence.json') == 'bac58e88a334e5ca7ef7b7909903182f6d8de287a5d42e54b207ffed2007693a'
build = load(BUILD / 'build.json')
local = load(BUILD / 'local_verification.json')
ovmf = load(BUILD / 'ovmf_verification.json')
assert build['efi_sha256'] == local['efi_sha256'] == ovmf['efi_sha256'] == PIN_EFI
assert build['iso_sha256'] == ovmf['iso_sha256'] == PIN_ISO
assert local['source_sha256'] == PIN_SOURCE and local['build_sha256'] == sha(BUILD / 'build.json')
assert local['test_source_sha256'] == sha(CASE / 'verify_candidate.py')
assert ovmf['test_source_sha256'] == sha(CASE / 'verify_ovmf.py')
assert local['status'] == 'PASS_LOCAL_SIMULATION_ONLY' and local['case_count'] == len(local['cases']) == 223
assert all(c['passed'] for c in local['cases'])
assert ovmf['status'] == 'PASS_LOCAL_OVMF_ONLY' and len(ovmf['cases']) == 2
assert all(c['status'] == 'PASS_LOCAL_OVMF_ONLY' and c['owned_process_finished'] for c in ovmf['cases'])
assert sum(len(c['checks']) for c in ovmf['cases']) == 18
assert all(c['efi_sha256'] == PIN_EFI and c['iso_sha256'] == PIN_ISO for c in ovmf['cases'])
assert all(sha(CASE / n) == s for n, s in build['source_files'].items())
assert sha(BUILD / 'source-snapshot.zip') == build['source_archive_sha256']
with zipfile.ZipFile(BUILD / 'source-snapshot.zip') as z:
    assert z.testzip() is None and set(z.namelist()) == set(build['source_files'])
    assert all(hashlib.sha256(z.read(n)).hexdigest() == s for n, s in build['source_files'].items())
with zipfile.ZipFile(BUILD / 'review-snapshot.zip') as z:
    assert z.testzip() is None
for dep in ['pydeps', 'vm-pydeps', 'kvm-pydeps']:
    sys.path.insert(0, str(ROOT / 'tools' / dep))
warnings.filterwarnings('ignore', message='pkg_resources is deprecated.*')
import pycdlib
from pyfatfs.PyFatFS import PyFatFS
iso = pycdlib.PyCdlib()
iso.open(str(iso_path))
b = io.BytesIO()
iso.get_file_from_iso_fp(b, iso_path='/EFI/BOOT/BOOTX64.EFI;1')
assert b.getvalue() == efi.read_bytes()
b = io.BytesIO()
iso.get_file_from_iso_fp(b, iso_path='/EFIBOOT.IMG;1')
assert b.getvalue() == (BUILD / 'eltorito.img').read_bytes()
assert iso.eltorito_boot_catalog.validation_entry.platform_id == 0xef
iso.close()
with PyFatFS(str(BUILD / 'eltorito.img'), read_only=True, utc=True) as fat:
    assert fat.readbytes('/EFI/BOOT/BOOTX64.EFI') == efi.read_bytes()

old_pins = [
    ('spi_inventory_candidate', '01', '6d7ecec192b814ffd85805a3ea16ecf44f745e4b3d4a1674f8ad91468fe2f3df', '7950e97739264a395b71aea450c33274a01b0ec5411ed9ec705a5b08bfa973e0', '7e023055a8c4e874d0e9d87a544ea948083705164b82eeafb439b1b46d8b3d8b'),
    ('spi_inventory_candidate02', '02', '20747e5fa983c34993059e052aafaae100be57a6fe7b534f3fddcd4da874a403', '9530c440c74ba13ad5294319b0e6aba647e348a4cb17122a2b8829bb0e2fbe8e', 'e8f09b8665c18c1681b8ae123f9b384427bc6bce5d5052ec77654aa19d2c42f9'),
    ('spi_inventory_candidate03', '03', '2f6856531adbb98403aeb4e455531c6d03149e0d426c10c62b1932bde97a442a', 'ffff289eb6e2b52ba8a53c66ffd70ff4e181443b23a1ef0b5ba60c445c50efba', 'cafd2b99a276897afa9bff0d330e2fecc58fecb5554c546e07fbdf7ef78f34e3'),
]
for folder, version, s, e, i in old_pins:
    p = BASE / folder
    assert sha(p / 'source/inventory.c') == s and sha(p / 'build/BOOTX64.EFI') == e
    assert sha(p / f'build/SAGE1904-SPI-INVENTORY{version}.iso') == i
old = BASE / 'spi_inventory_candidate03'
helpers = ['efi_min.h', 'kvm.h', 'probe_core.c', 'probe_core.h', 'vendor/qrcodegen.c', 'vendor/qrcodegen.h', 'compat/assert.h', 'compat/string.h', 'compat/stdlib.h']
assert all((CASE / 'source/p3' / n).read_bytes() == (old / 'source/p3' / n).read_bytes() for n in helpers)
assert (old / 'source/p3/kvm.c').read_bytes().replace(b'SPI INVENTORY 03', b'SPI INVENTORY 04').replace(b'SPI inventory 03', b'SPI inventory 04') == (CASE / 'source/p3/kvm.c').read_bytes()

hardware = ROOT / 'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162/hardware-spiinv03-1793675560232'
hm = load(hardware / 'manifest.json')
hb = (hardware / 'hardware-log.txt').read_bytes()
assert hm['pages'] == 7 and hm['bytes'] == len(hb) == 5019
assert hm['crc32'] == f'{zlib.crc32(hb):08X}' == 'BABC7EE1'
assert hm['sha256'] == sha(hardware / 'hardware-log.txt') == '0561747f769d4db43c689c12071d9912d2bb4ff721aefe9897da1e5d76ed87d9'
assert all(sha(hardware / n) == s for n, s in hm['files'].items())
assert b'ROOT_OBSERVATIONS_BEGIN' not in hb and b'CPU_IO2=PRESENT_NOT_CALLED' in hb
native_path = BASE / 'cpuio2_native/native_review.json'
assert sha(native_path) == '528503ed795ba75848ec968eff18d3dceb816f9a8bff5cb839dd81995aa6f145'
native = load(native_path)
assert native['synthetic_execution']['case_count'] == 21
assert all(c['passed'] and c['MMIO_writes'] == 0 for c in native['synthetic_execution']['cases'])
assert sha(BASE / 'cpuio2_native/OriginalCpuIo2.efi') == native['inputs']['EFI']['sha256']
assert sha(BASE / 'cpuio2_native/verify_native.py') == native['inputs']['verification_source_sha256']

checks = [
    ('hardware_binding', None, 'INV03 seven-page log and all manifest members verify. It records the exact 7AA4/rev/BDF/BAR, one covering type11 page FE010000..FE010FFF with attributes8000000000000001 and CPU_IO2 presence. Neither RootMem.Read nor CPU_IO2.Read ran. The omitted bus granularity means the previous resource-refusal reason was not established by that log.'),
    ('standard_CPU_IO2_ABI', 'typedef ES(EA *CPU_READ)', 'Mem.Read is slot0 of the 32-byte CPU_IO2 interface. Five arguments match the official header: This, UINT32 Width, UINT64 Address, UINTN Count, Buffer. Width32=2. Write and port-I/O slots remain opaque and uncalled. Application remains in Boot Services.'),
    ('route_selection', 'if(!root){put("ROOT_FALLBACK=REFUSED_RESOURCE_EVIDENCE', 'CPU path is considered only after all fourteen primary PCI_IO reads return EFI_UNSUPPORTED and no root read was performed. Mixed primary errors/success, a changed target, RootRead success or RootRead error do not lead to CPU reads.'),
    ('root_rules_preserved', 'static int root_reason', 'Root parsing rules are unchanged. Added GRAN and distinct refusal reasons improve diagnostics; nonzero bus granularity and every previous unsupported resource condition remain rejected.'),
    ('fresh_memory_map', 'static int cpu_map_gate', 'GetMemoryMap refresh has bounded64KiB storage, descriptor stride40..256, version1 and integral nonempty layout. Every physical range must have an allowed type, aligned start, nonzero pages and nonoverflowing size. Exactly one descriptor may overlap the target page, and it must exactly match type11, physicalFE010000, one page and observed attributes8000000000000001.'),
    ('capability_not_permission', 'CPU_MAP_GATE=EXACT_OBSERVED_TYPE11_UC_RUNTIME_PAGE', 'Resource matching is explicitly described as matching observed capabilities. It does not change attributes or claim active caching/access permission. Any extra or partial overlap, broader range, wrong type or other attribute value refuses.'),
    ('CPU_interface_selection', 'static CPU *select_cpu', 'Require exactly one CPU_IO2 handle and valid mapped handle data. HandleProtocol and FreePool must succeed. Re-fetch the map after lookup/free, revalidate SMBIOS and exact PCI identity/BDF/revclass/decode/BAR before accepting a RAM-bounded32-byte interface.'),
    ('method_mapping', 'static int cpu_method_in_code', 'Nonzero Mem.Read pointer must lie in exactly one BootServicesCode or RuntimeServicesCode descriptor and not report RP or XP. This is a mapped-code check, not a cryptographic proof of which firmware module supplies the live method.'),
    ('fixed_CPU_reads', 'ES e=cpu->mem.read(cpu,2,0xfe010000ULL+register_offsets[i],1,&raw)', 'The only CPU operation is Mem.Read at fourteen fixed, DWORD-aligned status-register addresses from FE010000 through FE010094, each Width32/count1. There is no arbitrary physical pointer dereference, user-supplied range or CPU port-I/O call.'),
    ('stop_on_untrusted_result', 'CPU_OBSERVATIONS_STOPPED_ON_ERROR;', 'First API error, all-ones result, FDV clear or SCIP busy ends CPU inventory immediately with partial/refused status. No further interface, retry route, raw read or register/flash write follows.'),
    ('native_original_evidence', None, 'Exact official1904 CAP extraction identifies the CPU_IO2 producer and registration table. Original Mem.Read3D4 calls only parameter check30C; Width32 loads one DWORD at44C and stores to caller output at44E. Twenty-one original-machine-code synthetic cases and registration emulation passed, with no synthetic MMIO writes. Separate Mem.Write/Io.Write methods exist but are not reached by this path.'),
    ('write_boundary', 'Flash bytes read=0; application PCI/MMIO write calls=0;', 'Manual source review found no PCI/MMIO write call, attribute change, unhide, SPI cycle command, flash byte read/program, SetVariable, file, network or capsule action. Existing watchdog disable, allocation/free and display operations retain their limited maintenance/UI purpose.'),
    ('artifact_binding', None, 'Pinned source/EFI/ISO, build-source map, source zip, both EFI locations in the ISO and final test sources/reports are checked. Old INV01/02/03 inputs are unchanged. This review did not rerun navigation agent tests or touch a device.'),
]
review = {
    'status': 'INDEPENDENT_INV04_CPU_IO2_SOURCE_AND_ARTIFACT_REVIEW_COMPLETE_NO_BLOCKER_FOUND',
    'review_date': '2026-11-03', 'reviewer': 'sage_original', 'source_sha256': PIN_SOURCE,
    'scope': 'Independent offline source/artifact review plus separately recorded original-firmware disassembly and synthetic native-path verification. No hardware connection, BMC action, production or candidate mutation.',
    'blocking_findings': [],
    'inputs': {'source': info(source), 'prior_review': info(BASE / 'spi_inventory03_source_review.json'), 'hardware03_log': info(hardware / 'hardware-log.txt'), 'hardware03_manifest': info(hardware / 'manifest.json'), 'patch': info(CASE / 'inventory03-to-04.patch'), 'source_references': info(CASE / 'sources.json'), 'cpu_io_evidence': info(CASE / 'cpu_io_evidence.json'), 'compiled_source_map': build['source_files'], 'native_review': info(native_path), 'native_EFI': info(BASE / 'cpuio2_native/OriginalCpuIo2.efi'), 'native_verifier': info(BASE / 'cpuio2_native/verify_native.py'), 'REA_status': info(BASE / 'cpuio2_native/rea_status.json')},
    'final_label_change_verified': 'Reversing only the two CPU_IO2_DISCOVERY log strings reproduces the exact independently reviewed prelabel source SHA2b43da24f756acf5b7872541b9ebb49bc7f582dfdfb2f4d6df8730935c249df2. No implementation change occurred at finalization.',
    'checks': [{'id': key, 'status': 'PASS_MANUAL_REVIEW_AND_BINDING', 'finding': finding, **({'location': loc(token)} if token else {})} for key, token, finding in checks],
    'build_binding': {'efi': info(efi), 'iso': info(iso_path), 'build': info(BUILD / 'build.json'), 'source_snapshot': info(BUILD / 'source-snapshot.zip'), 'manifest': info(CASE / 'candidate_manifest.json'), 'review_snapshot': info(BUILD / 'review-snapshot.zip'), 'source_map_and_archive_match': True, 'ISO_direct_and_ElTorito_FAT_EFI_match': True, 'INV01_INV02_INV03_preserved': True},
    'external_validation_observed': {'owner': 'sage_navigation', 'local': info(BUILD / 'local_verification.json'), 'cases': 223, 'prior_baseline': 157, 'CPU_additional_cases': 66, 'all_passed': True, 'synthetic_qr_pages': local['qr_pages'], 'synthetic_qr_bytes': local['qr_log_bytes'], 'synthetic_qr_crc32': local['qr_whole_crc32'], 'ovmf': info(BUILD / 'ovmf_verification.json'), 'ovmf_cases': 2, 'ovmf_checks': 18, 'owned_qemu_processes_finished': True, 'tests_rerun_by_reviewer': False, 'no_hardware_pass_inferred': True},
    'nonblocking_limits': [
        'Firmware protocols, memory-map declarations and SMBIOS remain trusted. Exact resource matching reduces scope; it does not guarantee active caching, hardware access permission, absence of SMM activity or lack of read side effects.',
        'Original module evidence does not prove live CPU_IO2 pointer identity or that no firmware extension replaced it. Candidate checks mapped code and standard protocol selection, not a native module hash.',
        'The CPU_IO2 provider has general arithmetic/alignment checks and no board allowlist. Candidate identity, fresh memory-map and constant-address gates are essential.',
        'Reads are sequential, not atomic. Identity and BAR are rechecked before the read loop; asynchronous changes between individual reads are not excluded.',
        'Strict map type/size/attributes, code mapping and SMBIOS checks may refuse a valid but different environment. Refusal is missing evidence for this path, not a claim that the flash is unreadable.',
        'No actual CPU_IO2 register read has passed on hardware at review time. Successful inventory would not constitute a flash dump, chip capacity/count, verified permissions for flash bytes, restore capability or permission to flash modified firmware.',
        'REA opened the original PE successfully but analyze_function timed out at180s and close_binary succeeded. No successful REA decompilation is claimed; exact machine-code evidence is recorded separately.',
        'Existing warning counts preserve primary/Root refusals. Assess explicit CPU observations and final collection status together; display partial labels alone are not a full result summary. Escape returns to the boot caller; attended maintenance cleanup remains parent-owned.',
    ],
    'primary_references': ['https://github.com/tianocore/edk2/blob/edk2-stable202502/MdePkg/Include/Protocol/CpuIo2.h', 'https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/Uefi/UefiSpec.h'],
    'decision': {'source_or_artifact_blocker_found': False, 'suitable_for_attended_authorized_register_inventory_boot': True, 'qualification': 'Exact reviewed INV04 only, with runtime gates unchanged. Does not authorize raw physical reads, register/flash writes, backup/recovery claims or modified-BIOS deployment.', 'hardware_access_by_reviewer': False, 'candidate_or_production_modified_by_reviewer': False},
    'review_binder': info(Path(__file__).resolve()),
}
out = BASE / 'spi_inventory04_source_review.json'
out.write_text(json.dumps(review, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
print(json.dumps({'status': review['status'], 'report': info(out)}, indent=2))

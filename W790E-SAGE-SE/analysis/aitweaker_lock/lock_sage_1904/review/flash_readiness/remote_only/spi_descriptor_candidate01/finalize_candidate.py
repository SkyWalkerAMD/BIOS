"""Bind the tested FD01 binary to its local evidence, before hardware launch."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
HW = HERE.parents[3] / 'remote_172_20_2_162'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read(name):
    return json.loads((HERE / name).read_text(encoding='utf-8'))

def main():
    build = read('build/build.json')
    efi = HERE / 'build/BOOTX64.EFI'
    iso = HERE / 'build/SAGE1904-SPI-DESCRIPTOR01.iso'
    assert sha(efi) == build['efi_sha256'] == '20a9c111dc048805b62261bdee7438a573a0a5a2846d2a57bc4f6cfbda4c3c48'
    assert sha(iso) == build['iso_sha256'] == '769e5a900de23fec97a99697ff9396e33e5246c8ac4e1b283245b03719116160'
    assert build['iso_embedded_efi_verified']
    for name, digest in build['source_files'].items():
        assert sha(HERE / name) == digest, name
    core = read('core_regression.json')
    frontend = read('frontend_regression.json')
    qr = read('transport_regression.json')
    ovmf = read('build/ovmf_verification.json')
    parser = read('parser_regression.json')
    assert core['case_count'] == 90 and frontend['case_count'] == 35
    for result in (core, frontend):
        assert all(case['passed'] for case in result['cases'])
    for result in (core, frontend, qr, ovmf):
        assert result['efi_sha256'] == sha(efi)
    assert core['verification_source_sha256'] == sha(HERE / 'verify_core.py')
    assert frontend['verification_source_sha256'] == sha(HERE / 'verify_frontend.py')
    assert qr['test_source_sha256'] == sha(HERE / 'verify_transport.py')
    assert qr['roundtrip_identical'] and qr['missing_and_corrupt_page_rejected']
    assert ovmf['test_source_sha256'] == sha(HERE / 'verify_ovmf.py')
    assert len(ovmf['cases']) == 2 and all(c['status'] == 'PASS_LOCAL_OVMF_ONLY' and len(c['checks']) == 9 for c in ovmf['cases'])
    assert parser['status'] == 'PASS'
    assert parser['parser_sha256'] == sha(HW / 'read_spi_descriptor01_qr.py')
    files = sorted(p for p in (HERE / 'source').rglob('*') if p.is_file())
    files += sorted(HERE.glob('*.py'))
    files += [HERE / n for n in ['sources.json', 'build/build.json', 'core_regression.json',
              'frontend_regression.json', 'transport_regression.json', 'parser_regression.json',
              'build/ovmf_verification.json', 'build/qr_test.dll']]
    files += [efi, iso, HW / 'read_spi_descriptor01_qr.py', HW / 'operations/capture_spi_descriptor01.mjs']
    data = {
        'status': 'LOCAL_TESTS_PASSED_AWAITING_PHYSICAL_CAPTURE',
        'application': 'SPI-DESCRIPTOR-01', 'board': 'ASUS Pro WS W790E-SAGE SE', 'bios': '1904',
        'hardware_tested': False, 'firmware_flashing_performed': False,
        'scope': 'Read only FLA 0x00000000..0x00000FFF twice with fixed READ64 cycles; QR export only.',
        'controller_effects': 'DWORD MMIO writes to FADDR and HSFSTS_CTL only. The latter repeats the measured lock values and acknowledges FDONE; no permission change, flash program/erase, WREN or WRSR.',
        'failure_policy': 'Unexpected state, timeout or ambiguous command completion stops without another controller write. Restoration occurs only after all 128 cycles complete in a known-idle state.',
        'test_counts': {'compiled_core_synthetic': 90, 'complete_EFI_original_CPU_IO2_synthetic': 35,
                        'OVMF_cases': 2, 'OVMF_assertions': 18, 'synthetic_QR_pages': 15},
        'artifact_bindings': [{'path': str(p), 'bytes': p.stat().st_size, 'sha256': sha(p)} for p in files],
        'limits': ['No exclusive controller ownership against SMM is established.',
                   'No physical acceptance is inferred from synthetic or OVMF tests.',
                   'A 4 KiB descriptor is not a full SPI backup or a proven recovery route.',
                   'Descriptor density fields are configuration, not independent JEDEC/SFDP capacity proof.']
    }
    out = HERE / 'candidate_manifest.json'
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': data['status'], 'manifest_sha256': sha(out), 'bindings': len(files)}))

if __name__ == '__main__':
    main()

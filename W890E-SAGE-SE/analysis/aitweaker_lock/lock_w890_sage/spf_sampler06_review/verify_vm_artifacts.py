"""Read-only reassembly of captured VM QR pages and ISO/FAT artifact binding."""
from pathlib import Path
import hashlib
import io
import json
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = HERE.parents[3]
D7 = BASE / 'diagnostic_delta07'
LEGACY = ROOT / 'analysis/aitweaker_lock/probe_p3_kvm'
for p in ('pydeps', 'vm-pydeps', 'kvm-pydeps'):
    sys.path.insert(0, str(ROOT / 'tools' / p))
sys.path.insert(0, str(LEGACY))
sys.path.insert(0, str(D7))
import pycdlib
from decode_captures import read_image, assemble
from transport import parse
from decode_packet import CPU, NVME, SOCKET


def digest(data):
    return hashlib.sha256(data).hexdigest()


def binding(path):
    path = Path(path)
    data = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(data), 'sha256': digest(data)}


def extract_fat16_efi(image):
    u16 = lambda at: struct.unpack_from('<H', image, at)[0]
    u32 = lambda at: struct.unpack_from('<I', image, at)[0]
    sector = u16(11)
    per_cluster = image[13]
    reserved = u16(14)
    fats = image[16]
    entries = u16(17)
    fat_sectors = u16(22)
    assert sector == 512 and per_cluster and fats and fat_sectors
    fat_start = reserved * sector
    root_start = (reserved + fats * fat_sectors) * sector
    root_size = ((entries * 32 + sector - 1) // sector) * sector
    data_start = root_start + root_size
    cluster_size = sector * per_cluster

    def chain(cluster):
        seen = set()
        data = bytearray()
        while 2 <= cluster < 0xfff8:
            assert cluster not in seen and cluster != 0xfff7
            seen.add(cluster)
            start = data_start + (cluster - 2) * cluster_size
            assert start + cluster_size <= len(image)
            data += image[start:start + cluster_size]
            assert fat_start + cluster * 2 + 2 <= root_start
            cluster = u16(fat_start + cluster * 2)
        assert cluster >= 0xfff8
        return bytes(data)

    def find(directory, name):
        hits = []
        for at in range(0, len(directory), 32):
            entry = directory[at:at + 32]
            if not entry or entry[0] == 0:
                break
            if entry[0] == 0xe5 or entry[11] == 0xf:
                continue
            if entry[:11] == name:
                hits.append(entry)
        assert len(hits) == 1
        record = hits[0]
        data = chain(struct.unpack_from('<H', record, 26)[0])
        return data, struct.unpack_from('<I', record, 28)[0], record[11]

    directory, _, attrs = find(image[root_start:root_start + root_size], b'EFI        ')
    assert attrs & 0x10
    directory, _, attrs = find(directory, b'BOOT       ')
    assert attrs & 0x10
    data, size, attrs = find(directory, b'BOOTX64 EFI')
    assert not attrs & 0x10 and size <= len(data)
    return data[:size]


def main():
    out = D7 / 'build'
    efi = (out / 'BOOTX64.EFI').read_bytes()
    iso_path = out / 'W890-DELTA07-STRUCTURE-NOFLASH.iso'
    before = binding(iso_path)
    iso = pycdlib.PyCdlib()
    iso.open(str(iso_path))
    stream = io.BytesIO()
    iso.get_file_from_iso_fp(stream, iso_path='/EFI/BOOT/BOOTX64.EFI;1')
    assert stream.getvalue() == efi
    stream = io.BytesIO()
    iso.get_file_from_iso_fp(stream, iso_path='/EFIBOOT.IMG;1')
    iso.close()
    fat_image = stream.getvalue()
    assert fat_image == (out / 'efiboot.img').read_bytes()
    assert extract_fat16_efi(fat_image) == efi
    selection_path = D7 / 'selection_hardware02.json'
    selection = json.loads(selection_path.read_text())
    payload = selection['payload']
    baselines = {g: (BASE / 'foreign_hii05/blobs' / f'{name}_0.forms.bin').read_bytes()
                 for g, name in ((CPU, 'GetCpuInfo'), (NVME, 'NvmeDynamicSetup'), (SOCKET, 'SocketSetup'))}
    vm_path = out / 'ovmf_tests.json'
    vm = json.loads(vm_path.read_text())
    assert vm['passed'] and len(vm['results']) == 2
    assert vm['frozen_verifier_sha256'] == binding(LEGACY / 'verify_vm.py')['sha256']
    records = []
    paths = [vm_path, D7 / 'verify_vm.py', LEGACY / 'verify_vm.py',
             LEGACY / 'decode_captures.py', selection_path, out / 'BOOTX64.EFI', iso_path]
    for result in vm['results']:
        assert result['passed'] and result['efi_sha256'] == digest(efi)
        assert result['iso_sha256_before'] == result['iso_sha256_after'] == before['sha256']
        folder = out / result['folder']
        images = sorted(folder.glob('qr-*.png'))
        frames = [read_image(p) for p in images]
        restored, metadata = assemble(frames)
        assert restored == (folder / 'RESTORED-LOG.TXT').read_bytes()
        assert metadata == result['qr_restoration']
        serial = (folder / 'serial.log').read_bytes()
        assert restored == serial.split(b'KVM_LOG_BEGIN\r\n', 1)[1].split(b'KVM_LOG_END\r\n', 1)[0]
        decoded = parse(restored, payload['targets'], bytes.fromhex(payload['source_log_sha256']),
                        bytes.fromhex(selection['selection_sha256']), baselines, 15360)
        assert decoded['environment']['map'] == 'READY'
        assert decoded['refused'] == [1, 2, 3, 4, 5]
        assert decoded['spf']['carrier_state'] == 'MODULE_UNAVAILABLE'
        assert 'escape_exit' in result['controls_checked'] and b'P3 KVM ended.' in serial
        records.append({'run': result['name'], 'pages_independently_decoded': len(images),
                        'bytes': len(restored), 'sha256': digest(restored),
                        'spfs_absent_correctly_reported': True,
                        'console_matches_images': True,
                        'reported_controls': result['controls_checked']})
        paths += images + [folder / 'RESTORED-LOG.TXT', folder / 'serial.log',
                           folder / 'command.json', folder / 'result.json']
    assert binding(iso_path) == before
    report = {'status': 'PASS_EXISTING_VM_EVIDENCE_REDECODED_AND_OPTICAL_ARTIFACT_BOUND',
              'efi_sha256': digest(efi), 'iso_sha256': before['sha256'],
              'iso_direct_efi_equals_artifact': True, 'eltorito_fat_efi_equals_artifact': True,
              'vm_checks': records, 'bindings': [binding(p) for p in dict.fromkeys(paths)],
              'limits': ['This verifier re-decodes existing actual VM screenshots; it does not start a new VM.',
                         'OVMF has no target AMITSE/SPF. These runs prove boot, bounded missing-target output, QR transport and exit, not physical source content.',
                         'ISO and EFI remain diagnostics, not a BIOS capsule or deployment approval.']}
    target = HERE / 'vm_artifacts_review.json'
    target.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'report': binding(target)}, indent=2))


if __name__ == '__main__':
    main()

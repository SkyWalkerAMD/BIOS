"""Read-only independent ISO/FAT and raw QR evidence check.

Does not import or execute the candidate's builder, runner or QR decoder.
Only this review directory is written. QEMU is not launched by this script.
"""
from pathlib import Path
import hashlib, io, json, re, struct, sys, zlib

HERE = Path(__file__).resolve().parent
PROBE = HERE.parent / 'prerequisite_probe04'
ROOT = next(p for p in HERE.parents if (p / 'tools/pydeps').is_dir())
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT / 'tools/vm-pydeps'), str(ROOT / 'tools/kvm-pydeps')]
import pycdlib
from PIL import Image
import zxingcpp

sha = lambda raw: hashlib.sha256(raw).hexdigest()
sha_file = lambda path: sha(Path(path).read_bytes())
u16 = lambda raw, at: struct.unpack_from('<H', raw, at)[0]
u32 = lambda raw, at: struct.unpack_from('<I', raw, at)[0]


def fat16_files(raw):
    """Read the simple FAT16 image without mounting it or opening it writable."""
    assert raw[510:512] == b'\x55\xaa'
    bps, spc, reserved, count, roots, fatsz = u16(raw, 11), raw[13], u16(raw, 14), raw[16], u16(raw, 17), u16(raw, 22)
    total = u16(raw, 19) or u32(raw, 32)
    assert bps == 512 and spc in (1, 2, 4, 8, 16, 32, 64, 128) and count == 2 and reserved > 0 and fatsz > 0
    root_sectors = (roots * 32 + bps - 1) // bps
    root_at = (reserved + count * fatsz) * bps
    data_at = root_at + root_sectors * bps
    clusters = (total - data_at // bps) // spc
    assert 4085 <= clusters < 65525 and total * bps == len(raw)
    first = raw[reserved * bps:(reserved + fatsz) * bps]
    assert first == raw[(reserved + fatsz) * bps:(reserved + 2 * fatsz) * bps]
    used, files = set(), {}
    def chain(cluster):
        result, seen = bytearray(), set()
        while cluster < 0xfff8:
            assert 2 <= cluster < clusters + 2 and cluster not in seen and cluster not in used
            seen.add(cluster); used.add(cluster)
            at = data_at + (cluster - 2) * spc * bps
            result += raw[at:at + spc * bps]
            cluster = u16(first, cluster * 2)
        return bytes(result)
    def directory(data, prefix):
        for offset in range(0, len(data), 32):
            entry = data[offset:offset + 32]
            if not entry[0]: break
            if entry[0] == 0xe5 or entry[11] == 0xf or entry[11] & 8: continue
            name = entry[:8].decode('ascii').rstrip()
            ext = entry[8:11].decode('ascii').rstrip()
            if name in ('.', '..'): continue
            if ext: name += '.' + ext
            assert u16(entry, 20) == 0
            path = prefix + '/' + name
            payload = chain(u16(entry, 26))
            if entry[11] & 16:
                directory(payload, path)
            else:
                size = u32(entry, 28)
                assert size <= len(payload) and path not in files
                files[path] = payload[:size]
    directory(raw[root_at:root_at + roots * 32], '')
    return files


FRAME = re.compile(rb'^AITWK-P3-KVM\nT=([0-9]+);C=([0-9A-F]{8});P=([0-9]+)/([0-9]+);O=([0-9]+);N=([0-9]+);D=([0-9A-F]{8})\n\n')


def main():
    build = json.loads((PROBE / 'build/build.json').read_text(encoding='utf8'))
    report_path = PROBE / 'ovmf_report.json'
    report = json.loads(report_path.read_text(encoding='utf8'))
    assert report['status'] == 'PASS_ACTUAL_EFI_ISO_OVMF_BOOT_TRANSPORT' and report['error'] is None
    efi = (PROBE / 'build/SageNative13Prerequisite04.efi').read_bytes()
    iso = (PROBE / 'build/SAGE-N13-OWNED-PREREQUISITE04.iso').read_bytes()
    boot = (PROBE / 'build/readonly-efiboot.img').read_bytes()
    assert sha(efi) == build['efi_sha256'] == report['efi_sha256']
    assert sha(iso) == build['iso_sha256'] == report['iso_sha256']
    assert sha(boot) == build['boot_image_sha256']
    disc = pycdlib.PyCdlib(); disc.open_fp(io.BytesIO(iso))
    names = []
    for root, dirs, files in disc.walk(iso_path='/'):
        names.extend(root.rstrip('/') + '/' + name for name in files)
        assert not dirs
    assert set(names) == {'/BOOT.CAT;1', '/EFIBOOT.IMG;1'}, names
    embedded = io.BytesIO(); disc.get_file_from_iso_fp(embedded, iso_path='/EFIBOOT.IMG;1'); disc.close()
    assert embedded.getvalue() == boot
    catalog_lba = None
    for sector in range(16, 64):
        record = iso[sector * 2048:(sector + 1) * 2048]
        assert record[1:6] == b'CD001'
        if record[0] == 0 and record[7:39].rstrip(b'\0 ') == b'EL TORITO SPECIFICATION':
            catalog_lba = u32(record, 71)
        if record[0] == 255: break
    assert catalog_lba is not None
    catalog = iso[catalog_lba * 2048:(catalog_lba + 1) * 2048]
    assert catalog[0] == 1 and catalog[1] == 0xef and catalog[30:32] == b'\x55\xaa'
    assert sum(struct.unpack('<16H', catalog[:32])) & 0xffff == 0
    assert catalog[32] == 0x88 and catalog[33] == 0 and u16(catalog, 38) * 512 == len(boot)
    image_lba = u32(catalog, 40)
    assert iso[image_lba * 2048:image_lba * 2048 + len(boot)] == boot
    fat_files = fat16_files(boot)
    assert set(fat_files) == {'/EFI/BOOT/BOOTX64.EFI'} and fat_files['/EFI/BOOT/BOOTX64.EFI'] == efi

    run = Path(report['run'])
    command = json.loads((run / 'command.json').read_text(encoding='utf8'))
    assert command[command.index('-nic') + 1] == 'none'
    drives = [command[i + 1] for i, token in enumerate(command) if token == '-drive']
    assert len(drives) == 3
    assert sum('if=pflash' in value for value in drives) == 2
    assert any('unit=0,readonly=on' in value for value in drives)
    assert any(value.endswith('file=' + str(run / 'vars.fd')) for value in drives)
    assert any(value.startswith('media=cdrom,readonly=on,file=') and value.endswith(str(PROBE / 'build/SAGE-N13-OWNED-PREREQUISITE04.iso')) for value in drives)
    parts, records, identity = {}, [], None
    for record in report['screens']:
        path = Path(record['path'])
        assert sha_file(path) == record['sha256']
        with Image.open(path) as image:
            found = zxingcpp.read_barcodes(image.convert('RGB'), formats=zxingcpp.BarcodeFormat.QRCode)
        frames = [bytes(item.bytes) for item in found if bytes(item.bytes).startswith(b'AITWK-P3-KVM\n')]
        assert len(frames) == 1
        raw = frames[0]; match = FRAME.match(raw); assert match
        total, crc, page, pages, offset, length, fragment_crc = match.groups()
        total, page, pages, offset, length = map(int, (total, page, pages, offset, length))
        crc, fragment_crc = int(crc, 16), int(fragment_crc, 16)
        payload = raw[match.end():]
        assert 0 < total <= 24575 and pages == (total + 767) // 768 and 1 <= page <= pages
        assert offset == (page - 1) * 768 and length == min(768, total - offset) == len(payload)
        assert zlib.crc32(payload) == fragment_crc and page not in parts
        if identity is None: identity = (total, crc, pages)
        assert identity == (total, crc, pages)
        parts[page] = payload
        records.append({'path': str(path), 'sha256': record['sha256'], 'page': page, 'fragment_crc32': f'{fragment_crc:08X}'})
    total, crc, pages = identity
    assert set(parts) == set(range(1, pages + 1))
    log = b''.join(parts[n] for n in range(1, pages + 1))
    assert len(log) == total and zlib.crc32(log) == crc
    assert log == (run / 'probe.log').read_bytes() and sha(log) == report['log_sha256']
    assert log in (run / 'debug.log').read_bytes() and b'PROBE_DISPLAY_EXIT_OK' in (run / 'debug.log').read_bytes()
    assert log.startswith(b'AITWK-P3-KVM\r\nSAGE_NATIVE13_PREREQUISITE04_OWNED_ONLY\r\n') and log.endswith(b'SAGE_NATIVE13_PREREQUISITE04_END\r\n')
    for token in [b'INSTALLER_PRESENT=NO', b'LOG_COMPLETE=YES', b'LOG_OVERFLOW=NO', b'ProviderStarted=NO', b'RuntimeTableChanged=NO', b'INSTALLATION_AUTHORIZED_BY_PROBE=NO', b'OriginalUniquePatchPagesObserved=0000000000000000', b'ResidentHoldRequired=0000000000000000', b'RetainedOwnedPages=0000000000000000', b'OwnedCodeReturn=000000004E313304']:
        assert token + b'\r\n' in log, token
    assert log.count(b'PASS owned allocation cycle complete\r\n') == 2
    assert log.count(b'PASS owned original semantic permissions restored\r\n') == 2
    result = {'status': 'PASS_INDEPENDENT_ISO_FAT_QR_BINDING', 'efi_sha256': sha(efi), 'iso_sha256': sha(iso),
              'boot_image_sha256': sha(boot), 'ovmf_report_sha256': sha_file(report_path), 'run': str(run),
              'only_fat_file': '/EFI/BOOT/BOOTX64.EFI', 'iso_file_names': sorted(names),
              'qr_pages': pages, 'log_bytes': total, 'log_crc32': f'{crc:08X}', 'log_sha256': sha(log), 'screens': records,
              'owned_cycles_completed': 2, 'observed_original_patch_pages': 0, 'nic': 'none', 'drives': drives,
              'scope': 'Independent local reinspection of exact ISO contents and recorded OVMF screenshots/logs. OVMF ran the real CPU Arch service and fixed owned code; ASUS AMITSE/Setup, native entry interception, and physical motherboard service behavior were absent. Standard services change owned RAM/page tables/TLB state; no claim of zero system effects.'}
    (HERE / 'transport_binding_result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
    (HERE / 'independently_decoded_ovmf.log').write_bytes(log)
    print(json.dumps({key: result[key] for key in ['status', 'efi_sha256', 'iso_sha256', 'qr_pages', 'log_bytes', 'log_crc32']}))


if __name__ == '__main__':
    main()

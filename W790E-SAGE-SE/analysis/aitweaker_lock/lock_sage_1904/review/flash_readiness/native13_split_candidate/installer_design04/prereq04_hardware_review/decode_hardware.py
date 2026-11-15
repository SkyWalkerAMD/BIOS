"""Independent QR-to-bytes reconstruction. Reads saved PNGs; no remote calls."""
from pathlib import Path
from collections import Counter
import hashlib
import json
import re
import sys
import zlib

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'tools/kvm-pydeps').is_dir())
sys.path.insert(0, str(ROOT / 'tools/kvm-pydeps'))
from PIL import Image
import zxingcpp

SAGE = ROOT / 'analysis/aitweaker_lock/lock_sage_1904'
HW = SAGE / 'remote_172_20_2_162'
CAPTURE = HW / 'hardware-native13-prerequisite04-1793704790283'
P04 = HERE.parent / 'prerequisite_probe04'
PRIOR = HERE.parent / 'prereq04_independent_review'
PINNED_LOG = '2af56b709f22663d502de32f4e7b22a4e49f256ad6f57deea1168b1af4958c91'
PINNED_CANDIDATE = '1c70adb50d8e17c2672b091c4bc0ab8fa201a5035b3bfda1a67e017fb3033ba9'
PINNED_PRIOR = '771dc8792b501a9431e866b7da0e313ab34f3379dceeb42c474ba11522585f39'


def sha_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha(p):
    return sha_bytes(p.read_bytes())


def read(p):
    return json.loads(p.read_text(encoding='utf8'))


def bind(p):
    return {'path': str(p.resolve()), 'bytes': p.stat().st_size, 'sha256': sha(p)}


def parse(raw):
    header, body = raw.split(b'\n\n', 1)
    match = re.fullmatch(rb'AITWK-P3-KVM\nT=([0-9]{1,5});C=([0-9A-F]{8});P=([0-9]{1,2})/([0-9]{1,2});O=([0-9]{1,5});N=([0-9]{1,3});D=([0-9A-F]{8})', header)
    if not match:
        raise ValueError('Header shape')
    total, crc, page, pages, offset, count, chunk_crc = match.groups()
    total, page, pages, offset, count = map(int, [total, page, pages, offset, count])
    if not (0 < total < 24576 and pages == (total + 767) // 768 and 1 <= page <= pages
            and offset == (page - 1) * 768 and count == min(768, total - offset) and len(body) == count):
        raise ValueError('Frame bounds')
    if zlib.crc32(body) != int(chunk_crc, 16):
        raise ValueError('Chunk CRC')
    return {'total': total, 'crc32': crc.decode(), 'page': page, 'pages': pages,
            'offset': offset, 'bytes': count, 'chunk_crc32': chunk_crc.decode(), 'body': body}


def assemble(raw_frames):
    parsed = [parse(x) for x in raw_frames]
    if not parsed:
        raise ValueError('No pages')
    key = parsed[0]['total'], parsed[0]['crc32'], parsed[0]['pages']
    if any((p['total'], p['crc32'], p['pages']) != key for p in parsed):
        raise ValueError('Mixed session')
    if sorted(p['page'] for p in parsed) != list(range(1, key[2] + 1)):
        raise ValueError('Missing or duplicate page')
    data = b''.join(p['body'] for p in sorted(parsed, key=lambda x: x['page']))
    if len(data) != key[0] or f'{zlib.crc32(data):08X}' != key[1]:
        raise ValueError('Whole log CRC/length')
    if not data.startswith(b'AITWK-P3-KVM\r\nSAGE_NATIVE13_PREREQUISITE04_OWNED_ONLY\r\n'):
        raise ValueError('Wrong probe')
    if not data.endswith(b'SAGE_NATIVE13_PREREQUISITE04_END\r\n'):
        raise ValueError('Missing end')
    for token in [b'LOG_COMPLETE=YES\r\n', b'LOG_OVERFLOW=NO\r\n', b'INSTALLER_PRESENT=NO\r\n',
                  b'INSTALLATION_AUTHORIZED_BY_PROBE=NO\r\n', b'RuntimeTableChanged=NO\r\n', b'ProviderStarted=NO\r\n']:
        if token not in data:
            raise ValueError('Missing scope marker')
    if b'LOG_OVERFLOW=YES' in data:
        raise ValueError('Overflow')
    return data, parsed


def main():
    cm = P04 / 'prerequisite04_manifest.json'
    pm = PRIOR / 'review_manifest.json'
    assert sha(cm) == PINNED_CANDIDATE and sha(pm) == PINNED_PRIOR
    manifest_results = []
    for base, path, expected_count in [(P04, cm, 97), (PRIOR, pm, 38)]:
        rows = read(path)['artifacts']
        assert len(rows) == expected_count
        for row in rows:
            p = (base / row['path']).resolve()
            assert p.is_relative_to(ROOT.resolve())
            assert p.stat().st_size == row['bytes'] and sha(p) == row['sha256'], p
        manifest_results.append({'manifest': bind(path), 'bindings_verified': len(rows)})
    capture_manifest = read(CAPTURE / 'manifest.json')
    assert capture_manifest['pages'] == 16 and capture_manifest['bytes'] == 12125
    assert capture_manifest['crc32'] == '54DC8D8D' and capture_manifest['sha256'] == PINNED_LOG
    assert len(capture_manifest['files']) == 33
    for name, digest in capture_manifest['files'].items():
        assert sha(CAPTURE / name) == digest
    raw_frames, page_rows = [], []
    for index in range(1, 17):
        p = CAPTURE / f'page-{index:02d}.png'
        with Image.open(p) as im:
            assert im.width * im.height <= 32_000_000
            results = zxingcpp.read_barcodes(im.convert('RGB'), formats=zxingcpp.BarcodeFormat.QRCode)
            dimensions = [im.width, im.height]
        assert len(results) == 1, (index, len(results))
        raw = bytes(results[0].bytes)
        parsed = parse(raw)
        assert parsed['page'] == index
        assert raw == (CAPTURE / f'page-{index:02d}.frame').read_bytes()
        raw_frames.append(raw)
        page_rows.append({'page': index, 'png': bind(p), 'dimensions': dimensions,
                          'decoded_frame_sha256': sha_bytes(raw),
                          **{k: v for k, v in parsed.items() if k != 'body'}})
    data, _ = assemble(raw_frames)
    assert data == (CAPTURE / 'hardware-log.txt').read_bytes()
    assert len(data) == 12125 and sha_bytes(data) == PINNED_LOG
    faults = {
        'missing_last_page': raw_frames[:-1],
        'duplicate_page': raw_frames + raw_frames[:1],
        'altered_payload': [raw_frames[0][:-1] + bytes([raw_frames[0][-1] ^ 1])] + raw_frames[1:],
        'truncated_payload': [raw_frames[0][:-1]] + raw_frames[1:],
        'mixed_total_crc': [raw_frames[0].replace(b'C=54DC8D8D;', b'C=54DC8D8C;', 1)] + raw_frames[1:],
    }
    fault_results = []
    for name, raw in faults.items():
        try:
            assemble(raw)
        except ValueError as exc:
            fault_results.append({'case': name, 'status': 'EXPECTED_REJECTION', 'reason': str(exc)})
        else:
            raise AssertionError(name)
    assert assemble(list(reversed(raw_frames)))[0] == data
    text = data.decode('ascii')
    lines = text.splitlines()
    assert not any(x.startswith('FAIL ') for x in lines)
    def number(name):
        matches = re.findall(r'^' + re.escape(name) + r'=([0-9A-F]{16})$', text, re.M)
        assert len(matches) == 1, (name, matches)
        return int(matches[0], 16)
    # splitlines removes CR explicitly; regex assertions operate on normalized text.
    text = '\n'.join(lines)
    modules = re.findall(r'^MODULE (AMITSE|Setup)\nCount=([0-9A-F]{16})\nBase=([0-9A-F]{16})\nLoadedSize=([0-9A-F]{16})\nPASS original relocation-free text SHA256$', text, re.M)
    assert len(modules) == 2
    module_info = [{'name': n, 'count': int(c, 16), 'base': f'0x{int(b, 16):X}', 'loaded_size': int(s, 16)} for n, c, b, s in modules]
    assert all(x['count'] == 1 for x in module_info)
    patch_re = re.compile(r'^PATCH (\w+) RVA=([0-9A-F]{16}) ORIGINAL_OK\nPATCH_PAGE ([0-9A-F]{16}) TYPE=([0-9A-F]{16}) MAP_ATTR=([0-9A-F]{16}) ACTUAL_ATTR=UNKNOWN\nCPU_PTE ([0-9A-F]{16}) P=1 RW=([01]) NX=([01]) US=([01]) LEVEL=([1-5]) PATIDX=([0-7]) IDENTITY=YES$', re.M)
    patches = []
    for name, rva, page, memtype, mapattr, walked, rw, nx, user, level, pat in patch_re.findall(text):
        assert page == walked
        patches.append({'name': name, 'rva': f'0x{int(rva,16):X}', 'page': f'0x{int(page,16):X}',
                        'memory_type': int(memtype,16), 'memory_map_attribute': int(mapattr,16),
                        'present': True, 'rw': int(rw), 'nx': int(nx), 'user': int(user),
                        'leaf_level': int(level), 'pat_index': int(pat), 'identity': True})
    assert len(patches) == 12 and len({p['page'] for p in patches}) == 8
    assert all(p['memory_type'] == 3 and p['rw'] == 1 and p['nx'] == p['user'] == p['pat_index'] == 0 and p['leaf_level'] == 2 for p in patches)
    assert number('OriginalUniquePatchPagesObserved') == 8
    assert number('CPU.CR0') & (1 << 16)
    assert number('CPU.CR4') & sum(1 << bit for bit in [20,21,22,23,24]) == 0
    assert number('CpuArchLocate.status') == 0 and number('CpuArchSetMemoryAttributes') == 0x614A23D0
    assert number('NativeCallerReturnRVA') == 0xA8E6 and number('LaunchOuterReturnRVA') == 0x960C
    assert number('AMITSE.stage') == 7 and number('AMITSE.app_pointer') == 0
    for token in ['PASS SMBIOS W790E-SAGE SE version1904', 'PASS exact fixed Core StartImage frame',
                  'PASS exact known native StartImage callsite', 'PASS exact outer CALL target9F78 and return RVA',
                  'INSTALLATION_AUTHORIZED_BY_CONTEXT=NO', 'NativeBrowserInactiveProof=NOT_AVAILABLE',
                  'CPU_ARCH_ATTRIBUTE_SERVICE=BOUNDED_EXECUTABLE', 'CPU_SUPERVISOR_WP=ENABLED',
                  'MemoryAttributeProtocol=UNAVAILABLE_ACTUAL_PERMISSIONS_UNKNOWN',
                  'PASS original target permission snapshots unchanged',
                  'PASS AMITSE original text unchanged after owned fixture',
                  'PASS Setup original text unchanged after owned fixture',
                  'FOREIGN_PAGE_ATTRIBUTES_REQUESTED=NO', 'ORIGINAL_MODULE_BYTES_WRITTEN=NO',
                  'NO_CR0_CR3_CR4_PAT_OR_PTE_WRITE_BY_PROBE', 'NO_NATIVE_UI_OR_HOOK_INSTALL']:
        assert lines.count(token) == 1, token
    cycles = re.findall(r'^OWNED_ALLOCATION_BEGIN\n(.*?)\nOWNED_ALLOCATION_END$', text, re.M | re.S)
    assert len(cycles) == 2
    cycle_info = []
    for index, block in enumerate(cycles):
        values = lambda k: [int(x,16) for x in re.findall(r'^'+re.escape(k)+r'=([0-9A-F]{16})$',block,re.M)]
        kind = values('OwnedMemoryType')
        assert kind == [3 + index]
        assert values('OwnedAllocate.status') == values('OwnedFree.status') == [0]
        assert values('OwnedSetAttributes.request') == [0x24000,0x20000,0x4000,0]
        assert values('OwnedSetAttributes.status') == [0,0,0,0]
        assert values('OwnedInitialRW') == [1] and values('OwnedInitialNX') == values('OwnedInitialPATIndex') == [0]
        for token in ['PASS owned allocation exclusive map and bounds',
                      'PASS owned RO NX transition and neighbor invariants',
                      'PASS owned RO executable transition and neighbor invariants',
                      'PASS owned RW NX transition and neighbor invariants',
                      'PASS owned writable byte readback', 'PASS owned original semantic permissions restored',
                      'PASS owned allocation cycle complete']:
            assert block.splitlines().count(token) == 1
        returns = values('OwnedCodeReturn')
        if index == 0:
            assert returns == [0x4E313304] and 'PASS fixed six byte owned code execution' in block
        else:
            assert returns == [] and 'DATA_PAGE_NOT_EXECUTED' in block
        base = values('OwnedAllocate.address')[0]
        cycle_info.append({'memory_type': 3 + index, 'allocation_base': f'0x{base:X}',
                           'owned_pages': 3, 'only_attribute_target_page': f'0x{base+4096:X}',
                           'attribute_requests': ['0x24000','0x20000','0x4000','0x0'],
                           'all_statuses_success': True, 'neighbors_semantics_unchanged': True,
                           'original_target_semantics_unchanged_each_transition': True,
                           'fixed_code_return': f'0x{returns[0]:X}' if returns else None,
                           'data_page_executed': False, 'write_readback_pass': True,
                           'semantic_permissions_restored': True, 'free_pages_status': 0})
    for name in ['RetainedOwnedPages','EBSObserved','ResidentHoldRequired','PrerequisiteEventClose.status','Warnings']:
        assert number(name) == 0
    result = {'status': 'PASS_INDEPENDENT_HARDWARE_QR_AND_SEMANTIC_RECONSTRUCTION',
              'candidate_manifests': manifest_results, 'raw_capture_manifest': bind(CAPTURE / 'manifest.json'),
              'raw_capture_file_bindings': 33, 'pages': 16, 'bytes': len(data), 'crc32': f'{zlib.crc32(data):08X}',
              'sha256': sha_bytes(data), 'page_details': page_rows,
              'strict_decoder_negative_cases': fault_results, 'unordered_complete_pages_accepted': True,
              'modules': module_info, 'original_patch_sites': patches, 'unique_patch_pages': 8,
              'cpu': {k: f'0x{number("CPU."+k):X}' for k in ['CR0','CR3','CR4','EFER','PAT','PhysicalAddressBits']},
              'cr0_wp_enabled': True, 'memory_attribute_protocol_available': False,
              'cpu_arch_set_attributes_address': '0x614A23D0', 'owned_cycles': cycle_info,
              'context': {'AMITSE_stage': 7, 'app_pointer': 0, 'native_return_rva': '0xA8E6',
                          'outer_return_rva': '0x960C', 'outer_frame_recognized': True,
                          'browser_inactivity_proven': False, 'context_authorizes_installation': False},
              'complete_status': {name: number(name) for name in ['RetainedOwnedPages','EBSObserved','ResidentHoldRequired','PrerequisiteEventClose.status','Warnings']},
              'scope': 'Independently decoded all original PNGs, byte-compared saved frames/log, and parsed recorded semantics against frozen source. Does not independently observe CPU fault enforcement, other cores/TLBs or runtime attestation of the loaded probe binary.',
              'native_password_hardware_pass': False, 'native_installation_authorized': False,
              'flash_ready': False, 'reviewer_remote_operations': 0}
    with (HERE / 'independently_decoded.log').open('xb') as f:
        f.write(data)
    with (HERE / 'decode_result.json').open('x', encoding='utf8', newline='\n') as f:
        f.write(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({k: result[k] for k in ['status','pages','bytes','crc32','sha256','unique_patch_pages']}))


if __name__ == '__main__':
    main()

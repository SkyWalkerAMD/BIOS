"""Read-only authentication review of two pinned HERO 3107 capsule files.

Uses only public-key operations. No CAP is written or changed, including for
negative controls: those use deliberately different digests of existing bytes.
The signed-region hypothesis comes from the earlier SAGE investigation, but is
parsed and cryptographically checked here against HERO's own map and keys.
This does not emulate EZ Flash, FlashBack, a BMC, or the board's trust store.
"""
from __future__ import annotations

import hashlib
import json
import struct
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ORIGINAL = ROOT / 'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP'
CANDIDATE = ROOT / 'analysis/hero_ipmi_p5_rea_review_20261103/rc2/HERO-3107-IPMI-P5-RC2-UNSIGNED.CAP'
PIN_ORIGINAL = 'e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a'
PIN_CANDIDATE = '5906d1bca3dbaa1157ecf36ecff1a1123bfe4b6fb896aeb33d354ab4ef21b521'
CAPSULE_GUID = '4a3ca68b-7723-48fb-803d-578cc1fec44d'
RSA_CERT_GUID = 'a7717414-c616-4977-9420-844712a735bf'
SHA256_GUID = '51aa59de-fdf2-4ea3-bc63-875fb7842ee9'
PUBLIC_KEY_FFS_GUID = '3feec852-f14c-4e7f-97fd-4c3a8c5bbecc'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def guid(data: bytes) -> str:
    return str(uuid.UUID(bytes_le=data))


def find_all(data: bytes, needle: bytes) -> list[int]:
    result, offset = [], -1
    while (offset := data.find(needle, offset + 1)) >= 0:
        result.append(offset)
    return result


def parse_capsule(data: bytes) -> dict:
    require(len(data) >= 4096, 'CAP is too small')
    header_size, flags, cap_size, rom_offset, layout_offset = struct.unpack_from('<IIIHH', data, 16)
    cert_size, revision, cert_type = struct.unpack_from('<IHH', data, 32)
    require(guid(data[:16]) == CAPSULE_GUID, 'Unexpected capsule GUID')
    require(header_size == rom_offset == 4096 and cap_size == len(data), 'Invalid sizes')
    require(flags == 0x10001, 'Unexpected flags')
    require((cert_size, revision, cert_type) == (0x438, 0x200, 0xEF1), 'Unexpected WIN_CERT header')
    require(guid(data[40:56]) == RSA_CERT_GUID, 'Unexpected certificate GUID')
    require(0x20 + cert_size == layout_offset == 0x458, 'Certificate boundary mismatch')
    regions, offset = [], layout_offset
    body_size = len(data) - rom_offset
    physical_base = 0x100000000 - body_size
    while True:
        require(offset + 24 <= header_size, 'Map exceeds CAP header')
        entry = data[offset:offset + 24]
        offset += 24
        if entry == bytes(24):
            break
        physical, body_offset, size, kind, attrs = struct.unpack('<QIIII', entry)
        require(size > 0 and body_offset + size <= body_size, 'Invalid map bounds')
        require(physical == physical_base + body_offset, 'Physical mapping mismatch')
        regions.append(dict(index=len(regions), table_cap_offset=offset - 24,
                            physical_address=physical, body_offset=body_offset,
                            cap_offset=rom_offset + body_offset, size=size,
                            kind=kind, attributes=attrs,
                            signature_included=bool(attrs & 0x200)))
    require(regions, 'Empty ROM map')
    gaps, cursor = [], 0
    for region in sorted(regions, key=lambda item: item['body_offset']):
        start = region['body_offset']
        require(start >= cursor, 'Overlapping ROM regions')
        if start > cursor:
            gaps.append(dict(body_offset=cursor, cap_offset=rom_offset + cursor, size=start - cursor))
        cursor = start + region['size']
    if cursor < body_size:
        gaps.append(dict(body_offset=cursor, cap_offset=rom_offset + cursor, size=body_size - cursor))
    return dict(guid=guid(data[:16]), header_size=header_size, flags=flags,
                image_size=cap_size, body_offset=rom_offset, body_size=body_size,
                physical_base=physical_base, certificate_length=cert_size,
                certificate_revision=revision, certificate_type=cert_type,
                certificate_guid=guid(data[40:56]), rsa_block_offsets=[0x38, 0x248],
                rom_layout_offset=layout_offset, rom_layout_end=offset,
                region_count=len(regions), disjoint_regions=True,
                map_covers_entire_body=not gaps, unmapped_ranges=gaps,
                regions=regions)


def mgf1(seed: bytes, length: int) -> bytes:
    return b''.join(hashlib.sha256(seed + n.to_bytes(4, 'big')).digest()
                    for n in range((length + 31) // 32))[:length]


def rsa_pss_verify(block: bytes, digest: bytes) -> dict:
    require(len(block) == 528 and len(digest) == 32, 'RSA/SHA256 input lengths')
    require(guid(block[:16]) == SHA256_GUID, 'Hash GUID mismatch')
    modulus, signature = block[16:272], block[272:528]
    n, s = int.from_bytes(modulus, 'big'), int.from_bytes(signature, 'big')
    require(n.bit_length() == 2048 and n & 1, 'Expected RSA2048 odd modulus')
    require(0 <= s < n, 'Signature representative outside modulus')
    em = pow(s, 65537, n).to_bytes(256, 'big')
    masked_db, encoded_h = em[:223], em[223:255]
    db = bytearray(a ^ b for a, b in zip(masked_db, mgf1(encoded_h, 223)))
    db[0] &= 0x7F
    # Derive the salt length from the encoded PSS block; do not assume SAGE's.
    delimiter = next((i for i, value in enumerate(db) if value != 0), len(db))
    salt = bytes(db[delimiter + 1:]) if delimiter < len(db) else b''
    calculated_h = hashlib.sha256(bytes(8) + digest + salt).digest()
    checks = dict(trailer_0xbc=em[-1] == 0xBC,
                  unused_top_bit_zero=masked_db[0] & 0x80 == 0,
                  padding_delimiter_0x01=delimiter < len(db) and db[delimiter] == 1,
                  digest_matches=encoded_h == calculated_h)
    return dict(valid=all(checks.values()), scheme='RSASSA-PSS', rsa_modulus_bits=2048,
                public_exponent=65537, hash='SHA-256', mgf='MGF1-SHA-256',
                em_bits=2047, salt_bytes=len(salt), salt=salt.hex(),
                padding_zero_bytes=delimiter, checks=checks, message_digest=digest.hex(),
                modulus_sha256=sha(modulus), signature_sha256=sha(signature),
                encoded_h=encoded_h.hex(), computed_h=calculated_h.hex(),
                encoded_message_sha256=sha(em))


def signed_stream_parts(data: bytes, header: dict) -> list[dict]:
    result = [dict(kind='rom_region', region_index=r['index'], cap_offset=r['cap_offset'],
                   length=r['size']) for r in header['regions'] if r['signature_included']]
    result.append(dict(kind='rom_layout_including_zero_terminator',
                       cap_offset=header['rom_layout_offset'],
                       length=header['rom_layout_end'] - header['rom_layout_offset']))
    return result


def digest_parts(data: bytes, parts: list[dict]) -> bytes:
    h = hashlib.sha256()
    for part in parts:
        h.update(data[part['cap_offset']:part['cap_offset'] + part['length']])
    return h.digest()


def signatures(data: bytes, header: dict) -> dict:
    return dict(firmware=rsa_pss_verify(data[0x38:0x248], digest_parts(data, signed_stream_parts(data, header))),
                certificate=rsa_pss_verify(data[0x248:0x458], hashlib.sha256(data[0x20:0x248]).digest()))


def main() -> None:
    original, candidate = ORIGINAL.read_bytes(), CANDIDATE.read_bytes()
    require(sha(original) == PIN_ORIGINAL and sha(candidate) == PIN_CANDIDATE, 'Input hash binding failed')
    require(len(original) == len(candidate), 'CAP size differs')
    oh, ch = parse_capsule(original), parse_capsule(candidate)
    require(oh == ch and original[:4096] == candidate[:4096], 'CAP header differs')
    osig, csig = signatures(original, oh), signatures(candidate, ch)
    require(osig['firmware']['valid'] and osig['certificate']['valid'], 'Original authentication failed')
    require(not csig['firmware']['valid'] and csig['certificate']['valid'], 'Unexpected RC2 authentication')
    require(all(s['salt_bytes'] == 8 for s in osig.values()), 'Observed salt length differs')

    regions = []
    for r in oh['regions']:
        start, end = r['cap_offset'], r['cap_offset'] + r['size']
        a, b = original[start:end], candidate[start:end]
        count = sum(x != y for x, y in zip(a, b))
        regions.append(r | dict(original_sha256=sha(a), candidate_sha256=sha(b), changed_bytes=count))
    total_changed = sum(x != y for x, y in zip(original, candidate))
    require(sum(r['changed_bytes'] for r in regions) == total_changed, 'Change outside parsed regions')
    changed_regions = [r for r in regions if r['changed_bytes']]
    require(changed_regions and all(r['signature_included'] for r in changed_regions), 'Unanticipated changed area')

    root_key = original[0x258:0x358]
    key_ffs_candidates = []
    for offset in find_all(original, uuid.UUID(PUBLIC_KEY_FFS_GUID).bytes_le):
        ffs_size = int.from_bytes(original[offset + 20:offset + 23], 'little')
        section_size = int.from_bytes(original[offset + 24:offset + 27], 'little')
        root_matches = original[offset + 28:offset + 284] == root_key
        key_ffs_candidates.append(dict(cap_offset=offset, ffs_size=ffs_size,
                                       ffs_type=original[offset + 18], section_size=section_size,
                                       section_type=original[offset + 27],
                                       raw_payload_matches_certificate_public_key=root_matches,
                                       same_bytes_in_candidate=original[offset:offset + ffs_size] == candidate[offset:offset + ffs_size]))
    require(len(key_ffs_candidates) == 1, 'Ambiguous key FFS')
    k = key_ffs_candidates[0]
    require(k['ffs_size'] == 284 and k['section_size'] == 260 and k['section_type'] == 0x19
            and k['raw_payload_matches_certificate_public_key'] and k['same_bytes_in_candidate'], 'Root FFS mismatch')

    parts = signed_stream_parts(original, oh)
    alternate_digests = {
        'zero_digest': bytes(32),
        'whole_rom_body': hashlib.sha256(original[oh['body_offset']:]).digest(),
        'without_rom_layout': digest_parts(original, parts[:-1]),
        'without_layout_zero_terminator': digest_parts(original, parts[:-1] + [parts[-1] | {'length': parts[-1]['length'] - 24}]),
        'signed_regions_in_address_order': digest_parts(original, sorted(parts[:-1], key=lambda p: p['cap_offset']) + parts[-1:]),
    }
    controls = [dict(name=name, digest=digest.hex(), valid=rsa_pss_verify(original[0x38:0x248], digest)['valid'])
                for name, digest in alternate_digests.items()]
    require(not any(c['valid'] for c in controls), 'Unexpected negative control acceptance')

    report = dict(
        status='ORIGINAL_BOTH_SIGNATURES_VALID_RC2_FIRMWARE_SIGNATURE_INVALID',
        scope='Read-only local byte parsing and mathematical public-key verification. Not hardware or flash-path execution.',
        script_sha256=sha(Path(__file__).read_bytes()),
        files=dict(original=dict(path=str(ORIGINAL), sha256=sha(original), bytes=len(original)),
                   rc2=dict(path=str(CANDIDATE), sha256=sha(candidate), bytes=len(candidate))),
        cap_header_byte_identical=True, structure=oh,
        format_interpretation='AMI custom capsule uses a WIN_CERTIFICATE_UEFI_GUID envelope with two RSA blocks. These exact signatures are PSS, not PKCS#1 v1.5, and the envelope is not a DER X.509/PKCS#7 certificate.',
        signed_stream_rule='SHA256 of ROM regions where attributes & 0x200, in original table order, then ROM layout bytes including the 24-byte zero terminator.',
        signed_stream_parts=parts, signed_stream_length=sum(p['length'] for p in parts),
        certificate_signed_range=dict(cap_offset=0x20, length=0x228, end_exclusive=0x248),
        signature_blocks=dict(firmware=dict(cap_offset=0x38, modulus_offset=0x48, signature_offset=0x148),
                              certificate=dict(cap_offset=0x248, modulus_offset=0x258, signature_offset=0x358)),
        signatures=dict(original=osig, rc2=csig),
        region_comparison=regions, changed_region_indices=[r['index'] for r in changed_regions],
        total_changed_bytes=total_changed, root_key_ffs=key_ffs_candidates,
        root_public_modulus_sha256=sha(root_key),
        negative_digest_controls=controls,
        input_files_unchanged=sha(ORIGINAL.read_bytes()) == PIN_ORIGINAL and sha(CANDIDATE.read_bytes()) == PIN_CANDIDATE,
        rea_evidence_ids=[],
        limitations=[
            'No REA call is made by this script; these are raw-file and mathematical results, not invented REA Evidence records.',
            'Signed-region rule is verified for these two pinned HERO artifacts; it is not a universal AMI format claim.',
            'Matching the root modulus to an embedded FFS is self-consistency evidence; which installed hardware trust store consumes it requires separate code/runtime evidence.',
            'This result alone does not establish EZ Flash or USB BIOS FlashBack acceptance or rejection, nor successful execution after flashing.',
            'No private key, signing, patching, signature bypass, BMC access, or flashing was used.',
        ])
    output = HERE / 'hero_capsule_authentication.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(status=report['status'], output=str(output), sha256=sha(output.read_bytes()),
                          original={k: v['valid'] for k, v in osig.items()}, rc2={k: v['valid'] for k, v in csig.items()},
                          map_regions=oh['region_count'], map_gaps=oh['unmapped_ranges'], changed_bytes=total_changed,
                          changed_region_indices=report['changed_region_indices']), indent=2))


if __name__ == '__main__':
    main()

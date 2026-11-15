"""Public-only Python mathematical and OpenSSL CLI verification of three inputs.

Negative controls exist only as small public signature blocks/digests or in-RAM
capsule copies. No private key is required, generated, loaded or exported here.
"""
import subprocess
import sys

sys.dont_write_bytecode = True
from capsule_common import *


def independent_digests(data):
    assert len(data) == 0x4001000 and struct.unpack_from('<IIIHH', data, 16) == (0x1000, 0x10001, len(data), 0x1000, 0x458)
    digest = hashlib.sha256(); start = 0x458; at = start; included = []
    while data[at:at+24] != bytes(24):
        assert at+24 <= 4096
        physical, raw, count, kind, attrs = struct.unpack_from('<QIIII', data, at)
        assert physical == 0xfc000000+raw and count > 0 and raw+count <= 0x4000000
        if attrs & 0x200:
            digest.update(data[0x1000+raw:0x1000+raw+count]); included.append({'table_offset': hex(at), 'body_offset': hex(raw), 'bytes': count})
        at += 24
    assert at+24 == 0x680
    digest.update(data[start:at+24])
    return {'firmware': digest.digest(), 'certificate': hashlib.sha256(data[0x20:0x248]).digest()}, included


def main():
    scope = parser(); original, source, header = inputs(scope)
    creation = json.loads((HERE/'creation_manifest.json').read_text(encoding='utf8'))
    candidate = ARTIFACT.read_bytes()
    assert record(ARTIFACT) == creation['artifact']
    assert record(SOURCE) == creation['source']
    assert record(HERE/'sign_engineering.py') == creation['script'] and record(HERE/'capsule_common.py') == creation['common']
    retained = preservation(scope, source, candidate)
    assert retained == creation['preservation']
    assert not creation['ASUS_signature'] and not creation['FLASH_READY']
    assert creation['key_handling']['native_EVP_objects_only'] and not creation['key_handling']['private_key_serialization_or_file_created']
    evidence = HERE/'public_evidence'; evidence.mkdir(exist_ok=True)
    checks = []; digest_sets = {}; public_only_files = []

    def crosscheck(name, block, digest, expected, reason):
        result = scope['rsa_pss_sha256'](block, digest)
        assert result['valid'] == expected, name
        public_path = evidence/(name+'.public.pem'); signature_path = evidence/(name+'.signature.bin'); digest_path = evidence/(name+'.sha256.bin')
        public_path.write_bytes(public_pem(block[16:272])); signature_path.write_bytes(block[272:528]); digest_path.write_bytes(digest)
        public_only_files.extend([public_path, signature_path, digest_path])
        args = [str(OPENSSL), 'pkeyutl', '-verify', '-pubin', '-inkey', str(public_path), '-sigfile', str(signature_path), '-in', str(digest_path),
                '-pkeyopt', 'digest:sha256', '-pkeyopt', 'rsa_padding_mode:pss', '-pkeyopt', 'rsa_pss_saltlen:8', '-pkeyopt', 'rsa_mgf1_md:sha256']
        run = subprocess.run(args, capture_output=True, text=True, encoding='utf8', timeout=30)
        assert (run.returncode == 0) == expected, name
        checks.append({'name': name, 'expected_valid': expected, 'reason': reason, 'python': result,
                       'openssl': {'returncode': run.returncode, 'stdout': run.stdout.strip(), 'stderr': run.stderr.strip(), 'args': args},
                       'public_key': record(public_path), 'signature': record(signature_path), 'digest': record(digest_path)})

    for sample, data in [('ASUS_original', original), ('candidate05_stale_signature', source), ('engineering_nonOEM', candidate)]:
        digests, included = independent_digests(data)
        assert digests['firmware'] == scope['firmware_digest'](data, header)
        assert digests['certificate'] == bytes.fromhex(scope['signatures'](data, header)['certificate_signature']['message_digest'])
        digest_sets[sample] = {'digests': {k: v.hex() for k, v in digests.items()}, 'included_ranges_in_table_order': included,
                               'map_start': '0x458', 'map_end_including_zero_terminator': '0x680'}
        for kind, off in BLOCKS.items():
            expected = not (sample == 'candidate05_stale_signature' and kind == 'firmware')
            crosscheck(sample+'_'+kind, data[off:off+528], digests[kind], expected, 'Independent raw-map digest and each sample embedded public key')

    digests, included = independent_digests(candidate)
    # Exact same bytes must not acquire OEM authenticity under the original moduli.
    for kind, off in BLOCKS.items():
        engineering_block = candidate[off:off+528]
        crosscheck('negative_engineering_signature_under_ASUS_'+kind,
                   engineering_block[:16]+original[off+16:off+272]+engineering_block[272:], digests[kind], False,
                   'Engineering signature is not valid under the retained ASUS public modulus')
        flipped = bytearray(engineering_block); flipped[-1] ^= 1
        crosscheck('negative_tampered_'+kind+'_signature', bytes(flipped), digests[kind], False, 'One signature bit changed')
        wrong_digest = bytes([digests[kind][0]^1])+digests[kind][1:]
        crosscheck('negative_wrong_'+kind+'_digest', engineering_block, wrong_digest, False, 'One digest bit changed')
        other = 'certificate' if kind == 'firmware' else 'firmware'; other_off = BLOCKS[other]
        crosscheck('negative_cross_role_'+kind+'_key', engineering_block[:16]+candidate[other_off+16:other_off+272]+engineering_block[272:], digests[kind], False,
                   'Fresh firmware and certificate signing keys are distinct')

    tampered = bytearray(candidate)
    # Alter one byte in the signed DXE region. This is a RAM-only negative image.
    changed_at = 0x3181088; assert any(0x1000+int(r['body_offset'], 16) <= changed_at < 0x1000+int(r['body_offset'], 16)+r['bytes'] for r in included)
    tampered[changed_at] ^= 1; bad, _ = independent_digests(tampered)
    assert bad['firmware'] != digests['firmware'] and bad['certificate'] == digests['certificate']
    crosscheck('negative_signed_payload_tamper', candidate[0x38:0x248], bad['firmware'], False, 'Payload bit flip inside original signed range')
    tampered[changed_at] ^= 1
    # Keep range selection and layout valid, alter a non-mask attribute bit.
    tampered[0x458+20] ^= 0x10; bad, _ = independent_digests(tampered)
    crosscheck('negative_ROM_map_tamper', candidate[0x38:0x248], bad['firmware'], False, 'ROM map itself is hashed without changing its inclusion mask')
    tampered[0x458+20] ^= 0x10
    tampered[0x148] ^= 1
    bad, _ = independent_digests(tampered)
    crosscheck('negative_certificate_covers_firmware_signature', candidate[0x248:0x458], bad['certificate'], False,
               'Firmware signature changed after certificate signing')
    assert len(checks) == 17
    assert sha(SOURCE.read_bytes()) == SOURCE_SHA and sha(ORIGINAL.read_bytes()) == ORIGINAL_SHA
    public_keys = []
    for kind, off in BLOCKS.items():
        key = evidence/(kind+'.engineering.public.pem')
        assert key.read_bytes() == public_pem(candidate[off+16:off+272])
        public_keys.append(record(key))
    version = subprocess.run([str(OPENSSL), 'version'], capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    report = {'status': 'PASS_ENGINEERING_ONLY_DUAL_SIGNATURE_CROSSCHECK_NOT_FLASH_READY',
              'original': record(ORIGINAL), 'source_stale_signature': record(SOURCE), 'engineering_artifact': record(ARTIFACT),
              'creation_manifest': record(HERE/'creation_manifest.json'), 'script': record(Path(__file__)), 'common': record(HERE/'capsule_common.py'),
              'pure_python_verifier': record(HELPER), 'openssl': record(OPENSSL), 'libcrypto': record(LIBCRYPTO), 'openssl_version': version,
              'independent_raw_map_digests': digest_sets, 'preservation': retained, 'checks': checks, 'check_count': len(checks),
              'ASUS_original_valid_signatures': 2, 'stale_candidate05_valid_signatures': 1, 'engineering_valid_signatures': 2,
              'negative_controls_rejected_by_both_verifiers': 11, 'public_keys': public_keys,
              'private_key_required_or_read_by_verifier': False, 'private_key_retained': False,
              'ASUS_signature': False, 'BMC_uploaded': False, 'device_trust_anchor_changed': False, 'payload_changed': False, 'FLASH_READY': False,
              'limits': ['The engineering signatures are valid only under the new embedded public keys.',
                         'No OEM signing authority, public-key enrollment, verifier modification or policy bypass is involved.',
                         'Unchanged payload means all firmware-resident trust anchors remain exactly as in candidate05.',
                         'No live BMC acceptance, local firmware acceptance, flash write, boot success or recovery claim.']}
    save(HERE/'verification.json', report)
    print(json.dumps({'status': report['status'], 'artifact': report['engineering_artifact'], 'checks': len(checks),
                      'payload_identical': retained['payload_byte_identical'], 'ASUS_signature': False, 'FLASH_READY': False}, indent=2))


if __name__ == '__main__': main()

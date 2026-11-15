"""Independent OpenSSL verification; public material only, never signs or writes CAPs."""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from pathlib import Path

import verify_hero_capsule as cap

HERE = Path(__file__).resolve().parent
OPENSSL = Path('D:/OpenSSL-Win64/bin/openssl.exe')


def tlv(tag: int, data: bytes) -> bytes:
    size = len(data)
    if size < 128:
        length = bytes([size])
    else:
        encoded = size.to_bytes((size.bit_length() + 7) // 8, 'big')
        length = bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + length + data


def public_key(modulus: bytes) -> bytes:
    cap.require(len(modulus) == 256 and modulus[0] & 0x80, 'RSA2048 modulus')
    der = tlv(0x30, tlv(2, b'\0' + modulus) + tlv(2, b'\x01\x00\x01'))
    encoded = base64.b64encode(der)
    return b'-----BEGIN RSA PUBLIC KEY-----\n' + b'\n'.join(encoded[i:i + 64] for i in range(0, len(encoded), 64)) + b'\n-----END RSA PUBLIC KEY-----\n'


def main() -> None:
    original, candidate = cap.ORIGINAL.read_bytes(), cap.CANDIDATE.read_bytes()
    cap.require(cap.sha(original) == cap.PIN_ORIGINAL and cap.sha(candidate) == cap.PIN_CANDIDATE, 'Input binding')
    work = HERE / 'openssl_public_evidence'
    work.mkdir(exist_ok=True)
    cases = []
    for label, data in [('official3107', original), ('rc2', candidate)]:
        header = cap.parse_capsule(data)
        for kind, start, digest in [
            ('firmware', 0x38, cap.digest_parts(data, cap.signed_stream_parts(data, header))),
            ('certificate', 0x248, hashlib.sha256(data[0x20:0x248]).digest()),
        ]:
            name = label + '_' + kind
            keyfile, sigfile, hashfile = (work / (name + ext) for ext in ['.public.pem', '.signature.bin', '.sha256.bin'])
            keyfile.write_bytes(public_key(data[start + 16:start + 272]))
            sigfile.write_bytes(data[start + 272:start + 528])
            hashfile.write_bytes(digest)
            for mode in (['pss8', 'pss32', 'pkcs1'] if label == 'official3107' else ['pss8']):
                argv = [str(OPENSSL), 'pkeyutl', '-verify', '-pubin', '-inkey', str(keyfile),
                        '-sigfile', str(sigfile), '-in', str(hashfile), '-pkeyopt', 'digest:sha256']
                if mode.startswith('pss'):
                    argv += ['-pkeyopt', 'rsa_padding_mode:pss', '-pkeyopt', 'rsa_mgf1_md:sha256',
                             '-pkeyopt', 'rsa_pss_saltlen:' + mode[3:]]
                else:
                    argv += ['-pkeyopt', 'rsa_padding_mode:pkcs1']
                p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
                expected = mode == 'pss8' and (label == 'official3107' or kind == 'certificate')
                cap.require((p.returncode == 0) == expected, 'Unexpected OpenSSL result: ' + name + '_' + mode)
                cases.append(dict(name=name, mode=mode, argv=argv, signature_valid=p.returncode == 0,
                                  expected_valid=expected, digest=digest.hex(), returncode=p.returncode,
                                  stdout=p.stdout.strip(), stderr=p.stderr.strip()))
    version = subprocess.run([str(OPENSSL), 'version', '-a'], capture_output=True, text=True, check=True, timeout=30)
    report = dict(status='OPENSSL_AGREES_ORIGINAL_VALID_RC2_FIRMWARE_INVALID',
                  original_sha256=cap.sha(original), rc2_sha256=cap.sha(candidate),
                  script_sha256=cap.sha(Path(__file__).read_bytes()),
                  helper_script_sha256=cap.sha(Path(cap.__file__).read_bytes()),
                  openssl_executable=str(OPENSSL), openssl_executable_sha256=cap.sha(OPENSSL.read_bytes()),
                  openssl_version=version.stdout.strip(), checks=cases,
                  input_files_unchanged=cap.sha(cap.ORIGINAL.read_bytes()) == cap.PIN_ORIGINAL and cap.sha(cap.CANDIDATE.read_bytes()) == cap.PIN_CANDIDATE,
                  only_public_material_used=True, no_private_keys_or_signing=True,
                  no_image_mutation_or_device_access=True,
                  derived_files=[dict(name=p.name, bytes=p.stat().st_size, sha256=cap.sha(p.read_bytes())) for p in sorted(work.iterdir()) if p.is_file()],
                  limitations=['OpenSSL verifies public-key mathematics only; no flash update path or installed hardware trust store is executed.',
                               'Region parsing/digest assembly uses the separately recorded HERO verifier, while RSA/PSS validation is OpenSSL independent of the pure-Python verifier.'])
    output = HERE / 'hero_openssl_authentication.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(status=report['status'], output=str(output), sha256=cap.sha(output.read_bytes()),
                          results=[dict(name=c['name'], mode=c['mode'], valid=c['signature_valid']) for c in cases]), indent=2))


if __name__ == '__main__':
    main()

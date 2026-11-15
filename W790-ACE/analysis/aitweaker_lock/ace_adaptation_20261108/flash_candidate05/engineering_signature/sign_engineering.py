"""Generate one engineering-only capsule using ephemeral native EVP keys.

The private keys never leave OpenSSL objects: no private-parameter extraction,
private-key serialization, subprocess pipe, environment variable or key file.
Only public moduli and final signatures are copied into Python/serialized.
No firmware/BMC trust anchor, verifier, signature flag, map or payload is edited.
"""
import argparse
import ctypes as C
import hashlib
import os
import sys

sys.dont_write_bytecode = True
from capsule_common import *


class EphemeralEVP:
    def __init__(self):
        self.dll_directory = os.add_dll_directory(str(LIBCRYPTO.parent))
        self.lib = C.CDLL(str(LIBCRYPTO)); self.keys = []
        p, i, z, s = C.c_void_p, C.c_int, C.c_size_t, C.c_char_p
        signatures = {
            'EVP_PKEY_CTX_new_from_name': ([p, s, s], p), 'EVP_PKEY_CTX_new_from_pkey': ([p, p, s], p),
            'EVP_PKEY_keygen_init': ([p], i), 'EVP_PKEY_CTX_set_rsa_keygen_bits': ([p, i], i),
            'EVP_PKEY_generate': ([p, C.POINTER(p)], i), 'EVP_PKEY_CTX_free': ([p], None), 'EVP_PKEY_free': ([p], None),
            'EVP_PKEY_get_bn_param': ([p, s, C.POINTER(p)], i), 'BN_num_bits': ([p], i), 'BN_bn2binpad': ([p, p, i], i), 'BN_free': ([p], None),
            'EVP_PKEY_sign_init': ([p], i), 'EVP_PKEY_CTX_set_rsa_padding': ([p, i], i), 'EVP_PKEY_CTX_set_signature_md': ([p, p], i),
            'EVP_PKEY_CTX_set_rsa_pss_saltlen': ([p, i], i), 'EVP_PKEY_CTX_set_rsa_mgf1_md': ([p, p], i), 'EVP_sha256': ([], p),
            'EVP_PKEY_sign': ([p, p, C.POINTER(z), p, z], i), 'EVP_PKEY_private_check': ([p], i),
        }
        for name, (args, result) in signatures.items():
            f = getattr(self.lib, name); f.argtypes = args; f.restype = result
        self.bound_functions = sorted(signatures)

    @staticmethod
    def ok(result, operation):
        if result <= 0: raise RuntimeError('OpenSSL operation failed: '+operation)

    def generate(self):
        ctx = self.lib.EVP_PKEY_CTX_new_from_name(None, b'RSA', None)
        if not ctx: raise RuntimeError('RSA context unavailable')
        key = C.c_void_p()
        try:
            self.ok(self.lib.EVP_PKEY_keygen_init(ctx), 'keygen_init')
            self.ok(self.lib.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048), 'set_bits')
            self.ok(self.lib.EVP_PKEY_generate(ctx, C.byref(key)), 'keygen')
            assert key.value
            self.keys.append(key)
        finally: self.lib.EVP_PKEY_CTX_free(ctx)
        check = self.lib.EVP_PKEY_CTX_new_from_pkey(None, key, None)
        if not check: raise RuntimeError('Key-check context unavailable')
        try: self.ok(self.lib.EVP_PKEY_private_check(check), 'private_key_check')
        finally: self.lib.EVP_PKEY_CTX_free(check)
        modulus = self.public_parameter(key, b'n', 256)
        exponent = self.public_parameter(key, b'e', 3)
        assert exponent == b'\x01\0\x01' and int.from_bytes(modulus, 'big').bit_length() == 2048
        return key, modulus

    def public_parameter(self, key, name, size):
        assert name in (b'n', b'e'), 'Only public parameters may be exported'
        number = C.c_void_p()
        try:
            self.ok(self.lib.EVP_PKEY_get_bn_param(key, name, C.byref(number)), 'public_param')
            assert number.value and 0 < self.lib.BN_num_bits(number) <= size*8
            out = C.create_string_buffer(size)
            assert self.lib.BN_bn2binpad(number, out, size) == size
            return out.raw
        finally:
            if number.value: self.lib.BN_free(number)

    def sign_digest(self, key, digest):
        assert len(digest) == 32
        ctx = self.lib.EVP_PKEY_CTX_new_from_pkey(None, key, None)
        if not ctx: raise RuntimeError('Signing context unavailable')
        try:
            self.ok(self.lib.EVP_PKEY_sign_init(ctx), 'sign_init')
            self.ok(self.lib.EVP_PKEY_CTX_set_rsa_padding(ctx, 6), 'PSS_padding')
            self.ok(self.lib.EVP_PKEY_CTX_set_signature_md(ctx, self.lib.EVP_sha256()), 'SHA256')
            self.ok(self.lib.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, self.lib.EVP_sha256()), 'MGF1_SHA256')
            self.ok(self.lib.EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 8), 'salt8')
            output = C.create_string_buffer(256); size = C.c_size_t(256)
            self.ok(self.lib.EVP_PKEY_sign(ctx, output, C.byref(size), digest, len(digest)), 'sign')
            assert size.value == 256
            return output.raw
        finally: self.lib.EVP_PKEY_CTX_free(ctx)

    def close(self):
        for key in self.keys: self.lib.EVP_PKEY_free(key)
        self.keys.clear(); self.dll_directory.close()


def main():
    args = argparse.ArgumentParser(description=__doc__)
    modes = args.add_mutually_exclusive_group(required=True)
    modes.add_argument('--preflight', action='store_true'); modes.add_argument('--create', action='store_true')
    mode = args.parse_args()
    scope = parser(); original, source, header = inputs(scope)
    crypto = EphemeralEVP()
    preflight = {'status': 'FEASIBLE_FOR_ENGINEERING_ONLY_SIGNATURES', 'source': record(SOURCE), 'original': record(ORIGINAL),
                 'pure_verifier': record(HELPER), 'libcrypto': record(LIBCRYPTO), 'openssl_cli': record(OPENSSL),
                 'available_native_functions': crypto.bound_functions, 'scheme': 'RSA2048/PSS/SHA256/MGF1-SHA256/salt8/e65537',
                 'signing_order': ['firmware: map-selected payload ranges followed by original complete ROM map', 'certificate: SHA256(CAP[0x20:0x248]) after firmware signature insertion'],
                 'private_keys_generated': False, 'hardware_access': False, 'ASUS_signature': False, 'FLASH_READY': False}
    if mode.preflight:
        crypto.close(); save(HERE/'feasibility.json', preflight)
        print(preflight['status']); return
    if ARTIFACT.exists() or (HERE/'creation_manifest.json').exists():
        crypto.close(); raise FileExistsError('Engineering artifact already exists; this command will not replace it or regenerate keys.')
    candidate = bytearray(source)
    try:
        fw_key, fw_modulus = crypto.generate(); cert_key, cert_modulus = crypto.generate()
        assert fw_modulus != cert_modulus
        assert fw_modulus != source[0x48:0x148] and cert_modulus != source[0x258:0x358]
        candidate[0x48:0x148] = fw_modulus; candidate[0x258:0x358] = cert_modulus
        fw_digest = scope['firmware_digest'](candidate, header)
        candidate[0x148:0x248] = crypto.sign_digest(fw_key, fw_digest)
        cert_digest = hashlib.sha256(candidate[0x20:0x248]).digest()
        candidate[0x358:0x458] = crypto.sign_digest(cert_key, cert_digest)
        mathematical = scope['signatures'](candidate, header)
        assert all(value['valid'] for value in mathematical.values())
        retained = preservation(scope, source, candidate)
    finally:
        crypto.close()
        # Python only held native pointers plus public n/e/signatures; no private serialization exists.
    with ARTIFACT.open('xb') as stream: stream.write(candidate)
    evidence = HERE/'public_evidence'; evidence.mkdir(exist_ok=True)
    for label, off in BLOCKS.items():
        modulus = bytes(candidate[off+16:off+272])
        (evidence/(label+'.engineering.public.pem')).write_bytes(public_pem(modulus))
        (evidence/(label+'.engineering.modulus.bin')).write_bytes(modulus)
    public = {label: {'modulus_sha256': sha(bytes(candidate[off+16:off+272])), 'modulus_bits': 2048, 'exponent': 65537,
                      'origin': 'Fresh ephemeral engineering key, not ASUS/OEM key', 'public_pem': record(evidence/(label+'.engineering.public.pem'))}
              for label, off in BLOCKS.items()}
    report = {'status': 'ENGINEERING_SIGNATURE_CREATED_AWAITING_INDEPENDENT_CROSSCHECK_NOT_FLASH_READY',
              'source': record(SOURCE), 'artifact': record(ARTIFACT), 'script': record(Path(__file__)), 'common': record(HERE/'capsule_common.py'),
              'libcrypto': record(LIBCRYPTO), 'pure_verifier': record(HELPER), 'scheme': preflight['scheme'], 'public_keys': public,
              'mathematical_signatures_at_creation': mathematical, 'preservation': retained,
              'key_handling': {'generated_key_count': 2, 'native_EVP_objects_only': True, 'private_parameters_extracted': False,
                               'private_key_serialization_or_file_created': False, 'private_key_stdout_or_stderr': False,
                               'private_key_environment_or_subprocess_arguments': False, 'EVP_objects_freed': True,
                               'private_keys_retained_for_future_signing': False,
                               'memory_caveat': 'No secure erasure of process/OS memory is asserted; EVP objects were freed and the signing process exits.'},
              'ASUS_signature': False, 'device_trust_anchor_changed': False, 'verifier_or_signature_policy_changed': False,
              'payload_changed': False, 'hardware_access': False, 'BMC_uploaded': False, 'FLASH_READY': False,
              'acceptance_scope': 'Mathematical authenticity under the new embedded engineering public keys only. No OEM authority or live BMC/BIOS trust acceptance.'}
    save(HERE/'creation_manifest.json', report)
    print(json.dumps({'status': report['status'], 'artifact': report['artifact'], 'payload_sha256': retained['payload_candidate_sha256'],
                      'private_key_files_created': False}, indent=2))


if __name__ == '__main__': main()
